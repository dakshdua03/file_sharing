import os
import secrets
from hashlib import sha256

from labkit import title, step, show, ok, warn, fail, note, short

P = 2**255 - 19


def poly_eval(coeffs, x):
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % P
    return result


def poly_from_roots(roots):
    coeffs = [1]
    for root in roots:
        new = [0] * (len(coeffs) + 1)
        for i, c in enumerate(coeffs):
            new[i] = (new[i] - root * c) % P
            new[i + 1] = (new[i + 1] + c) % P
        coeffs = new
    return coeffs


def shamir_split(secret, n, threshold):
    coeffs = [secret] + [secrets.randbelow(P) for _ in range(threshold - 1)]
    return [(x, poly_eval(coeffs, x)) for x in range(1, n + 1)]


def shamir_combine(shares):
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * xj) % P
            den = (den * (xj - xi)) % P
        secret = (secret + yi * num * pow(den, -1, P)) % P
    return secret


def h(value, r):
    return int.from_bytes(sha256(r + value).digest(), "big") % P


def main():
    title("05", "Secret sharing and Paper A's access polynomial")

    step("1. Shamir 3-of-5: split a secret into 5 shares")
    secret = secrets.randbelow(P)
    shares = shamir_split(secret, n=5, threshold=3)
    show("secret", short(secret.to_bytes(32, "big")))
    for x, y in shares:
        show(f"share {x}", short(y.to_bytes(32, "big")))
    note("Each share is one point on a random degree-2 curve.")
    note("The secret is the value of that curve at x = 0.")

    step("2. Any 3 shares rebuild the secret")
    picked = [shares[0], shares[2], shares[4]]
    show("using shares", ", ".join(str(x) for x, _ in picked))
    rebuilt = shamir_combine(picked)
    if rebuilt == secret:
        ok("reconstructed secret matches")
    else:
        fail("reconstruction failed")

    step("3. Only 2 shares are not enough")
    too_few = shamir_combine(shares[:2])
    show("value from 2 shares", short(too_few.to_bytes(32, "big")))
    if too_few != secret:
        ok("it is NOT the secret; infinitely many curves fit 2 points")
    note("That is why a degree-2 polynomial needs 3 points.")

    step("4. Paper A style access polynomial")
    users = {name: os.urandom(32) for name in ["alice", "bob", "carol", "dave"]}
    for name, key in users.items():
        show(f"{name}'s secret Ki", short(key))
    kc_int = int.from_bytes(os.urandom(32), "big") % P
    kc = kc_int.to_bytes(32, "big")
    r = os.urandom(32)
    show("file key Kc", kc.hex())
    show("random nonce r", short(r))
    note("Each user's public point is h(Ki, r) = SHA-256(r || Ki) mod p.")

    points = {name: h(key, r) for name, key in users.items()}
    for name, point in points.items():
        show(f"h({name}'s Ki, r)", short(point.to_bytes(32, "big")))

    coeffs = poly_from_roots(list(points.values()))
    coeffs[0] = (coeffs[0] + kc_int) % P
    show("published polynomial degree", len(coeffs) - 1)
    show("constant term (Kc hidden here)", short(coeffs[0].to_bytes(32, "big")))
    show("coefficient of x^1", short(coeffs[1].to_bytes(32, "big")))
    note("The coefficients are the public 'KeyInfo' metadata.")

    step("5. A valid user recovers Kc with their own Ki")
    for name in users:
        value = poly_eval(coeffs, points[name])
        if value == kc_int:
            ok(f"{name}: f(h(Ki,r)) = Kc")

    step("6. A non-member gets a meaningless number")
    outsider = os.urandom(32)
    outsider_point = h(outsider, r)
    value = poly_eval(coeffs, outsider_point)
    if value != kc_int:
        ok("outsider's point does not yield Kc")

    step("7. Revoke 'bob': new Kc, new r, rebuild from the remaining 3")
    new_kc_int = int.from_bytes(os.urandom(32), "big") % P
    new_kc = new_kc_int.to_bytes(32, "big")
    new_r = os.urandom(32)
    remaining = {n: k for n, k in users.items() if n != "bob"}
    new_points = {n: h(k, new_r) for n, k in remaining.items()}
    new_coeffs = poly_from_roots(list(new_points.values()))
    new_coeffs[0] = (new_coeffs[0] + new_kc_int) % P
    show("new Kc", new_kc.hex())

    for name in remaining:
        value = poly_eval(new_coeffs, new_points[name])
        if value == new_kc_int:
            ok(f"{name} still works with their OLD Ki (no re-keying needed)")

    bob_old_point = h(users["bob"], new_r)
    bob_value = poly_eval(new_coeffs, bob_old_point)
    if bob_value != new_kc_int:
        ok("bob (revoked) computes a wrong value, not the new Kc")
    warn("In Paper A these coefficients are protected with ABE, not posted publicly.")
    note("This demo shows the algebra of recovery + revocation, not full security.")


if __name__ == "__main__":
    main()
