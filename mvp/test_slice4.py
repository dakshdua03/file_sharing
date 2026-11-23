"""Automated test runner for Slice 4: Time-Restricted Access & Revocation."""

from datetime import datetime, timedelta, timezone
import json
import urllib.error
import urllib.request
import uuid

BASE_URL = "http://127.0.0.1:8000"


def post_json(path: str, data: dict) -> dict:
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def upload_multipart(owner_id: str, filename: str, content: bytes) -> dict:
    boundary = uuid.uuid4().hex
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(b'Content-Disposition: form-data; name="owner_id"\r\n\r\n')
    body.extend(owner_id.encode("utf-8"))
    body.extend(b"\r\n")

    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(
            "utf-8"
        )
    )
    body.extend(b"Content-Type: text/plain\r\n\r\n")
    body.extend(content)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request(
        f"{BASE_URL}/upload",
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def download(file_id: str, user_id: str) -> tuple[int, bytes]:
    url = f"{BASE_URL}/download/{file_id}?user_id={user_id}"
    try:
        with urllib.request.urlopen(url) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def run_tests():
    print("=" * 70)
    print("DEMO: Live Execution of Slice 4 (Time-Restricted Access & Revocation)")
    print("=" * 70)

    # 1. Register users
    alice = post_json("/users", {"username": f"prof_{uuid.uuid4().hex[:6]}", "role": "professor"})
    bob = post_json("/users", {"username": f"student_{uuid.uuid4().hex[:6]}", "role": "student"})
    charlie = post_json("/users", {"username": f"student_{uuid.uuid4().hex[:6]}", "role": "student"})

    print(f"\n[1] Registered Users:")
    print(f"    - Professor Alice: {alice['user_id']}")
    print(f"    - Student Bob:     {bob['user_id']}")
    print(f"    - Student Charlie: {charlie['user_id']}")

    # 2. Upload file
    secret_text = b"Assignment Solution Key - Valid for 10 minutes only"
    upload_res = upload_multipart(alice["user_id"], "solution.txt", secret_text)
    file_id = upload_res["file_id"]
    print(f"\n[2] Uploaded File: {file_id}")

    # 3. Share with Bob with an already-EXPIRED timestamp (-5 minutes)
    expired_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    post_json("/share", {
        "file_id": file_id,
        "owner_id": alice["user_id"],
        "recipient_id": bob["user_id"],
        "expires_at": expired_time,
    })
    print(f"\n[3] Shared with Bob with EXPIRED timestamp ({expired_time}):")
    code_bob, resp_bob = download(file_id, bob["user_id"])
    print(f"    - Bob download status: {code_bob} (Expected 403 Forbidden)")
    print(f"    - Response:            {resp_bob.decode('utf-8')}")
    assert code_bob == 403
    assert b"expired" in resp_bob

    # 4. Share with Charlie with a FUTURE expiry (+1 hour)
    valid_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    post_json("/share", {
        "file_id": file_id,
        "owner_id": alice["user_id"],
        "recipient_id": charlie["user_id"],
        "expires_at": valid_time,
    })
    print(f"\n[4] Shared with Charlie with VALID expiry (+1 hour):")
    code_charlie, resp_charlie = download(file_id, charlie["user_id"])
    print(f"    - Charlie download status: {code_charlie} (Expected 200 OK)")
    print(f"    - Decrypted:               {resp_charlie.decode('utf-8')}")
    assert code_charlie == 200
    assert resp_charlie == secret_text

    # 5. Alice REVOKES Charlie's access immediately
    revoke_res = post_json("/revoke", {
        "file_id": file_id,
        "owner_id": alice["user_id"],
        "recipient_id": charlie["user_id"],
    })
    print(f"\n[5] Alice Revokes Charlie's Access:")
    print(f"    - Revoked status: {revoke_res['status']}")

    # 6. Charlie attempts to download again after revocation
    code_charlie_revoked, resp_charlie_revoked = download(file_id, charlie["user_id"])
    print(f"\n[6] Charlie downloads AFTER Revocation:")
    print(f"    - Charlie download status: {code_charlie_revoked} (Expected 403 Forbidden)")
    print(f"    - Response:                {resp_charlie_revoked.decode('utf-8')}")
    assert code_charlie_revoked == 403
    assert b"revoked" in resp_charlie_revoked

    print("\n" + "=" * 70)
    print("SUCCESS: Expiry & Immediate Revocation fully verified!")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
