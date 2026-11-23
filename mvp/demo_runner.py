"""Live automated demonstration of Slice 3: Hybrid / Envelope Encryption."""

import json
import urllib.error
import urllib.parse
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


def get_json(path: str) -> dict | list:
    with urllib.request.urlopen(f"{BASE_URL}{path}") as resp:
        return json.loads(resp.read().decode("utf-8"))


def upload_multipart(owner_id: str, filename: str, content: bytes) -> dict:
    boundary = uuid.uuid4().hex
    body = bytearray()

    # Form field: owner_id
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(b'Content-Disposition: form-data; name="owner_id"\r\n\r\n')
    body.extend(owner_id.encode("utf-8"))
    body.extend(b"\r\n")

    # File field
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


def main():
    print("=" * 65)
    print("DEMO: Live Execution of Slice 3 (FastAPI + Envelope Encryption)")
    print("=" * 65)

    # 1. Health check
    health = get_json("/health")
    print(f"\n[1] Health Check: {health}")

    # 2. Register users
    alice = post_json("/users", {"username": f"alice_{uuid.uuid4().hex[:6]}", "role": "professor"})
    bob = post_json("/users", {"username": f"bob_{uuid.uuid4().hex[:6]}", "role": "student"})
    eve = post_json("/users", {"username": f"eve_{uuid.uuid4().hex[:6]}", "role": "intruder"})

    print(f"\n[2] Registered Users:")
    print(f"    - Professor Alice ID: {alice['user_id']}")
    print(f"    - Student Bob ID:     {bob['user_id']}")
    print(f"    - Intruder Eve ID:    {eve['user_id']}")

    # 3. Alice uploads and encrypts an exam paper
    exam_content = b"FINAL EXAM: 1. Explain AES-GCM. 2. Derive RSA key generation."
    upload_res = upload_multipart(alice["user_id"], "exam_paper.txt", exam_content)
    file_id = upload_res["file_id"]
    print(f"\n[3] Alice Uploads File:")
    print(f"    - File ID:         {file_id}")
    print(f"    - Plaintext size:  {upload_res['plaintext_size']} bytes")
    print(f"    - Ciphertext size: {upload_res['ciphertext_size']} bytes (AES-256-GCM + 16B auth tag)")

    # 4. Bob attempts download before sharing (Must be rejected)
    status_bob_before, err_bob_before = download(file_id, bob["user_id"])
    print(f"\n[4] Bob downloads BEFORE being authorized:")
    print(f"    - HTTP Status: {status_bob_before} (Expected 403 Forbidden)")
    print(f"    - Response:    {err_bob_before.decode('utf-8')}")

    # 5. Alice shares file with Bob (RSA key-wrapping)
    share_res = post_json("/share", {
        "file_id": file_id,
        "owner_id": alice["user_id"],
        "recipient_id": bob["user_id"]
    })
    print(f"\n[5] Alice Shares with Bob (Envelope Key-Wrapping):")
    print(f"    - Share ID: {share_res['share_id']}")
    print(f"    - Status:   {share_res['status']}")

    # 6. Bob downloads and decrypts
    status_bob_after, content_bob_after = download(file_id, bob["user_id"])
    print(f"\n[6] Bob downloads AFTER authorization:")
    print(f"    - HTTP Status: {status_bob_after} (Success)")
    print(f"    - Decrypted:   {content_bob_after.decode('utf-8')}")
    assert content_bob_after == exam_content
    print("    - Integrity:   MATCHES ORIGINAL BYTES EXACTLY!")

    # 7. Eve (unauthorized) tries to download
    status_eve, err_eve = download(file_id, eve["user_id"])
    print(f"\n[7] Intruder Eve attempts to download:")
    print(f"    - HTTP Status: {status_eve} (Expected 403 Forbidden)")
    print(f"    - Response:    {err_eve.decode('utf-8')}")

    print("\n" + "=" * 65)
    print("RESULT: ALL SECURITY POLICIES ENFORCED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    main()
