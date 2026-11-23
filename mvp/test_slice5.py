"""Automated verification test runner for Slice 5: Tamper-Evident Audit Log."""

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


def get_json(path: str) -> dict | list:
    with urllib.request.urlopen(f"{BASE_URL}{path}") as resp:
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
    print("=" * 75)
    print("DEMO: Live Execution of Slice 5 (Tamper-Evident Audit Log via Hash Chains)")
    print("=" * 75)

    # 1. Register users
    alice = post_json("/users", {"username": f"prof_{uuid.uuid4().hex[:6]}", "role": "professor"})
    bob = post_json("/users", {"username": f"student_{uuid.uuid4().hex[:6]}", "role": "student"})
    eve = post_json("/users", {"username": f"intruder_{uuid.uuid4().hex[:6]}", "role": "intruder"})

    # 2. Upload file
    upload_res = upload_multipart(alice["user_id"], "thesis.pdf", b"Confidential Thesis Draft v1")
    file_id = upload_res["file_id"]

    # 3. Eve tries unauthorized download (generates DOWNLOAD_DENIED entry)
    download(file_id, eve["user_id"])

    # 4. Alice shares with Bob with future expiry
    valid_time = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    post_json("/share", {
        "file_id": file_id,
        "owner_id": alice["user_id"],
        "recipient_id": bob["user_id"],
        "expires_at": valid_time,
    })

    # 5. Bob downloads (generates DOWNLOAD_GRANTED entry)
    download(file_id, bob["user_id"])

    # 6. Alice revokes Bob's access (generates ACCESS_REVOKED entry)
    post_json("/revoke", {
        "file_id": file_id,
        "owner_id": alice["user_id"],
        "recipient_id": bob["user_id"],
    })

    # 7. Bob attempts download again (generates DOWNLOAD_DENIED entry)
    download(file_id, bob["user_id"])

    # 8. Inspect the Audit Logs
    logs = get_json("/audit/logs")
    print(f"\n[+] Total Audit Entries Generated: {len(logs)}")
    for log in logs:
        print(f"  Seq {log['sequence_id']}: [{log['action']}] by user {log['user_id'][:8]}...")
        print(f"       prev_hash:  {log['prev_hash'][:16]}...")
        print(f"       entry_hash: {log['entry_hash'][:16]}...")

    # 9. Cryptographically verify the chain
    verify_res = get_json("/audit/verify")
    print(f"\n[+] Cryptographic Chain Verification Result:")
    print(f"    - Status:  {verify_res['status']}")
    print(f"    - Entries: {verify_res['total_entries']}")
    print(f"    - Message: {verify_res['message']}")
    assert verify_res["status"] == "VALID"

    print("\n" + "=" * 75)
    print("SUCCESS: Full tamper-evident audit log verified!")
    print("=" * 75)


if __name__ == "__main__":
    run_tests()
