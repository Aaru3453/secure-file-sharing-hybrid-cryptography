"""
Live HTTP Socket Test for Flask Hybrid Crypto App
=================================================
Interacts with the running Flask application on http://127.0.0.1:5000:
1. Registers alice & bob over HTTP
2. Logs in alice with session cookies
3. Alice uploads and encrypts cns_demo_file.txt for bob
4. Logs out alice
5. Logs in bob with session cookies
6. Bob inspects received files and views verification page
7. Bob downloads decrypted file and checks content
"""

import requests
import os

BASE_URL = "http://127.0.0.1:5000"

def run_live_test():
    session_alice = requests.Session()
    session_bob = requests.Session()

    print("[1] Registering Alice...")
    r = session_alice.post(f"{BASE_URL}/register", data={
        "username": "alice_live",
        "email": "alice_live@college.edu",
        "password": "AlicePassword123!",
        "confirm_password": "AlicePassword123!"
    }, allow_redirects=True)
    assert r.status_code == 200, f"Register Alice failed: {r.status_code}"
    print(" -> Alice registered successfully.")

    print("[2] Registering Bob...")
    r = session_bob.post(f"{BASE_URL}/register", data={
        "username": "bob_live",
        "email": "bob_live@college.edu",
        "password": "BobPassword456!",
        "confirm_password": "BobPassword456!"
    }, allow_redirects=True)
    assert r.status_code == 200, f"Register Bob failed: {r.status_code}"
    print(" -> Bob registered successfully.")

    print("[3] Logging in as Alice...")
    r = session_alice.post(f"{BASE_URL}/login", data={
        "username": "alice_live",
        "password": "AlicePassword123!"
    }, allow_redirects=True)
    assert "Welcome back, alice_live" in r.text
    print(" -> Alice logged in successfully.")

    print("[4] Fetching Bob's user ID from Alice's send page...")
    r = session_alice.get(f"{BASE_URL}/send")
    assert "bob_live" in r.text
    # Extract Bob's id
    import re
    bob_id_match = re.search(r'<option value="(\d+)">\s*👤\s*bob_live', r.text)
    assert bob_id_match, "Could not find bob_live option in dropdown"
    bob_id = bob_id_match.group(1)
    print(f" -> Found Bob's ID: {bob_id}")

    print("[5] Alice encrypts and sends cns_demo_file.txt to Bob...")
    demo_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cns_demo_file.txt")
    with open(demo_file_path, "rb") as f:
        file_bytes = f.read()
        f.seek(0)
        r = session_alice.post(f"{BASE_URL}/send", data={
            "receiver_id": bob_id
        }, files={
            "file": ("cns_demo_file.txt", f, "text/plain")
        }, allow_redirects=True)
    assert r.status_code == 200
    assert "encrypted and securely transferred to bob_live" in r.text
    print(" -> File encrypted and transferred successfully.")

    print("[6] Logging in as Bob...")
    r = session_bob.post(f"{BASE_URL}/login", data={
        "username": "bob_live",
        "password": "BobPassword456!"
    }, allow_redirects=True)
    assert "Welcome back, bob_live" in r.text
    print(" -> Bob logged in successfully.")

    print("[7] Bob visits Received Files...")
    r = session_bob.get(f"{BASE_URL}/received-files")
    assert "cns_demo_file.txt" in r.text
    # Extract file ID
    file_id_match = re.search(r'/verify/(\d+)', r.text)
    assert file_id_match, "Could not find file verification link"
    file_id = file_id_match.group(1)
    print(f" -> Found received file ID: {file_id}")

    print("[8] Bob views Cryptographic Verification & Audit page...")
    r = session_bob.get(f"{BASE_URL}/verify/{file_id}")
    assert r.status_code == 200
    assert "DECAPSULATED" in r.text, "RSA-OAEP decapsulation check missing"
    assert "TAG VERIFIED" in r.text, "AES-GCM tag verification missing"
    assert "SIGNATURE VALID" in r.text, "RSA-PSS signature check missing"
    assert "MATCH 100%" in r.text, "SHA-256 integrity match check missing"
    print(" -> ALL 4 CRYPTOGRAPHIC CHECKS PASSED (RSA-OAEP, AES-GCM, RSA-PSS, SHA-256)!")

    print("[9] Bob downloads decrypted file...")
    r = session_bob.get(f"{BASE_URL}/download/{file_id}")
    assert r.status_code == 200
    assert r.content == file_bytes, "Downloaded bytes do not match original file bytes!"
    print(" -> Downloaded decrypted file matches original demo file EXACTLY (100% byte match)!")

    print("\n============================================================")
    print(" ALL LIVE NETWORK WORKFLOW TESTS PASSED SUCCESSFULLY! ")
    print("============================================================")

if __name__ == '__main__':
    run_live_test()
