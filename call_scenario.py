from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64, json, requests, time, secrets

# Generate keypair for Alice
alice_private = ed25519.Ed25519PrivateKey.generate()
alice_public = base64.b64encode(
    alice_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
).decode()

# Generate keypair for Bob
bob_private = ed25519.Ed25519PrivateKey.generate()
bob_public = base64.b64encode(
    bob_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
).decode()

# Register Alice
requests.post("http://localhost:5000/register", json={
    "user_id": "alice",
    "public_key": alice_public
})

# Register Bob
requests.post("http://localhost:5000/register", json={
    "user_id": "bob",
    "public_key": bob_public
})


# Generate a challenge (like TOTP seed)
nonce = secrets.token_hex(8)
timestamp = int(time.time())
challenge = f"verify:{nonce}:{timestamp}"

# Alice signs the challenge
signature = base64.b64encode(alice_private.sign(challenge.encode())).decode()

# Send request to Bob
resp = requests.post("http://localhost:5000/request_call", json={
    "from": "alice",
    "to": "bob",
    "challenge": challenge,
    "signature": signature
})

print(resp.json())  # Contains request_id
request_id = resp.json()["request_id"]


resp = requests.post(f"http://localhost:5000/approve_call/{request_id}")
print(resp.json())