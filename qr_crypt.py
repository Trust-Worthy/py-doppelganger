




### used to generate keysand sign/ verify messages
from cryptography.hazmat.primitives.asymmetric import ed25519 

### used to convert keys (like pub key) into byte formats so they can be saved, sent, or shared
from cryptography.hazmat.primitives import serialization

### exception type to catch if signature verification fails (signed message was tampered with or diff key was used)
from cryptography.exceptions import InvalidSignature

### Used to generate cryptographically strong random nonce (one-time number) – preventing predictable challenges.
import secrets

import qrcode
import base64
import json
import time 



# --- Step 1: Generate Key pair (this is Alice)
alice_private_key = ed25519.Ed25519PrivateKey.generate()
alice_public_key = alice_private_key.public_key()

# --- Step 2: Save public key in a sharable form (e.g. QR)
pub_bytes = alice_public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# --- Step 3: encodes the bytes to make them readable and embedabble in JSON or QR
pub_b64 = base64.b64encode(pub_bytes).decode()

# --- Generate a challenge
nonce = secrets.token_hex(16) # one time use token
timestamp = int(time.time()) # gets current time
challenge = f"verify:{nonce}:{timestamp}" # creates challenge string that will be signed.
print(f"Challenge: {challenge}")

# --- Step 4: Alice sings the challenge
signed = alice_private_key.sign(challenge.encode())
signature_b64 = base64.b64encode(signed).decode()
# --- Step 5: Package response as a QR

payload = {
    "public_key": pub_b64, ### pub key so others can verify
    "challenge": challenge, ### original challenge so people know what was signed
    "signature": signature_b64 ### signature
}

payload_json = json.dumps(payload)

### Step 6: Create QR code
qr = qrcode.make(payload_json)
qr.show()



### Step 7: Bob Verify's response (on-scan)
def verify_response(payload_json) -> dict:
    """
    Parsees a json payload into a python dictionary

    Args:
        payload_json (_type_): payload containing the pub key, challenge, and signature
    """
    data = json.loads(payload_json)
    return data

### Step 8: Bob reconstructs the original public key from the shared base64 string

try:
    data = verify_response(payload_json=payload)
    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.
        b64decode(data["public_key"])
    )

    ### Step 9: Bob attempts to verity the signature against the challenge (encoded)
    pub_key.verify(
        base64.b64decode(data["signature"]),
        data["challenge"].encode()
    )
    print("✅ Identity verified!")
except InvalidSignature:
    print("❌ Verification failed.")
    ### If they match it means the signer had the private key + message wasn't tampered with

### TO-DO ###
'''
1. Add a re-direct feature to popular messaging apps once contacts are verified
'''