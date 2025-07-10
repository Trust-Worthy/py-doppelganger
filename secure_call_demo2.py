# Starting point for Flask prototype with verified call request

from flask import Flask, request, jsonify, session
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import base64, json, secrets, time

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# In-memory storage for users and requests
users = {}          # user_id: public_key
pending_requests = {}  # request_id: {from, to, challenge, timestamp, signature}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user_id = data['user_id']
    pubkey_b64 = data['public_key']
    users[user_id] = pubkey_b64
    return jsonify({"status": "registered"})

@app.route('/request_call', methods=['POST'])
def request_call():
    data = request.json
    sender = data['from']
    recipient = data['to']
    challenge = data['challenge']
    signature_b64 = data['signature']
    
    # Verify sender's signature
    try:
        pubkey_bytes = base64.b64decode(users[sender])
        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        pubkey.verify(base64.b64decode(signature_b64), challenge.encode())
    except Exception as e:
        return jsonify({"error": "Invalid signature"}), 400

    request_id = secrets.token_hex(8)
    pending_requests[request_id] = {
        "from": sender,
        "to": recipient,
        "challenge": challenge,
        "timestamp": int(time.time()),
        "signature": signature_b64
    }
    return jsonify({"request_id": request_id})

@app.route('/approve_call/<request_id>', methods=['POST'])
def approve_call(request_id):
    if request_id not in pending_requests:
        return jsonify({"error": "Invalid request ID"}), 404
    req = pending_requests.pop(request_id)
    # In a real app, you could now notify sender
    return jsonify({
        "status": "approved",
        "from": req["from"],
        "to": req["to"],
        "verified": True
    })

@app.route('/')
def index():
    return "Call verification prototype is running."

if __name__ == '__main__':
    app.run(debug=True)
