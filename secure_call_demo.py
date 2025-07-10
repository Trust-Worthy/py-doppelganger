from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import base64
import secrets

app = Flask(__name__)

# In-memory storage
users = {}  # Stores public/private keys
pending_requests = {}  # Stores pending call requests

# HTML Template (simplified UI)
template = '''
<!doctype html>
<title>Secure Contact Demo</title>
<h1>{{ user }}'s Dashboard</h1>
<p><b>Your Public Key:</b> {{ pubkey }}</p>
<form method="POST" action="/send_request/{{ user }}">
  <label>Send call request to:</label>
  <input name="target" placeholder="Bob or Alice" required>
  <button type="submit">Send Secure Call Request</button>
</form>
<br>
{% if requests %}
  <h2>Incoming Requests</h2>
  {% for sender, message in requests.items() %}
    <p>Request from {{ sender }} - Verified: {{ message['verified'] }}</p>
    {% if message['verified'] %}
      <a href="/accept/{{ user }}/{{ sender }}">Accept & Redirect</a>
    {% endif %}
  {% endfor %}
{% endif %}
'''

# Generate keys per user (once)
def generate_keys():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_b64 = base64.b64encode(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()
    return priv, pub_b64

# Initialize Alice and Bob
for name in ["Alice", "Bob"]:
    priv, pub_b64 = generate_keys()
    users[name] = {
        "private_key": priv,
        "public_key": pub_b64
    }

@app.route("/<user>")
def dashboard(user):
    pubkey = users[user]["public_key"]
    incoming = pending_requests.get(user, {})
    return render_template_string(template, user=user, pubkey=pubkey, requests=incoming)

@app.route("/send_request/<sender>", methods=["POST"])
def send_request(sender):
    target = request.form["target"]
    if target not in users:
        return f"User {target} not found.", 400

    priv = users[sender]["private_key"]
    message = f"call_request_from:{sender}"
    sig = priv.sign(message.encode())
    sig_b64 = base64.b64encode(sig).decode()

    if target not in pending_requests:
        pending_requests[target] = {}

    # Verify the message on the recipient side
    sender_pubkey_bytes = base64.b64decode(users[sender]["public_key"])
    sender_pub = ed25519.Ed25519PublicKey.from_public_bytes(sender_pubkey_bytes)
    try:
        sender_pub.verify(base64.b64decode(sig_b64), message.encode())
        verified = True
    except InvalidSignature:
        verified = False

    pending_requests[target][sender] = {
        "message": message,
        "signature": sig_b64,
        "verified": verified
    }
    return redirect(url_for("dashboard", user=sender))

@app.route("/accept/<receiver>/<sender>")
def accept_call(receiver, sender):
    # Simulated redirect to call app (could be WhatsApp, FaceTime, etc.)
    return redirect("https://www.whatsapp.com")

if __name__ == "__main__":
    app.run(debug=True)
