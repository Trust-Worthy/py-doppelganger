




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


### TO-DO ###
'''
1. Add a re-direct feature to popular messaging apps once contacts are verified
'''