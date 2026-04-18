import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class CryptoEngine:
    def __init__(self):
        self.aes_key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.aes_key)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def encrypt_payload(self, data_dict):
        nonce = os.urandom(12)
        plaintext = json.dumps(data_dict).encode('utf-8')
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')

    def generate_hash(self, data_str, prev_hash):
        digest = hashlib.sha256()
        digest.update((prev_hash + data_str).encode('utf-8'))
        return digest.hexdigest()

    def sign_alert(self, message):
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def secure_channel_encrypt(self, command_str):
        ciphertext = self.public_key.encrypt(
            command_str.encode('utf-8'),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return base64.b64encode(ciphertext).decode('utf-8')