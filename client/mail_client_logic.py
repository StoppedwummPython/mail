import requests
import base64
import json
import os
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MailClientLogic:
    def __init__(self, server_url, address, log_callback):
        self.server_url = server_url
        self.address = address
        self.private_key = None
        self.log = log_callback
        self.config_file = self._get_config_filename(address)

    def send_mail(self, recipient, message_content):
        """Sends mail using Hybrid Encryption so both sender and recipient can read it."""
        if not self.private_key:
            return False, "Not logged in."

        try:
            # 1. Get Recipient Public Key
            res = requests.get(f"{self.server_url}/publicKey/{recipient}")
            if res.status_code != 200:
                return False, "Recipient not found."
            recipient_pub_pem = res.json()['publicKey']
            recipient_public_key = serialization.load_pem_public_key(recipient_pub_pem.encode())

            # 2. Hybrid Encryption (AES-GCM)
            # Generate a random 32-byte key and 12-byte IV
            aes_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(aes_key)
            iv = os.urandom(12)
            
            # Encrypt the message body
            ciphertext_with_tag = aesgcm.encrypt(iv, message_content.encode(), None)
            # AESGCM in cryptography.py puts the tag at the end of the ciphertext
            tag = ciphertext_with_tag[-16:]
            encrypted_msg = ciphertext_with_tag[:-16]

            # 3. RSA Encrypt the AES key for BOTH recipient and sender
            def rsa_encrypt(key, data):
                return key.encrypt(
                    data,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

            enc_key_recipient = rsa_encrypt(recipient_public_key, aes_key)
            enc_key_sender = rsa_encrypt(self.private_key.public_key(), aes_key)

            # 4. Prepare Payload for Step 1 (Challenge)
            payload = {
                "sender": self.address,
                "recipient": recipient,
                "encryptedMessage": base64.b64encode(encrypted_msg).decode(),
                "iv": base64.b64encode(iv).decode(),
                "tag": base64.b64encode(tag).decode(),
                "encryptedKeyForRecipient": base64.b64encode(enc_key_recipient).decode(),
                "encryptedKeyForSender": base64.b64encode(enc_key_sender).decode()
            }

            # 5. Challenge-Response
            self.log("Sending challenge request...")
            chal_res = requests.post(f"{self.server_url}/send-challenge", json=payload)
            if chal_res.status_code != 200:
                return False, chal_res.json().get('error')

            data = chal_res.json()
            # Decrypt nonce to prove identity
            decrypted_nonce = self.private_key.decrypt(
                base64.b64decode(data['encryptedNonce']),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode()

            # 6. Verify and Finalize
            verify_res = requests.post(f"{self.server_url}/send-verify", json={
                "challengeId": data['challengeId'],
                "decryptedNonce": decrypted_nonce
            })

            return (True, "Success") if verify_res.status_code == 201 else (False, "Verification failed")

        except Exception as e:
            return False, str(e)

    def check_inbox(self):
        """Fetches and decrypts messages for both recipient and sender."""
        if not self.private_key: return None, "Not logged in."
        try:
            res = requests.get(f"{self.server_url}/mailchain")
            if res.status_code != 200: return None, "Chain fetch failed."

            messages = []
            is_domain = self.address.startswith('*@')
            domain = self.address.split('@')[1] if '@' in self.address else ""

            for mail in res.json()['chain']:
                is_recipient = mail['recipient'] == self.address or (is_domain and mail['recipient'].endswith(f"@{domain}"))
                is_sender = mail['sender'] == self.address
                
                if not (is_recipient or is_sender):
                    continue

                content = None
                try:
                    # Case 1: Hybrid Format (Try this first)
                    if 'encryptedMessage' in mail:
                        key_b64 = mail['encryptedKeyForRecipient'] if is_recipient else mail['encryptedKeyForSender']
                        
                        # Decrypt AES key
                        aes_key = self.private_key.decrypt(
                            base64.b64decode(key_b64),
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        )
                        
                        # Decrypt Body
                        iv = base64.b64decode(mail['iv'])
                        tag = base64.b64decode(mail['tag'])
                        ciphertext = base64.b64decode(mail['encryptedMessage'])
                        
                        aesgcm = AESGCM(aes_key)
                        content = aesgcm.decrypt(iv, ciphertext + tag, None).decode()

                    # Case 2: Old Format (Only recipient can read these)
                    elif 'encryptedContent' in mail and is_recipient:
                        content = self.private_key.decrypt(
                            base64.b64decode(mail['encryptedContent']),
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        ).decode()

                    if content:
                        messages.append({
                            'from': mail['sender'], 'to': mail['recipient'],
                            'timestamp': mail['timestamp'], 'content': content
                        })
                except:
                    continue
            return messages, "Done"
        except Exception as e:
            return None, str(e)

    # --- Utility Methods ---
    def _get_config_filename(self, addr):
        return f"client_config_{re.sub(r'[^a-zA-Z0-9_@.-]', '_', addr)}.json"

    def _save_config(self):
        pem = self.private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        with open(self.config_file, 'w') as f: json.dump({"address": self.address, "private_key_pem": pem}, f)

    def _load_from_file(self, path):
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = json.load(f)
                self.private_key = serialization.load_pem_private_key(data['private_key_pem'].encode(), password=None)
                return True
        return False

    def load_or_register(self):
        if self._load_from_file(self.config_file): return True, "Loaded"
        try:
            res = requests.post(f"{self.server_url}/register", json={"address": self.address})
            if res.status_code == 201:
                self.private_key = serialization.load_pem_private_key(res.json()['privateKey'].encode(), password=None)
                self._save_config()
                return True, "Registered"
            return False, res.json().get('error')
        except: return False, "Server Down"