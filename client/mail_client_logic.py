import requests
import base64
import json
import os
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class MailClientLogic:
    """
    Handles all non-GUI logic. This version implements the new
    two-step challenge-response protocol for sending mail.
    """
    def __init__(self, server_url, address, log_callback):
        self.server_url = server_url
        self.address = address
        self.private_key = None
        self.log = log_callback
        self.config_file = self._get_config_filename(address)

    def send_mail(self, recipient, message_content):
        """Sends an email using the new two-step challenge-response flow."""
        if not self.private_key:
            return False, "Cannot send mail. You are not logged in."

        try:
            # First, get the recipient's public key to encrypt the original message
            self.log(f"Preparing message for '{recipient}'...")
            recipient_key_response = requests.get(f"{self.server_url}/publicKey/{recipient}")
            if recipient_key_response.status_code != 200:
                return False, f"Could not get public key: {recipient_key_response.json().get('error')}"
            
            recipient_public_key = serialization.load_pem_public_key(recipient_key_response.json()['publicKey'].encode('utf-8'))
            
            # Encrypt the actual message content
            encrypted_content = base64.b64encode(recipient_public_key.encrypt(
                message_content.encode('utf-8'),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )).decode('utf-8')

            # --- STEP 1: SEND CHALLENGE REQUEST ---
            self.log("Initiating secure send... Requesting challenge from server.")
            initial_payload = {"sender": self.address, "recipient": recipient, "encryptedContent": encrypted_content}
            challenge_response = requests.post(f"{self.server_url}/send-challenge", json=initial_payload)

            if challenge_response.status_code != 200:
                return False, f"Server rejected send request: {challenge_response.json().get('error')}"

            challenge_data = challenge_response.json()
            challenge_id = challenge_data['challengeId']
            encrypted_nonce_b64 = challenge_data['encryptedNonce']
            
            # --- STEP 2: SOLVE THE CHALLENGE ---
            self.log("Challenge received. Decrypting with private key...")
            encrypted_nonce_bytes = base64.b64decode(encrypted_nonce_b64)
            
            # This is the proof-of-possession step
            decrypted_nonce = self.private_key.decrypt(
                encrypted_nonce_bytes,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode('utf-8')

            # --- STEP 3: SEND VERIFICATION ---
            self.log("Challenge solved. Sending verification back to server...")
            verification_payload = {"challengeId": challenge_id, "decryptedNonce": decrypted_nonce}
            final_response = requests.post(f"{self.server_url}/send-verify", json=verification_payload)

            if final_response.status_code == 201:
                return True, "Mail sent successfully after passing security challenge."
            else:
                return False, f"Server rejected verification: {final_response.json().get('error')}"

        except Exception as e:
            self.log(f"An unexpected error occurred during send: {e}")
            return False, f"An unexpected error occurred: {e}"

    def _get_config_filename(self, address):
        """Creates a safe filename from the client's address."""
        sanitized_address = re.sub(r'[^a-zA-Z0-9_@.-]', '_', address)
        return f"client_config_{sanitized_address}.json"

    def _save_config(self):
        """Saves the current private key to the config file matching the user's address."""
        if not self.private_key: return
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        with open(self.config_file, 'w') as f:
            json.dump({"address": self.address, "private_key_pem": private_key_pem}, f, indent=4)

    def _load_from_file(self, file_path):
        """Generic function to load a private key from a given file path."""
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    config_data = json.load(f)
                    self.private_key = serialization.load_pem_private_key(
                        config_data['private_key_pem'].encode('utf-8'), password=None
                    )
                    return True
            except Exception as e:
                self.log(f"Error reading config file '{file_path}': {e}")
                return False
        return False

    def _register(self):
        """Registers the current address on the server."""
        try:
            response = requests.post(f"{self.server_url}/register", json={"address": self.address})
            if response.status_code == 201:
                data = response.json()
                self.private_key = serialization.load_pem_private_key(
                    data['privateKey'].encode('utf-8'), password=None
                )
                self._save_config()
                return True, f"Successfully registered and saved new key for '{self.address}'."
            else:
                return False, f"Registration failed: {response.json().get('error')}"
        except requests.exceptions.ConnectionError:
            return False, f"Connection Error: Could not connect to {self.server_url}."

    def load_or_register(self):
        """Intelligent login: checks for specific key, then domain key, then registers."""
        if self._load_from_file(self.config_file):
            return True, f"Key for {self.address} loaded from local file."
        
        if not self.address.startswith('*@'):
            try:
                domain = self.address.split('@')[1]
                wildcard_address = f"*@{domain}"
                wildcard_config_file = self._get_config_filename(wildcard_address)
                if self._load_from_file(wildcard_config_file):
                    return True, f"Logged in as '{self.address}' using the domain key for '*{domain}'."
            except IndexError:
                pass # Malformed address, will fail at registration
        
        return self._register()

    def check_inbox(self):
        """Fetches the mail-chain and decrypts messages."""
        if not self.private_key:
            return None, "Cannot check mail. Not logged in."
        try:
            response = requests.get(f"{self.server_url}/mailchain")
            if response.status_code != 200:
                return None, "Error fetching mail-chain."

            decrypted_messages = []
            is_domain_client = self.address.startswith('*@')
            my_domain = self.address.split('@')[1] if is_domain_client else self.address.split('@')[1]

            for mail in response.json()['chain']:
                # A user can read mail sent to their specific address OR their domain
                recipient_is_me = mail['recipient'] == self.address
                recipient_in_my_domain = mail['recipient'].endswith(f"@{my_domain}")

                if recipient_is_me or (is_domain_client and recipient_in_my_domain):
                    try:
                        decrypted_content = self.private_key.decrypt(
                            base64.b64decode(mail['encryptedContent']),
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        ).decode('utf-8')
                        
                        decrypted_messages.append({
                            'from': mail['sender'],
                            'to': mail['recipient'],
                            'timestamp': mail['timestamp'],
                            'content': decrypted_content
                        })
                    except Exception:
                        pass # Ignore messages that can't be decrypted
            
            return decrypted_messages, f"Found {len(decrypted_messages)} message(s)."
        except Exception as e:
            return None, f"An error occurred while checking mail: {e}"