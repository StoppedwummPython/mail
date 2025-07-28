import requests
import base64
import json
import os
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class MailClient:
    """
    A client for the secure mail server that saves its private key locally.
    """
    def __init__(self, server_url, address):
        self.server_url = server_url
        self.address = address
        self.private_key = None
        self.config_file = self._get_config_filename(address)
        
        print(f"Client for '{self.address}' initialized.")
        self.load_config()

    def _get_config_filename(self, address):
        """Creates a safe filename from the client's address."""
        sanitized_address = re.sub(r'[^a-zA-Z0-9_@.-]', '_', address)
        return f"client_config_{sanitized_address}.json"

    def save_config(self):
        """Saves the private key to a local file, creating it if needed."""
        if not self.private_key: return
        print(f"Saving configuration to '{self.config_file}'...")
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        with open(self.config_file, 'w') as f:
            json.dump({"address": self.address, "private_key_pem": private_key_pem}, f, indent=4)
        print("✅ Configuration saved.")

    def load_config(self):
        """Loads the private key from a local file if it exists."""
        if os.path.exists(self.config_file):
            print(f"Found existing config file: '{self.config_file}'")
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                    self.private_key = serialization.load_pem_private_key(
                        config_data['private_key_pem'].encode('utf-8'), password=None
                    )
                    print(f"✅ Private key for '{self.address}' loaded from file.")
                    return True
            except Exception as e:
                print(f"❌ Error reading config file: {e}. Please check it or register again.")
                return False
        else:
            print("No local configuration file found. Client must register to get a key.")
        return False

    def register(self):
        """Registers the client if it doesn't already have a private key."""
        if self.private_key:
            print(f"'{self.address}' already has a key loaded. Skipping registration.")
            return True
        print(f"Attempting to register '{self.address}' on the server...")
        try:
            response = requests.post(f"{self.server_url}/register", json={"address": self.address})
            if response.status_code == 201:
                data = response.json()
                self.private_key = serialization.load_pem_private_key(
                    data['privateKey'].encode('utf-8'), password=None
                )
                print(f"✅ Successfully registered '{self.address}'.")
                self.save_config()
                return True
            else:
                print(f"❌ Registration failed: {response.json().get('error')}")
                return False
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Connection Error: Could not connect to {self.server_url}.")
            return False

    def _get_public_key(self, recipient_address):
        """Fetches a public key from the server."""
        try:
            response = requests.get(f"{self.server_url}/publicKey/{recipient_address}")
            if response.status_code == 200:
                return serialization.load_pem_public_key(response.json()['publicKey'].encode('utf-8'))
            print(f"❌ Error fetching public key: {response.json().get('error')}")
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Connection Error: {e}")
            return None

    def send_mail(self, recipient, message_content):
        """Encrypts and sends an email to a recipient."""
        print(f"\n--- Sending Mail from {self.address} to {recipient} ---")
        public_key = self._get_public_key(recipient)
        if not public_key: return

        encrypted_content = base64.b64encode(public_key.encrypt(
            message_content.encode('utf-8'),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )).decode('utf-8')
        
        payload = {"sender": self.address, "recipient": recipient, "encryptedContent": encrypted_content}
        response = requests.post(f"{self.server_url}/send", json=payload)
        if response.status_code == 201:
            print("✅ Mail successfully sent.")
        else:
            print(f"❌ Failed to send mail: {response.text}")

    def check_inbox(self):
        """Fetches the mail-chain and decrypts messages for this client."""
        if not self.private_key:
            print("❌ Cannot check inbox without a private key. Please register first.")
            return
        print(f"\n--- Checking Inbox for {self.address} ---")
        response = requests.get(f"{self.server_url}/mailchain")
        if response.status_code != 200:
            print("❌ Error fetching mail-chain.")
            return

        found_messages = False
        for mail in response.json()['chain']:
            is_for_me = mail['recipient'] == self.address or \
                        (self.address.startswith('*@') and mail['recipient'].endswith(self.address.split('@')[1]))
            if is_for_me:
                found_messages = True
                print(f"Found message for '{mail['recipient']}' from '{mail['sender']}'")
                try:
                    decrypted = self.private_key.decrypt(
                        base64.b64decode(mail['encryptedContent']),
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    ).decode('utf-8')
                    print(f"   ✅ Decrypted: '{decrypted}'\n")
                except Exception as e:
                    print(f"   ❌ Could not decrypt. Error: {e}\n")
        if not found_messages:
            print("No new messages found.")

def run_full_demo():
    """Demonstrates the entire system workflow."""
    SERVER_URL = "http://localhost:3000"
    print("=================================================\n=          SECURE MAIL SYSTEM DEMO            =\n=================================================\n")
    print("--- 1. Alice connects & registers ---")
    alice = MailClient(SERVER_URL, "alice@public.com")
    alice.register()

    print("\n--- 2. Bob connects & registers ---")
    bob = MailClient(SERVER_URL, "bob@public.com")
    bob.register()
    
    print("\n--- 3. Alice sends a secret message to Bob ---")
    alice.send_mail("bob@public.com", "Hi Bob, let's discuss the project privately.")

    print("\n--- 4. Bob checks his inbox ---")
    bob.check_inbox()

    print("\n\n=================================================\n=          PRIVATE DOMAIN DEMO              =\n=================================================\n")
    print("\n--- 5. Company registers its entire domain ---")
    company = MailClient(SERVER_URL, "*@my-company.com")
    company.register()
    
    print("\n--- 6. Alice sends mail to two different addresses at the company ---")
    alice.send_mail("support@my-company.com", "Help! I am locked out of my account.")
    alice.send_mail("sales@my-company.com", "I would like a quote for 1000 units.")

    print("\n--- 7. The company client checks all mail for its domain ---")
    company.check_inbox()

if __name__ == "__main__":
    # To start with a clean slate, delete all .json files in the server and client directories.
    run_full_demo()