# wallet/key_manager.py
from crypto.crypto_utils import CryptoUtils
from config import WALLET_DIR
import os
import json
import hashlib

class KeyManager:

  def __init__(self, wallet_name: str):
    self.wallet_name = wallet_name
    self.wallet_path = os.path.join(WALLET_DIR, f"{wallet_name}.json")
    self.private_key = None
    self.public_key = None
    self.identity = None

  def create_new_identity(self, password: str):
    """Nowa tożsamość"""

    print(f"[*] Generowanie nowej tożsamości dla {self.wallet_name}...")

    private_key, public_key = CryptoUtils.generate_keypair()

    private_key_bytes = CryptoUtils.get_private_key_bytes(private_key)
    public_key_bytes = CryptoUtils.get_public_key_bytes(public_key)

    encrypted_private, salt = CryptoUtils.encrypt_private_key(
      private_key_bytes,
      password
    )

    address = CryptoUtils.hash_data(public_key_bytes)[:40]

    wallet_data = {
      "wallet_name": self.wallet_name,
      "address": address,
      "public_key": public_key_bytes.decode('utf-8'),
      "encrypted_private_key": encrypted_private.hex(),
      "salt": salt.hex(),
      "identity_hash": CryptoUtils.hash_data(
        public_key_bytes
      )
    }

    with open(self.wallet_path, 'w') as f:
      json.dump(wallet_data, f, indent=2)

    self.private_key = private_key
    self.public_key = public_key
    self.identity = wallet_data

    print(f"[+] Tożsamość utworzona!")
    print(f"[+] Adres: {address}")
    print(f"[+] Zapisano: {self.wallet_path}")

    return wallet_data

  def load_identity(self, password: str):
    """Ładuje istniejącą tozsamość"""
    if not os.path.exists(self.wallet_path):
      raise FileNotFoundError(
        f"Portfel {self.wallet_name} nie istnieje."
      )

    print(f"[*] Ładowanie tożsamości z {self.wallet_path}...")

    with open(self.wallet_path, 'r') as f:
      wallet_data = json.load(f)

    try:
      encrypted_private = bytes.fromhex(
        wallet_data["encrypted_private_key"]
      )
      salt = bytes.fromhex(wallet_data["salt"])

      private_key_bytes = CryptoUtils.decrypt_private_key(
        encrypted_private,
        password,
        salt
      )

      self.private_key = CryptoUtils.load_private_key(
        private_key_bytes
      )

      public_key_bytes = wallet_data["public_key"].encode('utf-8')
      self.public_key = CryptoUtils.load_public_key(
        public_key_bytes
      )

      self.identity = wallet_data

      print(f"[+] Tożsamość załadowana!")
      print(f"[+] Adres: {wallet_data['address']}")
      return wallet_data

    except Exception as e:
      raise ValueError(f"Błędne hasło lub uszkodzony portfel: {e}")

  def get_address(self) -> str:
    """Zwraca adres portfela"""
    if self.identity is None:
      raise ValueError("Tożsamość nie została załadowana.")
    return self.identity["address"]

  def sign_data(self, data: bytes) -> str:
    """Podpisuje dane prywatnym kluczem"""
    if self.private_key is None:
      raise ValueError("Prywatny klucz nie został załadowany.")

    signature = CryptoUtils.sign_message(self.private_key, data)
    return signature.hex()

  def get_public_key_hex(self) -> str:
    """Zwraca klucz publiczny w formacie hex"""
    if self.public_key is None:
      raise ValueError("Publiczny klucz nie został załadowany.")
    return self.identity["public_key"]
