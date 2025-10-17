from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import hashlib
import secrets

class CryptoUtils:
    """Narzędzia kryptograficzne"""

    CURVE = ec.SECP256R1()
    HASH_ALGO = hashes.SHA256()

    @staticmethod
    def generate_keypair():
        """Generuje parę kluczy ECDSA"""
        private_key = ec.generate_private_key(
            CryptoUtils.CURVE, default_backend()
        )
        return private_key, private_key.public_key()

    @staticmethod
    def get_public_key_bytes(public_key) -> bytes:
        """Serializuje klucz publiczny"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def get_private_key_bytes(private_key) -> bytes:
        """Serializuje klucz prywatny"""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def load_private_key(key_bytes: bytes):
        """Ładuje klucz prywatny"""
        return serialization.load_pem_private_key(
            key_bytes,
            password=None,
            backend=default_backend()
        )

    @staticmethod
    def load_public_key(key_bytes: bytes):
        """Ładuje klucz publiczny"""
        return serialization.load_pem_public_key(
            key_bytes,
            backend=default_backend()
        )

    @staticmethod
    def sign_message(private_key, message: bytes) -> bytes:
        """Podpisuje wiadomość"""
        return private_key.sign(
            message,
            ec.ECDSA(CryptoUtils.HASH_ALGO)
        )

    @staticmethod
    def verify_signature(
        public_key,
        message: bytes,
        signature: bytes
    ) -> bool:
        """Weryfikuje podpis"""
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(CryptoUtils.HASH_ALGO)
            )
            return True
        except Exception:
            return False

    @staticmethod
    def hash_data(data: bytes) -> str:
        """Hashuje dane SHA256"""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def derive_key_from_password(
        password: str,
        salt: bytes = None
    ) -> tuple:
        """Bierze klucz szyfrowania z hasła PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt

    @staticmethod
    def encrypt_private_key(private_key_bytes: bytes, password: str):
        """Szyfruje klucz prywatny hasłem"""
        key, salt = CryptoUtils.derive_key_from_password(password)
        cipher = Fernet(
            Fernet.generate_key() if not key else
            __import__('base64').urlsafe_b64encode(key)
        )

        # Alternatywa: użyj key jako część szyfrowania
        key_b64 = __import__('base64').urlsafe_b64encode(key)
        cipher = Fernet(key_b64)

        encrypted = cipher.encrypt(private_key_bytes)
        return encrypted, salt

    @staticmethod
    def decrypt_private_key(encrypted_key: bytes, password: str, salt: bytes):
        """Odszyfrowuje klucz prywatny"""
        key, _ = CryptoUtils.derive_key_from_password(password, salt)
        key_b64 = __import__('base64').urlsafe_b64encode(key)
        cipher = Fernet(key_b64)
        return cipher.decrypt(encrypted_key)