from wallet.key_manager import KeyManager

class Wallet:
    """Cyfrowy portfel użytkownika"""

    def __init__(self, wallet_name: str):
        self.name = wallet_name
        self.key_manager = KeyManager(wallet_name)

    def create_wallet(self, password: str):
        """Tworzy nowy portfel"""
        self.key_manager.create_new_identity(password)

    def open_wallet(self, password: str):
        """Otwiera istniejący portfel"""
        self.key_manager.load_identity(password)

    def get_address(self) -> str:
        """Zwraca adres portfela"""
        return self.key_manager.get_address()

    def sign_transaction(self, tx_data: bytes) -> str:
        """Podpisuje transakcję"""
        return self.key_manager.sign_data(tx_data)

    def get_public_key(self) -> str:
        """Zwraca klucz publiczny"""
        return self.key_manager.get_public_key_hex()