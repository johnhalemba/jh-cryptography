class Wallet:

    def __init__(self, wallet_name: str):
        self.name = wallet_name

    def create_wallet(self, password: str):
        pass

    def open_wallet(self, password: str):
        pass

    def get_address(self) -> str:
        pass

    def sign_transaction(self, tx_data: bytes) -> str:
        pass

    def get_public_key(self) -> str:
        pass