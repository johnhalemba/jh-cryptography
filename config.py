import os

WALLET_DIR = os.path.expanduser("~/.wallet")
os.makedirs(WALLET_DIR, exist_ok=True)

DEFAULT_NODE_PORT = 5000
PEERS_BROADCAST_INTERVAL = 30  #seconds