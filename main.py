import asyncio
from wallet.wallet import Wallet
from node.p2p_node import P2PNode

async def main():
  """Demo: Tworzenie portfeli i węzłów"""

  print("=" * 60)
  print("SIEĆ KRYPTOWALUTY - KM1: P2P i Portfel")
  print("=" * 60)

  # --- PORTFELE ---
  print("\n[KROK 1] Tworzenie portfeli\n")

  # Portfel 1
  wallet1 = Wallet("alice")
  wallet1.create_wallet(password="alice_haslo_123")
  alice_address = wallet1.get_address()

  # Portfel 2
  wallet2 = Wallet("bob")
  wallet2.create_wallet(password="bob_haslo_123")
  bob_address = wallet2.get_address()

  print(f"\nAlice adres: {alice_address}")
  print(f"Bob adres: {bob_address}")

  # --- WĘZŁY ---
  print("\n[KROK 2] Uruchamianie węzłów P2P\n")

  # Węzeł 1 (Alice)
  node1 = P2PNode(port=5001, host="localhost")
  task1 = asyncio.create_task(node1.start("node_alice"))

  # Węzeł 2 (Bob)
  node2 = P2PNode(port=5002, host="localhost")
  task2 = asyncio.create_task(node2.start("node_bob"))

  # Daj chwilę na start
  await asyncio.sleep(1)

  # --- REJESTRACJA ---
  print("\n[KROK 3] Rejestracja węzłów\n")

  # Bob się rejestruje w Alice
  await node1.register_with_peer("localhost", 5002)

  # Alice się rejestruje w Bob
  await node2.register_with_peer("localhost", 5001)

  await asyncio.sleep(1)

  # --- TESTOWANIE ---
  print("\n[KROK 4] Test komunikacji\n")

  # Podpisanie wiadomości
  wallet1.open_wallet(password="alice_haslo_123")
  test_data = b"Test message from Alice"
  signature = wallet1.sign_transaction(test_data)
  print(f"[+] Alice podpisała wiadomość")
  print(f"    Sygnatura: {signature[:32]}...")

  # Broadcast
  await node1.broadcast_message("test", {"data": "Hello from Alice"})
  print(f"[+] Alice wysłała broadcast")

  await asyncio.sleep(2)

  # Status
  print(f"\n[STAN SIECI]")
  print(f"Węzły znane Node1: {len(node1.peers)}")
  print(f"Węzły znane Node2: {len(node2.peers)}")

  # Utrzymuj węzły działające
  await asyncio.gather(task1, task2)

if __name__ == "__main__":
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    print("\n[*] Zamykanie...")