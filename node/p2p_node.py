import asyncio
import json
from aiohttp import web, ClientSession
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class P2PNode:
  """Węzeł sieci peer-to-peer"""

  def __init__(self, port: int = 5000, host: str = "localhost"):
    self.port = port
    self.host = host
    self.peers = {}
    self.node_id = None
    self.app = web.Application()
    self.setup_routes()
    self.session = None

  def setup_routes(self):
    """Konfiguruje endpointy HTTP"""
    self.app.router.add_post('/register', self.handle_register)
    self.app.router.add_post('/ping', self.handle_ping)
    self.app.router.add_get('/peers', self.handle_get_peers)
    self.app.router.add_post('/broadcast', self.handle_broadcast)

  async def handle_register(self, request):
    """Rejestruje nowy węzeł w sieci"""
    try:
      data = await request.json()
      peer_address = data.get('address')
      peer_port = data.get('port')
      peer_id = data.get('node_id')

      if not all([peer_address, peer_port, peer_id]):
        return web.json_response(
          {'status': 'error', "message": "Missing data"},
          status=400
        )

      peer_key = f"{peer_address}:{peer_port}"
      self.peers[peer_key] = {
        "address": peer_address,
        "port": peer_port,
        "node_id": peer_id,
        "registered_at": datetime.utcnow().isoformat()
      }

      logger.info(f"[+] Węzeł zarejestrowany: {peer_key}")

      return web.json_response({
        'status': 'success',
        'message': f"Node registered, total peers: {len(self.peers)}"
      })
    except Exception as e:
      return web.json_response(
        {'status': 'error', "message": str(e)},
        status=500
      )

  async def handle_ping(self, request):
    """Odpowiada na żądanie ping"""
    return web.json_response({
      'status': 'pong',
      'node_id': self.node_id,
      'timestamp': datetime.utcnow().isoformat()
    })

  async def handle_get_peers(self, request):
    """Zwraca listę zarejestrowanych węzłów"""
    return web.json_response({
      'peers': list(self.peers.values()),
      'total': len(self.peers)
    })

  async def handle_broadcast(self, request):
    """Odbiera i przetwarza wiadomości broadcast"""
    try:
      data = await request.json()
      msg_type = data.get('type')
      payload = data.get('payload')

      logger.info(f"[*] Broadcast wiadomość: {msg_type}")

      return web.json_response({"status": "received"})
    except Exception as e:
      return web.json_response(
        {'status': 'error', "message": str(e)},
        status=500
      )

  async def register_with_peer(self, peer_address: str, peer_port: int):
    """Rejestruje się w innym węźle"""
    try:
      if self.session is None:
        self.session = ClientSession()

      url = f"http://{peer_address}:{peer_port}/register"
      data = {
        "address": self.host,
        "port": self.port,
        "node_id": self.node_id
      }

      async with self.session.post(url, json=data) as resp:
        result = await resp.json()
        logger.info(
          f"[+] Zarejestrowaliśmy się w {peer_address}:"
          f"{peer_port}: {result}"
        )
        return result

    except Exception as e:
      logger.error (
          f"[-] Błąd rejestracji w {peer_address}:{peer_port}: {e}"
      )

  async def discover_peers(self):
    """Odkrywa inne węzły w sieci"""
    for peer_key, peer_info in list(self.peers.items()):
      try:
        if self.session is None:
          self.session = ClientSession()

        url = (
          f"http://{peer_info['address']}:"
          f"{peer_info['port']}/peers"
        )
        async with self.session.get(url, timeout=5) as resp:
          result = await resp.json()
          new_peers = result.get('peers', [])

          for peer in new_peers:
            key = f"{peer['address']}:{peer['port']}"
            if key not in self.peers:
              self.peers[key] = peer
              logger.info(f"[+] Odkryto nowy węzeł: {key}")

      except Exception as e:
        logger.warning(f"[-] Błąd odkrywania: {e}")

  async def broadcast_message(self, msg_type: str, payload: dict):
    """Wysyła wiadomość broadcast do wszystkich znanych węzłów"""

    if self.session is None:
      self.session = ClientSession()

    message = {"type": msg_type, "payload": payload}

    for peer_key, peer_info in list(self.peers.items()):
      try:
        url = (
          f"http://{peer_info['address']}:"
          f"{peer_info['port']}/broadcast"
        )
        async with self.session.post(
          url,
          json=message,
          timeout=5
        ) as resp:
          await resp.json()

      except Exception as e:
        logger.warning(
          f"[-] Błąd broadcast do {peer_key}: {e}"
        )

  async def start(self, node_id: str):
    """Uruchamia węzeł"""
    self.node_id = node_id
    logger.info(f"[*] Uruchamianie węzła {node_id} na {self.host}:"
                    f"{self.port}")
    runner = web.AppRunner(self.app)
    await runner.setup()
    site = web.TCPSite(runner, self.host, self.port)
    await site.start()

    logger.info(f"[+] Węzeł {node_id} uruchomiony!")

    try:
      while True:
        await asyncio.sleep(30)
        await self.discover_peers()
    except KeyboardInterrupt:
      await runner.cleanup()
      if self.session:
        await self.session.close()
