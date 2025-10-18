# 🪙 Cryptocurrency System - Blockchain Project

> **Kamień Milowy 1**: Sieć P2P i Bezpieczny Portfel

System kryptowaluty implementujący podstawowy zestaw funkcji w oparciu o technologię rejestru rozproszonego i łańcucha bloków (blockchain).

---

## 📋 Spis Treści

- [Struktura Projektu](#-struktura-projektu)
- [Funkcjonalności](#-funkcjonalności)
- [Architektura](#-architektura)
- [Technologie](#-technologie)
- [Instalacja](#-instalacja)
- [Użycie](#-użycie)
- [Moduły](#-moduły)

---

## 📁 Struktura Projektu

```
crypto/
├── config.py                 # Konfiguracja (ścieżki, porty)
├── main.py                   # Demo application
├── requirements.txt          # Python dependencies
├── README.md                 # Ten plik
│
├── crypto/                   # 🔐 Moduł kryptografii
│   └── crypto_utils.py       # ECDSA, PBKDF2, Fernet, SHA-256
│
├── wallet/                   # 💼 Moduł portfela
│   ├── key_manager.py        # Zarządzanie kluczami i tożsamościami
│   └── wallet.py             # API portfela
│
└── node/                     # 🌐 Moduł sieci P2P
    └── p2p_node.py           # Węzeł peer-to-peer (async HTTP)
```

## ✨ Funkcjonalności

### ✅ - KM1

- **Cyfrowe Tożsamości**: Generowanie par kluczy ECDSA (SECP256R1)
- **Bezpieczny Portfel**: Szyfrowanie kluczy prywatnych (PBKDF2 + Fernet AES)
- **Sieć P2P**: Asynchroniczna komunikacja węzłów przez HTTP
- **Rejestracja Węzłów**: Auto-discovery i propagacja informacji o peers
- **Broadcast**: Wysyłanie wiadomości do wszystkich węzłów w sieci
- **Podpisy Cyfrowe**: ECDSA do autoryzacji działań użytkownika

---

## 🏗️ Architektura

```
┌─────────────────────────────────────────────────────────┐
│                    USER LAYER                           │
│  ┌─────────────┐              ┌─────────────┐          │
│  │   Wallet    │              │   Wallet    │          │
│  │   (Alice)   │              │    (Bob)    │          │
│  └──────┬──────┘              └──────┬──────┘          │
└─────────┼─────────────────────────────┼─────────────────┘
          │                             │
          │ API: sign, get_address      │
          │                             │
┌─────────▼─────────────────────────────▼─────────────────┐
│                   NODE LAYER                            │
│  ┌──────────────┐              ┌──────────────┐        │
│  │  P2P Node    │◄────────────►│  P2P Node    │        │
│  │ (port 5001)  │   HTTP P2P   │ (port 5002)  │        │
│  │              │◄────────────►│              │        │
│  └──────┬───────┘              └──────┬───────┘        │
└─────────┼──────────────────────────────┼───────────────┘
          │                              │
          │ /register, /broadcast        │
          │ /ping, /peers                │
          └──────────────────────────────┘
```

---

## 🛠️ Technologie

| Warstwa | Technologia | Zastosowanie |
|---------|-------------|--------------|
| **Język** | Python 3.x | Core implementation |
| **Async** | `asyncio` | Równoczesna obsługa wielu połączeń P2P |
| **HTTP** | `aiohttp` | Asynchroniczny serwer i klient HTTP |
| **Kryptografia** | `cryptography` | ECDSA, PBKDF2, Fernet (AES) |
| **Hashing** | `hashlib` | SHA-256 dla adresów i weryfikacji |
| **Storage** | JSON | Przechowywanie zaszyfrowanych portfeli |

---

## 📦 Instalacja

### Wymagania

- Python 3.8+
- pip

### Krok po kroku

```bash
# 1. Klonuj repozytorium
git clone <repository-url>
cd crypto

# 2. Utwórz wirtualne środowisko
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# 3. Requirements
pip install -r requirements.txt
```

### Requirements (`requirements.txt`)

```
aiohttp>=3.9.0
cryptography>=41.0.0
```

---

## 🚀 Użycie

### Quick Start - Demo

```bash
python main.py
```

Uruchomi:
1. Tworzenie 2 portfeli (Alice i Bob)
2. Uruchomienie 2 węzłów P2P
3. Rejestracja węzłów między sobą
4. Test podpisywania i broadcast
---

## 📚 Moduły

### `crypto/crypto_utils.py`

Narzędzia kryptograficzne (warstwa najniższa).

**Główne funkcje:**
- `generate_keypair()` - Generuje parę kluczy ECDSA
- `sign_message(private_key, message)` - Podpisuje wiadomość
- `verify_signature(public_key, message, signature)` - Weryfikuje podpis
- `hash_data(data)` - SHA-256 hash
- `encrypt_private_key(key, password)` - Szyfruje klucz prywatny
- `decrypt_private_key(encrypted, password, salt)` - Odszyfrowuje klucz

---

### `wallet/key_manager.py`

Zarządzanie kluczami i tożsamościami użytkownika.

**Główne metody:**
- `create_new_identity(password)` - Tworzy nową tożsamość
- `load_identity(password)` - Ładuje istniejącą tożsamość
- `get_address()` - Zwraca adres portfela
- `sign_data(data)` - Podpisuje dane kluczem prywatnym

**Format pliku portfela** (`~/.wallet/<name>.json`):
```json
{
  "wallet_name": "alice",
  "address": "a1b2c3d4e5...",
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "encrypted_private_key": "gAAAABh...",
  "salt": "a1b2c3d4...",
  "identity_hash": "def456..."
}
```

---

### `wallet/wallet.py`

Publiczne API portfela (warstwa fasady).

**Główne metody:**
- `create_wallet(password)` - Tworzy nowy portfel
- `open_wallet(password)` - Otwiera istniejący portfel
- `get_address()` - Zwraca adres
- `sign_transaction(tx_data)` - Podpisuje transakcję
- `get_public_key()` - Zwraca klucz publiczny

---

### `node/p2p_node.py`

Węzeł sieci peer-to-peer.

**Endpointy HTTP:**
- `POST /register` - Rejestracja nowego węzła
- `POST /ping` - Health check
- `GET /peers` - Lista znanych węzłów
- `POST /broadcast` - Odbieranie wiadomości broadcast

**Główne metody:**
- `start(node_id)` - Uruchamia węzeł
- `register_with_peer(address, port)` - Rejestruje się w innym węźle
- `discover_peers()` - Odkrywa nowe węzły (co 30s)
- `broadcast_message(type, payload)` - Wysyła wiadomość do wszystkich