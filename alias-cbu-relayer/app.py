from dotenv import load_dotenv
load_dotenv()

import os, re
from typing import Optional, Dict, Tuple

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ==== Routers opcionales (no deben romper import-time) ====
rpc_router = est_router = None
try:
    from api.rpc_proxy import router as _rpc_router
    rpc_router = _rpc_router
except Exception as e:
    print("[warn] rpc_proxy no disponible:", e)

try:
    from api.estimate_v3 import router as _est_router
    est_router = _est_router
except Exception as e:
    print("[warn] estimate_v3 no disponible:", e)

# ==== CARGA ENV – NO rompas en import-time ====
def _get_env_hex(name: str, default: str = "0x0") -> int:
    """Devuelve int interpretando hex/decimal; tolerante a vacíos."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return int(default, 16)
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw)  # decimal
    except Exception:
        return int(default, 16)

def _get_env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()

RPC_URL = _get_env_str("RPC_URL", "")
ALIAS_CONTRACT = _get_env_hex("ALIAS_CONTRACT", "0x0")
AIC_TOKEN = _get_env_hex("AIC_TOKEN", "0x0")
RELAYER_ACCOUNT_ADDRESS = _get_env_hex("RELAYER_ACCOUNT_ADDRESS", "0x0")
RELAYER_PRIVATE_KEY = _get_env_hex("RELAYER_PRIVATE_KEY", "0x0")
FEE_AIC_WEI = int(os.getenv("FEE_AIC_WEI", "0") or "0")
CHAIN_ID = _get_env_hex("CHAIN_ID", "0x1")  # por defecto 0x1

# ==== App FastAPI ====
app = FastAPI(title="AliasCBU Relayer (Gasless AIC)")
templates = Jinja2Templates(directory="templates")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

if rpc_router:
    app.include_router(rpc_router, prefix="/api")
if est_router:
    app.include_router(est_router, prefix="/api")

# ==== Validaciones de entorno por endpoint ====
def _missing_envs_for_tx():
    missing = []
    if not RPC_URL: missing.append("RPC_URL")
    if not ALIAS_CONTRACT: missing.append("ALIAS_CONTRACT")
    if not AIC_TOKEN: missing.append("AIC_TOKEN")
    if not RELAYER_ACCOUNT_ADDRESS: missing.append("RELAYER_ACCOUNT_ADDRESS")
    if not RELAYER_PRIVATE_KEY: missing.append("RELAYER_PRIVATE_KEY")
    if not FEE_AIC_WEI: missing.append("FEE_AIC_WEI")
    if not CHAIN_ID: missing.append("CHAIN_ID")
    return missing

# ==== Lazy init de starknet_py ====
_client = None
_relayer = None
def _get_client_and_relayer():
    global _client, _relayer
    if _client and _relayer:
        return _client, _relayer

    missing = _missing_envs_for_tx()
    if missing:
        raise HTTPException(500, f"Faltan variables de entorno: {', '.join(missing)}")

    try:
        from starknet_py.net.full_node_client import FullNodeClient
        from starknet_py.net.account.account import Account
        from starknet_py.net.signer.stark_curve_signer import KeyPair
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    _client = FullNodeClient(node_url=RPC_URL)
    _relayer = Account(
        client=_client,
        address=RELAYER_ACCOUNT_ADDRESS,
        key_pair=KeyPair.from_private_key(RELAYER_PRIVATE_KEY),
        chain=CHAIN_ID,
    )
    return _client, _relayer

# ==== Utilidades alias ====
ALIAS_REGEX = re.compile(r"^[a-z0-9.]{4,20}$")
NONCES: dict[str, int] = {}

# índice en memoria
ALIAS_INDEX: Dict[str, Tuple[str, str]] = {}  # alias_key_hex -> (user_address_hex, alias_str)
ADDR_INDEX: Dict[str, Tuple[str, str]] = {}   # address_hex -> (alias_key_hex, alias_str)

def normalize_alias(s: str) -> str:
    alias = s.strip().lower()
    if not ALIAS_REGEX.match(alias):
        raise ValueError("Alias invalido: solo letras, numeros y puntos; longitud 4-20.")
    return alias

FIELD_P = (2**251) + (17 * 2**192) + 1

def _keccak_bytes(msg: bytes) -> bytes:
    try:
        from eth_hash.auto import keccak as keccak256
    except Exception as e:
        raise HTTPException(500, f"eth_hash no disponible: {e}")
    return keccak256(msg)

def alias_key(alias: str) -> int:
    h_bytes = _keccak_bytes(alias.encode("utf-8"))
    return int.from_bytes(h_bytes, "big") % FIELD_P

def next_nonce(addr_hex: str) -> int:
    n = NONCES.get(addr_hex.lower(), 0) + 1
    NONCES[addr_hex.lower()] = n
    return n

def meta_message(alias_key_int: int, length: int, user_addr: int, nonce: int) -> str:
    return (
        f"AliasCBU|register|alias_key:{hex(alias_key_int)}|"
        f"len:{length}|user:{hex(user_addr)}|nonce:{nonce}|chain:{hex(CHAIN_ID)}"
    )

# ==== modelos ====
class PrepareIn(BaseModel):
    alias: str
    user_address: str

class SubmitIn(BaseModel):
    user_address: str
    alias: str
    signature_r: Optional[str] = None
    signature_s: Optional[str] = None
    signature: Optional[list[str]] = None
    nonce: int

# ==== rutas ====
@app.get("/", response_class=HTMLResponse)
async def index(req: Request):
    return templates.TemplateResponse("index.html", {"request": req})

@app.get("/api/health")
async def health():
    return {"ok": True}

@app.get("/api/config")
async def config():
    """
    Devuelve config sin romper si faltan envs; indica qué falta.
    """
    missing = []
    if not RPC_URL: missing.append("RPC_URL")
    if not ALIAS_CONTRACT: missing.append("ALIAS_CONTRACT")
    if not AIC_TOKEN: missing.append("AIC_TOKEN")
    if not RELAYER_ACCOUNT_ADDRESS: missing.append("RELAYER_ACCOUNT_ADDRESS")
    if not RELAYER_PRIVATE_KEY: missing.append("RELAYER_PRIVATE_KEY")
    if not FEE_AIC_WEI: missing.append("FEE_AIC_WEI")
    if not CHAIN_ID: missing.append("CHAIN_ID")

    return {
        "relayer_address": hex(RELAYER_ACCOUNT_ADDRESS),
        "aic_token": hex(AIC_TOKEN),
        "alias_contract": hex(ALIAS_CONTRACT),
        "chain_id": hex(CHAIN_ID),
        "fee_aic_wei": str(FEE_AIC_WEI),
        "missing_envs": missing,   # <- para debug en Vercel
    }

@app.post("/api/prepare")
async def prepare(data: PrepareIn):
    try:
        alias_norm = normalize_alias(data.alias)
    except ValueError as e:
        raise HTTPException(400, str(e))

    k = alias_key(alias_norm)
    ln = len(alias_norm)

    try:
        user_int = int(data.user_address, 16)
    except ValueError:
        raise HTTPException(400, "user_address inválido (hex)")

    nonce = next_nonce(data.user_address)

    msg = meta_message(k, ln, user_int, nonce)
    return {
        "alias_normalized": alias_norm,
        "alias_key": hex(k),
        "len": ln,
        "nonce": nonce,
        "message": msg,
        "fee_aic_wei": str(FEE_AIC_WEI),
        "aic_token": hex(AIC_TOKEN),
    }

@app.post("/api/submit")
async def submit(data: SubmitIn):
    # Validaciones básicas
    try:
        alias_norm = normalize_alias(data.alias)
    except ValueError as e:
        raise HTTPException(400, str(e))

    k = alias_key(alias_norm)
    ln = len(alias_norm)

    try:
        user = int(data.user_address, 16)
    except ValueError:
        raise HTTPException(400, "user_address inválido (hex)")

    if NONCES.get(data.user_address.lower(), 0) < data.nonce:
        raise HTTPException(400, "Nonce invalido (prepare faltante)")

    # Firma (passthrough)
    if data.signature and len(data.signature) >= 2:
        r_hex, s_hex = data.signature[0], data.signature[1]
    else:
        if not (data.signature_r and data.signature_s):
            raise HTTPException(400, "Falta firma (signature o r/s)")
        r_hex, s_hex = data.signature_r, data.signature_s

    try:
        int(r_hex, 16); int(s_hex, 16)
    except Exception:
        raise HTTPException(400, "Firma inválida (hex)")

    # --- Construcción de la tx ---
    client, relayer = _get_client_and_relayer()
    try:
        from starknet_py.net.client_models import Call
        from starknet_py.hash.selector import get_selector_from_name
        try:
            from starknet_py.net.client_models import BlockId, Tag
            block_id_pending = BlockId(tag=Tag.PENDING)
        except Exception:
            block_id_pending = "pending"
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    erc20_transfer_from = Call(
        to_addr=AIC_TOKEN,
        selector=get_selector_from_name("transfer_from"),
        calldata=[user, relayer.address, FEE_AIC_WEI, 0]
    )
    alias_register = Call(
        to_addr=ALIAS_CONTRACT,
        selector=get_selector_from_name("admin_register_for"),
        calldata=[k, ln, user]
    )

    # ===== Estimar fee con fallback =====
    SAFE_FEE = int(5e17)  # 0.5 STRK
    try:
        if hasattr(relayer, "_estimate_fee"):
            est = await relayer._estimate_fee(
                calls=[erc20_transfer_from, alias_register],
                block_id=block_id_pending,
                version=3,
                nonce=None
            )
            fee_value = int(est.overall_fee * 13 // 10)
        else:
            raise Exception("_estimate_fee no disponible")
    except Exception as e:
        print("[warn] estimate failed, usando fee fijo:", e)
        fee_value = SAFE_FEE

    
    # ===== Ejecutar con compatibilidad total (v0.27+ incluido) =====
    try:
        import inspect
        sig = inspect.signature(relayer.execute_v3)
        kwargs = {}

        if "auto_estimate" in sig.parameters:
            # Versión moderna: usar auto_estimate=True
            kwargs["auto_estimate"] = True
        elif "estimate_fee_mode" in sig.parameters:
            # Alternativa de 0.27.x+
            kwargs["estimate_fee_mode"] = "auto"
        else:
            print("[warn] execute_v3 sin auto_estimate, intentando vacío")

        resp = await relayer.execute_v3(
            calls=[erc20_transfer_from, alias_register],
            **kwargs
        )
        tx_hash = getattr(resp, "transaction_hash", resp)
    except Exception as e:
        raise HTTPException(500, f"Error enviando tx: {e}")


    # Índice en memoria
    alias_key_hex = hex(k)
    addr_hex = hex(user)
    ALIAS_INDEX[alias_key_hex] = (addr_hex, alias_norm)
    ADDR_INDEX[addr_hex] = (alias_key_hex, alias_norm)

    return {"ok": True, "tx_hash": hex(tx_hash), "relayer": hex(relayer.address)}

async def submit(data: SubmitIn):
    # Validaciones básicas
    try:
        alias_norm = normalize_alias(data.alias)
    except ValueError as e:
        raise HTTPException(400, str(e))

    k = alias_key(alias_norm)
    ln = len(alias_norm)

    try:
        user = int(data.user_address, 16)
    except ValueError:
        raise HTTPException(400, "user_address inválido (hex)")

    if NONCES.get(data.user_address.lower(), 0) < data.nonce:
        raise HTTPException(400, "Nonce invalido (prepare faltante)")

    # Firma (passthrough)
    if data.signature and len(data.signature) >= 2:
        r_hex, s_hex = data.signature[0], data.signature[1]
    else:
        if not (data.signature_r and data.signature_s):
            raise HTTPException(400, "Falta firma (signature o r/s)")
        r_hex, s_hex = data.signature_r, data.signature_s

    try:
        int(r_hex, 16); int(s_hex, 16)
    except Exception:
        raise HTTPException(400, "Firma inválida (hex)")

    client, relayer = _get_client_and_relayer()
    try:
        from starknet_py.net.client_models import Call
        from starknet_py.hash.selector import get_selector_from_name
        try:
            from starknet_py.net.client_models import BlockId, Tag
            block_id_pending = BlockId(tag=Tag.PENDING)
        except Exception:
            # Compatibilidad con versiones viejas
            block_id_pending = "pending"
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    erc20_transfer_from = Call(
        to_addr=AIC_TOKEN,
        selector=get_selector_from_name("transfer_from"),
        calldata=[user, relayer.address, FEE_AIC_WEI, 0]
    )
    alias_register = Call(
        to_addr=ALIAS_CONTRACT,
        selector=get_selector_from_name("admin_register_for"),
        calldata=[k, ln, user]
    )

    # ===== Estimar con 'pending' y fallback a fee fijo =====
    SAFE_MAX_FEE_FALLBACK = int(5e17)  # 0.5 STRK (ajustá si hace falta)
    try:
        # versiones viejas pueden no tener _estimate_fee, por eso se captura
        if hasattr(relayer, "_estimate_fee"):
            est = await relayer._estimate_fee(
                calls=[erc20_transfer_from, alias_register],
                block_id=block_id_pending,
                version=3,
                nonce=None
            )
            max_fee = int(est.overall_fee * 13 // 10)
        else:
            raise Exception("_estimate_fee no disponible")
    except Exception as e:
        print("[warn] estimate failed, using SAFE_MAX_FEE fallback:", e)
        max_fee = SAFE_MAX_FEE_FALLBACK

    try:
        resp = await relayer.execute_v3(
            calls=[erc20_transfer_from, alias_register],
            auto_estimate=False,
            max_fee=max_fee
        )
        tx_hash = resp.transaction_hash
    except Exception as e:
        raise HTTPException(500, f"Error enviando tx: {e}")

    alias_key_hex = hex(k)
    addr_hex = hex(user)
    ALIAS_INDEX[alias_key_hex] = (addr_hex, alias_norm)
    ADDR_INDEX[addr_hex] = (alias_key_hex, alias_norm)

    return {"ok": True, "tx_hash": hex(tx_hash), "relayer": hex(relayer.address)}

    # Validaciones básicas
    try:
        alias_norm = normalize_alias(data.alias)
    except ValueError as e:
        raise HTTPException(400, str(e))

    k = alias_key(alias_norm)
    ln = len(alias_norm)

    try:
        user = int(data.user_address, 16)
    except ValueError:
        raise HTTPException(400, "user_address inválido (hex)")

    if NONCES.get(data.user_address.lower(), 0) < data.nonce:
        raise HTTPException(400, "Nonce invalido (prepare faltante)")

    # Firma (passthrough)
    if data.signature and len(data.signature) >= 2:
        r_hex, s_hex = data.signature[0], data.signature[1]
    else:
        if not (data.signature_r and data.signature_s):
            raise HTTPException(400, "Falta firma (signature o r/s)")
        r_hex, s_hex = data.signature_r, data.signature_s

    try:
        int(r_hex, 16); int(s_hex, 16)
    except Exception:
        raise HTTPException(400, "Firma inválida (hex)")

    # --- Enviar multicall ---
    # Lazy import + construcción de cliente/relayer recién ahora
    client, relayer = _get_client_and_relayer()
    try:
        from starknet_py.net.client_models import Call, Tag, BlockId
        from starknet_py.hash.selector import get_selector_from_name
        from starknet_py.net.client_errors import ClientError
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    erc20_transfer_from = Call(
        to_addr=AIC_TOKEN,
        selector=get_selector_from_name("transfer_from"),
        calldata=[user, relayer.address, FEE_AIC_WEI, 0]  # u256: (low, high)
    )
    alias_register = Call(
        to_addr=ALIAS_CONTRACT,
        selector=get_selector_from_name("admin_register_for"),
        calldata=[k, ln, user]   # <— pasa el 'who'
    )

        # ===== Estimar con 'pending' y fallback a fee fijo =====
    SAFE_MAX_FEE_FALLBACK = int(5e17)  # 0.5 STRK
    try:
        if hasattr(relayer, "_estimate_fee"):
            est = await relayer._estimate_fee(
                calls=[erc20_transfer_from, alias_register],
                block_id=block_id_pending,
                version=3,
                nonce=None
            )
            max_fee = int(est.overall_fee * 13 // 10)
        else:
            raise Exception("_estimate_fee no disponible")
    except Exception as e:
        print("[warn] estimate failed, using SAFE_MAX_FEE fallback:", e)
        max_fee = SAFE_MAX_FEE_FALLBACK

    # ===== Ejecutar la transacción (compatibilidad entre versiones) =====
    try:
        # versiones nuevas aceptan 'max_fee', viejas solo 'fee'
        kwargs = {"auto_estimate": False}
        try:
            relayer.execute_v3.__signature__  # prueba de introspección
            # usamos 'fee' por compatibilidad si no acepta 'max_fee'
            import inspect
            if "max_fee" in inspect.signature(relayer.execute_v3).parameters:
                kwargs["max_fee"] = max_fee
            else:
                kwargs["fee"] = max_fee
        except Exception:
            kwargs["fee"] = max_fee

        resp = await relayer.execute_v3(
            calls=[erc20_transfer_from, alias_register],
            **kwargs
        )
        tx_hash = getattr(resp, "transaction_hash", resp)
    except Exception as e:
        raise HTTPException(500, f"Error enviando tx: {e}")


    # Índice en memoria
    alias_key_hex = hex(k)
    addr_hex = hex(user)
    ALIAS_INDEX[alias_key_hex] = (addr_hex, alias_norm)
    ADDR_INDEX[addr_hex] = (alias_key_hex, alias_norm)

    return {"ok": True, "tx_hash": hex(tx_hash), "relayer": hex(relayer.address)}

# ===== resolvers =====
@app.get("/api/resolve_alias")
async def resolve_alias(alias: str):
    alias_norm = normalize_alias(alias)
    k = alias_key(alias_norm)

    client, _ = _get_client_and_relayer()
    try:
        from starknet_py.net.client_models import Call
        from starknet_py.hash.selector import get_selector_from_name

        # 👇 starknet-py 0.28.0 usa block_number="latest" (NO block_id)
        res = await client.call_contract(
            call=Call(
                to_addr=ALIAS_CONTRACT,
                selector=get_selector_from_name("addr_of_alias"),
                calldata=[k],
            ),
            block_number="latest"
        )

        onchain_addr = hex(res[0])
    except Exception as e:
        raise HTTPException(500, f"Error on-chain: {e}")

    mem = ALIAS_INDEX.get(hex(k))
    return {
        "alias": alias_norm,
        "alias_key": hex(k),
        "onchain_address": onchain_addr,
        "memory_index": {"address": mem[0], "alias": mem[1]} if mem else None,
    }


@app.get("/api/resolve_address")
async def resolve_address(address: str):
    try:
        addr_int = int(address, 16)
    except ValueError:
        raise HTTPException(400, "address inválido (hex)")

    client, _ = _get_client_and_relayer()
    try:
        from starknet_py.net.client_models import Call
        from starknet_py.hash.selector import get_selector_from_name

        # 👇 igual: block_number="latest"
        res = await client.call_contract(
            call=Call(
                to_addr=ALIAS_CONTRACT,
                selector=get_selector_from_name("alias_key_of_addr"),
                calldata=[addr_int],
            ),
            block_number="latest"
        )

        onchain_key = hex(res[0])
    except Exception as e:
        raise HTTPException(500, f"Error on-chain: {e}")

    mem = ADDR_INDEX.get(hex(addr_int))
    return {
        "address": hex(addr_int),
        "onchain_alias_key": onchain_key,
        "memory_index": {"alias_key": mem[0], "alias": mem[1]} if mem else None,
    }

@app.get("/api/list")
async def list_local():
    items = [{"alias": alias, "alias_key": k, "address": addr} for k, (addr, alias) in ALIAS_INDEX.items()]
    items.sort(key=lambda x: x["alias"])
    return {"count": len(items), "items": items}

# ============================================================
# FAUCET (envía AIC a la billetera conectada, solo para pruebas)
# ============================================================
@app.post("/api/faucet")
async def faucet(req: Request):
    """
    Envía una pequeña cantidad de AIC (ej: 10 AIC) al address indicado.
    Usa el relayer como cuenta emisora (debe tener saldo AIC).
    """
    try:
        data = await req.json()
        dest_hex = data.get("address", "")
        if not dest_hex or not dest_hex.startswith("0x"):
            raise HTTPException(400, "Falta o es inválida la dirección destino (address)")

        dest_int = int(dest_hex, 16)
    except Exception as e:
        raise HTTPException(400, f"JSON inválido: {e}")

    client, relayer = _get_client_and_relayer()
    try:
        from starknet_py.net.client_models import Call
        from starknet_py.hash.selector import get_selector_from_name
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    # ---- definir monto coherente ----
    # 10 AIC * 10^18 (asumiendo 18 decimales)
    FAUCET_AMOUNT = 1000 * (10**18)
    low = FAUCET_AMOUNT & ((1 << 128) - 1)
    high = FAUCET_AMOUNT >> 128

    faucet_call = Call(
        to_addr=AIC_TOKEN,
        selector=get_selector_from_name("transfer"),
        calldata=[dest_int, low, high],
    )

    try:
        # versión moderna con auto_estimate=True
        resp = await relayer.execute_v3(
            calls=[faucet_call],
            auto_estimate=True,
        )
        tx_hash = getattr(resp, "transaction_hash", resp)
        return {
            "ok": True,
            "tx_hash": hex(tx_hash),
            "relayer": hex(relayer.address),
            "to": dest_hex,
            "amount_aic": str(FAUCET_AMOUNT),
        }
    except Exception as e:
        raise HTTPException(500, f"Error enviando faucet: {e}")

