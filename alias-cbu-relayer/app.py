from dotenv import load_dotenv
load_dotenv()

import os, re
from typing import Optional, Dict

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

CHAIN_ID_ETHEREUM_FELT = int.from_bytes(b"ETH", "big")
CHAIN_ID_BITCOIN_FELT = int.from_bytes(b"BTC", "big")
CHAIN_LABEL_TO_FELT = {
    "ETH": CHAIN_ID_ETHEREUM_FELT,
    "BTC": CHAIN_ID_BITCOIN_FELT,
}
FELT_TO_CHAIN_LABEL = {value: key for key, value in CHAIN_LABEL_TO_FELT.items()}

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
NONCES: Dict[str, int] = {}

# Índice en memoria enriquecido
ALIAS_INDEX: Dict[str, Dict[str, str]] = {}
ADDR_INDEX: Dict[str, Dict[str, str]] = {}
EXTERNAL_INDEX: Dict[str, Dict[str, Dict[str, str]]] = {"ETH": {}, "BTC": {}}

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


def encode_external_address(value: Optional[str], *, label: str) -> int:
    if not value:
        return 0

    raw = value.strip()
    if not raw:
        return 0

    if raw.startswith("0x") or raw.startswith("0X"):
        try:
            return int(raw, 16) % FIELD_P
        except Exception:
            raise HTTPException(400, f"{label} inválido (hex)")

    try:
        data = raw.encode("ascii")
    except Exception:
        raise HTTPException(400, f"{label} debe ser ASCII o hex 0x…")

    as_int = int.from_bytes(data, "big")
    if as_int >= FIELD_P:
        raise HTTPException(400, f"{label} demasiado largo; convertí a hex o hash")
    return as_int


def felt_to_ascii_str(value: int) -> Optional[str]:
    if value == 0:
        return None
    length = max(1, (value.bit_length() + 7) // 8)
    try:
        raw = value.to_bytes(length, "big")
    except OverflowError:
        return None
    try:
        text = raw.decode("ascii")
    except Exception:
        return None
    text = text.strip("\x00")
    return text or None


def format_external_value(value: int) -> Dict[str, Optional[str]]:
    ascii_val = felt_to_ascii_str(value)
    return {
        "felt_hex": hex(value),
        "as_ascii": ascii_val,
    }


def parse_chain_identifier(raw: str) -> int:
    key = (raw or "").strip()
    if not key:
        raise HTTPException(400, "Falta chain")

    upper = key.upper()
    if upper in CHAIN_LABEL_TO_FELT:
        return CHAIN_LABEL_TO_FELT[upper]

    try:
        return int(key, 16)
    except Exception:
        raise HTTPException(400, f"chain inválido: {raw}")

def next_nonce(addr_hex: str) -> int:
    n = NONCES.get(addr_hex.lower(), 0) + 1
    NONCES[addr_hex.lower()] = n
    return n

def meta_message(
    alias_key_int: int,
    length: int,
    user_addr: int,
    nonce: int,
    eth_address: int,
    btc_address: int,
) -> str:
    return (
        f"AliasCBU|register|alias_key:{hex(alias_key_int)}|"
        f"len:{length}|user:{hex(user_addr)}|nonce:{nonce}|chain:{hex(CHAIN_ID)}|"
        f"eth:{hex(eth_address)}|btc:{hex(btc_address)}"
    )


def _flatten_exception_message(exc: Exception) -> str:
    """Concatena mensajes de excepciones anidadas en una sola línea legible."""

    parts = []
    seen: set[int] = set()
    current: Optional[BaseException] = exc

    while current and id(current) not in seen:
        seen.add(id(current))

        text = getattr(current, "message", None)
        if not text:
            args = getattr(current, "args", None)
            if args:
                text = " ".join(str(arg) for arg in args if arg)
        if not text:
            text = str(current)

        if text:
            parts.append(str(text))

        current = getattr(current, "__cause__", None) or getattr(current, "__context__", None)

    if not parts:
        return "Error desconocido"

    collapsed = " | ".join(parts)
    collapsed = re.sub(r"\s+", " ", collapsed).strip()
    return collapsed[:800] + ("…" if len(collapsed) > 800 else "")


def _classify_relayer_error(exc: Exception) -> tuple[int, str]:
    raw = _flatten_exception_message(exc)
    upper = raw.upper()

    if "ALIAS_TAKEN" in upper:
        return 409, "Alias ya registrado on-chain (ALIAS_TAKEN)."
    if "ETH_ADDR_IN_USE" in upper:
        return 409, "La dirección ETH ya está asociada a otro alias (ETH_ADDR_IN_USE)."
    if "BTC_ADDR_IN_USE" in upper:
        return 409, "La dirección externa ya está asociada a otro alias (BTC_ADDR_IN_USE)."
    if "INSUFFICIENT" in upper and "BALANCE" in upper:
        return 400, "Fondos insuficientes o approve faltante para el token AIC."
    if "TRANSFER_FROM" in upper and "FAILED" in upper:
        return 400, "transfer_from del token AIC falló (approve/balance)."

    return 500, f"Error enviando transacción: {raw}"

# ==== modelos ====
class PrepareIn(BaseModel):
    alias: str
    user_address: str
    eth_address: Optional[str] = None
    btc_address: Optional[str] = None


class SubmitIn(BaseModel):
    user_address: str
    alias: str
    eth_address: Optional[str] = None
    btc_address: Optional[str] = None
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
        "external_chain_ids": {
            "ETH": hex(CHAIN_ID_ETHEREUM_FELT),
            "BTC": hex(CHAIN_ID_BITCOIN_FELT),
        },
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

    eth_int = encode_external_address(data.eth_address, label="eth_address")
    btc_int = encode_external_address(data.btc_address, label="btc_address")

    msg = meta_message(k, ln, user_int, nonce, eth_int, btc_int)
    return {
        "alias_normalized": alias_norm,
        "alias_key": hex(k),
        "len": ln,
        "nonce": nonce,
        "message": msg,
        "fee_aic_wei": str(FEE_AIC_WEI),
        "aic_token": hex(AIC_TOKEN),
        "eth_address_felt": hex(eth_int),
        "btc_address_felt": hex(btc_int),
        "eth_address_ascii": felt_to_ascii_str(eth_int),
        "btc_address_ascii": felt_to_ascii_str(btc_int),
    }


@app.post("/api/submit")
async def submit(data: SubmitIn):
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

    addr_key = data.user_address.lower()
    if data.nonce <= 0:
        raise HTTPException(400, "Nonce inválido")

    stored_nonce = NONCES.get(addr_key)
    if stored_nonce is None:
        # Entorno serverless puede inicializar un nuevo worker entre prepare y submit.
        # Persistimos el nonce recibido para no exigir preparar de nuevo cuando
        # el estado en memoria se perdió.
        NONCES[addr_key] = data.nonce
    elif data.nonce > stored_nonce + 1:
        raise HTTPException(400, "Nonce fuera de rango; volvé a preparar la firma")
    elif data.nonce == stored_nonce + 1:
        NONCES[addr_key] = data.nonce

    if data.signature and len(data.signature) >= 2:
        r_hex, s_hex = data.signature[0], data.signature[1]
    else:
        if not (data.signature_r and data.signature_s):
            raise HTTPException(400, "Falta firma (signature o r/s)")
        r_hex, s_hex = data.signature_r, data.signature_s

    try:
        int(r_hex, 16)
        int(s_hex, 16)
    except Exception:
        raise HTTPException(400, "Firma inválida (hex)")

    eth_int = encode_external_address(data.eth_address, label="eth_address")
    btc_int = encode_external_address(data.btc_address, label="btc_address")

    client, relayer = _get_client_and_relayer()
    try:
        from starknet_py.net.client_models import (
            Call,
            ResourceBounds,
            ResourceBoundsMapping,
        )
        from starknet_py.hash.selector import get_selector_from_name
        try:
            from starknet_py.net.client_models import BlockId, Tag
            block_id_pending = BlockId(tag=Tag.PENDING)
        except Exception:
            block_id_pending = "pending"
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    SAFE_FEE = int(5e17)

    async def _estimate_fee_components(calls: list[Call]):
        estimated_bounds: Optional[ResourceBoundsMapping] = None
        fee_value = SAFE_FEE

        try:
            if hasattr(relayer, "_estimate_fee"):
                est = await relayer._estimate_fee(
                    calls=calls,
                    block_id=block_id_pending,
                    version=3,
                    nonce=None,
                )
                fee_value = int(est.overall_fee * 13 // 10)
                try:
                    estimated_bounds = est.to_resource_bounds(
                        amount_multiplier=1.3,
                        unit_price_multiplier=1.3,
                    )
                except Exception as conv_err:
                    print("[warn] no se pudo convertir fee estimate a resource_bounds:", conv_err)
                    estimated_bounds = None
            else:
                raise Exception("_estimate_fee no disponible")
        except Exception as e:
            print("[warn] estimate failed, usando fee fijo:", e)

        if fee_value <= 0:
            fee_value = SAFE_FEE

        return fee_value, estimated_bounds

    async def _execute_with_calls(calls: list[Call], fee_value: int, estimated_bounds: Optional[ResourceBoundsMapping]):
        import inspect

        sig = inspect.signature(relayer.execute_v3)
        params = sig.parameters

        attempts = []

        primary_kwargs = {"calls": calls}
        if "auto_estimate" in params:
            primary_kwargs["auto_estimate"] = True
        elif "estimate_fee_mode" in params:
            primary_kwargs["estimate_fee_mode"] = "auto"
        attempts.append(primary_kwargs)

        fallback_kwargs = {"calls": calls}
        manual_fee_fields = False

        if "resource_bounds" in params and estimated_bounds is not None:
            fallback_kwargs["resource_bounds"] = estimated_bounds
            manual_fee_fields = True

        if "max_fee" in params:
            fallback_kwargs["max_fee"] = fee_value
            manual_fee_fields = True
        elif "fee" in params:
            fallback_kwargs["fee"] = fee_value
            manual_fee_fields = True

        if manual_fee_fields:
            if "auto_estimate" in params:
                fallback_kwargs["auto_estimate"] = False
            attempts.append(fallback_kwargs)

        last_error: Optional[Exception] = None
        for kwargs in attempts:
            try:
                resp = await relayer.execute_v3(**kwargs)
                return resp, None
            except Exception as err:
                last_error = err

        return None, last_error

    attempt_variants = []
    # Variante original (contratos que aún esperan la longitud explícita)
    attempt_variants.append(("with_len", [k, ln, user, eth_int, btc_int]))
    # Variante sin longitud (contratos actualizados que la derivan internamente)
    attempt_variants.append(("without_len", [k, user, eth_int, btc_int]))

    resp = None
    last_error: Optional[Exception] = None

    for variant_name, alias_calldata in attempt_variants:
        erc20_transfer_from = Call(
            to_addr=AIC_TOKEN,
            selector=get_selector_from_name("transfer_from"),
            calldata=[user, relayer.address, FEE_AIC_WEI, 0],
        )
        alias_register = Call(
            to_addr=ALIAS_CONTRACT,
            selector=get_selector_from_name("admin_register_for"),
            calldata=alias_calldata,
        )

        calls = [erc20_transfer_from, alias_register]
        fee_value, estimated_bounds = await _estimate_fee_components(calls)

        resp, last_error = await _execute_with_calls(calls, fee_value, estimated_bounds)
        if resp is not None:
            break

        message = _flatten_exception_message(last_error) if last_error else ""
        if variant_name == "with_len" and "INPUT TOO LONG FOR ARGUMENTS" in message.upper():
            print("[info] admin_register_for sin parámetro len, reintentando compatibilidad")
            continue
        else:
            break

    if resp is None:
        status_code, message = _classify_relayer_error(last_error or Exception("Error desconocido"))
        raise HTTPException(status_code, message)

    tx_hash = getattr(resp, "transaction_hash", resp)

    alias_key_hex = hex(k)
    addr_hex = hex(user)
    eth_hex = hex(eth_int)
    btc_hex = hex(btc_int)

    previous = ALIAS_INDEX.get(alias_key_hex)
    if previous:
        prev_eth = previous.get("eth_address")
        prev_btc = previous.get("btc_address")
        if prev_eth and prev_eth != eth_hex:
            EXTERNAL_INDEX["ETH"].pop(prev_eth, None)
        if prev_btc and prev_btc != btc_hex:
            EXTERNAL_INDEX["BTC"].pop(prev_btc, None)

    prev_addr_record = ADDR_INDEX.get(addr_hex)
    if prev_addr_record and prev_addr_record is not previous:
        EXTERNAL_INDEX["ETH"].pop(prev_addr_record.get("eth_address"), None)
        EXTERNAL_INDEX["BTC"].pop(prev_addr_record.get("btc_address"), None)

    record = {
        "alias_key": alias_key_hex,
        "alias": alias_norm,
        "address": addr_hex,
        "eth_address": eth_hex,
        "btc_address": btc_hex,
    }

    ALIAS_INDEX[alias_key_hex] = record
    ADDR_INDEX[addr_hex] = record
    if eth_int:
        EXTERNAL_INDEX["ETH"][eth_hex] = record
    if btc_int:
        EXTERNAL_INDEX["BTC"][btc_hex] = record

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
        block_kwargs = {}
        try:
            from starknet_py.net.client_models import BlockId, Tag

            block_kwargs["block_id"] = BlockId(tag=Tag.LATEST)
        except Exception:
            block_kwargs["block_number"] = "latest"
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    try:
        res_addr = await client.call_contract(
            call=Call(
                to_addr=ALIAS_CONTRACT,
                selector=get_selector_from_name("addr_of_alias"),
                calldata=[k],
            ),
            **block_kwargs,
        )
        onchain_addr_int = int(res_addr[0]) if res_addr else 0

        eth_res = await client.call_contract(
            call=Call(
                to_addr=ALIAS_CONTRACT,
                selector=get_selector_from_name("external_address_of"),
                calldata=[k, CHAIN_ID_ETHEREUM_FELT],
            ),
            **block_kwargs,
        )
        btc_res = await client.call_contract(
            call=Call(
                to_addr=ALIAS_CONTRACT,
                selector=get_selector_from_name("external_address_of"),
                calldata=[k, CHAIN_ID_BITCOIN_FELT],
            ),
            **block_kwargs,
        )
    except Exception as e:
        raise HTTPException(500, f"Error on-chain: {e}")

    mem = ALIAS_INDEX.get(hex(k))
    return {
        "alias": alias_norm,
        "alias_key": hex(k),
        "onchain_registered": onchain_addr_int != 0,
        "onchain_address": hex(onchain_addr_int),
        "external_addresses": {
            "ETH": format_external_value(int(eth_res[0]) if eth_res else 0),
            "BTC": format_external_value(int(btc_res[0]) if btc_res else 0),
        },
        "memory_index": dict(mem) if mem else None,
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
        block_kwargs = {}
        try:
            from starknet_py.net.client_models import BlockId, Tag

            block_kwargs["block_id"] = BlockId(tag=Tag.LATEST)
        except Exception:
            block_kwargs["block_number"] = "latest"
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    try:
        alias_res = await client.call_contract(
            call=Call(
                to_addr=ALIAS_CONTRACT,
                selector=get_selector_from_name("alias_of_addr"),
                calldata=[addr_int],
            ),
            **block_kwargs,
        )
        alias_felt = int(alias_res[0]) if alias_res else 0

        key_res = await client.call_contract(
            call=Call(
                to_addr=ALIAS_CONTRACT,
                selector=get_selector_from_name("alias_key_of_addr"),
                calldata=[addr_int],
            ),
            **block_kwargs,
        )
        alias_key = int(key_res[0]) if key_res else 0
    except Exception as e:
        raise HTTPException(500, f"Error on-chain: {e}")

    alias_text = felt_to_ascii_str(alias_felt)
    if alias_text and not ALIAS_REGEX.fullmatch(alias_text):
        alias_text = None

    mem = ADDR_INDEX.get(hex(addr_int))
    if not alias_text and mem:
        alias_text = mem.get("alias")

    eth_value = 0
    btc_value = 0
    if alias_key:
        try:
            eth_res = await client.call_contract(
                call=Call(
                    to_addr=ALIAS_CONTRACT,
                    selector=get_selector_from_name("external_address_of"),
                    calldata=[alias_key, CHAIN_ID_ETHEREUM_FELT],
                ),
                **block_kwargs,
            )
            btc_res = await client.call_contract(
                call=Call(
                    to_addr=ALIAS_CONTRACT,
                    selector=get_selector_from_name("external_address_of"),
                    calldata=[alias_key, CHAIN_ID_BITCOIN_FELT],
                ),
                **block_kwargs,
            )
            eth_value = int(eth_res[0]) if eth_res else 0
            btc_value = int(btc_res[0]) if btc_res else 0
        except Exception:
            pass

    onchain_key_hex = hex(alias_key) if alias_key else None

    return {
        "address": hex(addr_int),
        "alias_felt_hex": hex(alias_felt),
        "alias": alias_text,
        "onchain_alias_key": onchain_key_hex,
        "external_addresses": {
            "ETH": format_external_value(eth_value),
            "BTC": format_external_value(btc_value),
        },
        "memory_index": dict(mem) if mem else None,
    }


# ===== eventos on-chain =====


@app.get("/api/contract_events")
async def contract_events(
    limit: int = 20,
    continuation_token: Optional[str] = None,
    max_chunks: int = 200,
):
    if not ALIAS_CONTRACT:
        raise HTTPException(500, "ALIAS_CONTRACT no configurado")

    client, _ = _get_client_and_relayer()

    try:
        from starknet_py.hash.selector import get_selector_from_name
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    try:
        event_key = get_selector_from_name("AliasExternalUpdated")
    except Exception as e:
        raise HTTPException(500, f"No se pudo calcular selector: {e}")

    chunk_size = max(1, min(int(limit or 20), 100))
    max_scans = max(1, min(int(max_chunks or 1), 1000))

    def _resolve_event_attr(source, attr: str):
        if source is None:
            return None

        if isinstance(source, dict):
            candidate = source.get(attr)
        else:
            candidate = getattr(source, attr, None)

        if callable(candidate):
            try:
                return candidate()
            except TypeError:
                return None
        return candidate

    def _extract_keys_and_data(evt):
        event_section = evt
        nested = _resolve_event_attr(evt, "event")
        if nested is not None:
            event_section = nested

        raw_keys = _resolve_event_attr(event_section, "keys")
        raw_data = _resolve_event_attr(event_section, "data")

        if raw_keys is None:
            keys_list = []
        elif isinstance(raw_keys, (list, tuple, set)):
            keys_list = list(raw_keys)
        else:
            keys_list = [raw_keys]

        if raw_data is None:
            data_list = []
        elif isinstance(raw_data, (list, tuple, set)):
            data_list = list(raw_data)
        else:
            data_list = [raw_data]

        norm_keys = []
        for key in keys_list:
            try:
                norm_keys.append(int(key))
            except Exception:
                continue

        norm_data = []
        for value in data_list:
            try:
                norm_data.append(int(value))
            except Exception:
                continue

        return {
            "section": event_section,
            "keys": norm_keys,
            "raw_keys": keys_list,
            "data": norm_data,
            "raw_data": data_list,
        }

    def _event_matches(evt, *, allow_keyless: bool) -> Dict[str, object]:
        extracted = _extract_keys_and_data(evt)

        for key in extracted["keys"]:
            if key == event_key:
                return {"matched": True, "extracted": extracted, "used_keyless": False}

        if allow_keyless and not extracted["keys"]:
            # AliasExternalUpdated always contains exactly (alias_key, eth, btc)
            if len(extracted["data"]) == 3:
                return {"matched": True, "extracted": extracted, "used_keyless": True}

        return {"matched": False, "extracted": extracted, "used_keyless": False}

    async def _scan_events(keys_filter, *, allow_keyless: bool):
        next_token_local = continuation_token
        matched = []
        fetches_local = 0
        empty_local = 0
        visited_local = set()
        truncated_local = False
        keyless_matches = 0

        while len(matched) < chunk_size:
            marker = next_token_local or "__initial__"
            if marker in visited_local:
                truncated_local = True
                next_token_local = None
                break
            visited_local.add(marker)

            try:
                chunk = await client.get_events(
                    address=ALIAS_CONTRACT,
                    keys=keys_filter,
                    from_block_number=0,
                    to_block_number="latest",
                    continuation_token=next_token_local,
                    chunk_size=chunk_size,
                )
            except Exception as e:
                raise HTTPException(500, f"Error consultando eventos: {e}")

            fetches_local += 1
            chunk_events = list(getattr(chunk, "events", []) or [])

            matched_chunk = []
            for evt in chunk_events:
                match_info = _event_matches(evt, allow_keyless=allow_keyless)
                if match_info["matched"]:
                    matched.append((evt, match_info["extracted"]))
                    matched_chunk.append((evt, match_info["extracted"]))
                    if match_info["used_keyless"]:
                        keyless_matches += 1
                    if len(matched) >= chunk_size:
                        break

            if not matched_chunk:
                empty_local += 1

            next_token_local = getattr(chunk, "continuation_token", None)

            if not next_token_local:
                break

            if fetches_local >= max_scans:
                truncated_local = True
                break

        return {
            "events": matched[:chunk_size],
            "next_token": next_token_local,
            "fetches": fetches_local,
            "empty": empty_local,
            "visited": visited_local,
            "truncated": truncated_local,
            "keyless": keyless_matches,
        }

    primary_scan = await _scan_events([[event_key]], allow_keyless=False)
    used_fallback = False
    keyless_hits = primary_scan["keyless"]

    if not primary_scan["events"] and primary_scan["fetches"] > 0:
        fallback_scan = await _scan_events(None, allow_keyless=True)
        used_fallback = True

        chosen_events = fallback_scan["events"]
        next_token = fallback_scan["next_token"]
        fetches = primary_scan["fetches"] + fallback_scan["fetches"]
        empty_chunks = primary_scan["empty"] + fallback_scan["empty"]
        visited_tokens = primary_scan["visited"].union(fallback_scan["visited"])
        truncated = primary_scan["truncated"] or fallback_scan["truncated"]
        keyless_hits += fallback_scan["keyless"]
    else:
        chosen_events = primary_scan["events"]
        next_token = primary_scan["next_token"]
        fetches = primary_scan["fetches"]
        empty_chunks = primary_scan["empty"]
        visited_tokens = primary_scan["visited"]
        truncated = primary_scan["truncated"]

    def _event_numeric(value):
        if value is None:
            return None
        if isinstance(value, int):
            return value
        try:
            return int(value)
        except Exception:
            if isinstance(value, str):
                try:
                    return int(value, 16)
                except Exception:
                    return None
        return None

    def _event_hex(value):
        if value is None:
            return None
        if isinstance(value, str):
            v = value.strip()
            if v:
                if v.startswith("0x") or v.startswith("0X"):
                    return v.lower()
                try:
                    return hex(int(v))
                except Exception:
                    return v
            return None
        try:
            return hex(int(value))
        except Exception:
            return None

    events = []
    for evt, extracted in chosen_events:
        data = extracted["data"]
        alias_key_int = data[0] if len(data) > 0 else 0
        eth_int = data[1] if len(data) > 1 else 0
        btc_int = data[2] if len(data) > 2 else 0

        alias_key_hex = hex(alias_key_int) if alias_key_int else None
        mem = ALIAS_INDEX.get(alias_key_hex) if alias_key_hex else None

        event_section = extracted["section"]

        block_number = _resolve_event_attr(evt, "block_number")
        block_hash = _event_hex(_resolve_event_attr(evt, "block_hash"))
        transaction_hash = _event_hex(_resolve_event_attr(evt, "transaction_hash"))

        from_address_source = _resolve_event_attr(evt, "from_address")
        if from_address_source is None:
            from_address_source = _resolve_event_attr(event_section, "from_address")
        from_address_hex = _event_hex(from_address_source)

        raw_keys = []
        for key in extracted["raw_keys"]:
            num = _event_numeric(key)
            if num is not None:
                raw_keys.append(hex(num))
            elif isinstance(key, str):
                raw_keys.append(key)

        raw_data = []
        for value in extracted["raw_data"]:
            num = _event_numeric(value)
            if num is not None:
                raw_data.append(hex(num))
            elif isinstance(value, str):
                raw_data.append(value)

        events.append(
            {
                "block_number": _event_numeric(block_number),
                "block_hash": block_hash,
                "transaction_hash": transaction_hash,
                "from_address": from_address_hex,
                "alias_key": alias_key_hex,
                "external": {
                    "ETH": format_external_value(eth_int),
                    "BTC": format_external_value(btc_int),
                },
                "raw_event": {
                    "keys": raw_keys,
                    "data": raw_data,
                },
                "memory_index": dict(mem) if mem else None,
            }
        )

    return {
        "count": len(events),
        "event_key": hex(event_key),
        "continuation_token": next_token,
        "events": events,
        "chunk_size": chunk_size,
        "fetches": fetches,
        "empty_chunks": empty_chunks,
        "scanned_chunks": len(visited_tokens),
        "truncated": truncated,
        "used_fallback_without_key": used_fallback,
        "matched_keyless_events": keyless_hits,
    }


@app.get("/api/alias_of_external")
async def alias_of_external(chain: str, external_address: str):
    chain_id = parse_chain_identifier(chain)
    ext_int = encode_external_address(external_address, label="external_address")

    client, _ = _get_client_and_relayer()
    try:
        from starknet_py.net.client_models import Call
        from starknet_py.hash.selector import get_selector_from_name
        block_kwargs = {}
        try:
            from starknet_py.net.client_models import BlockId, Tag

            block_kwargs["block_id"] = BlockId(tag=Tag.LATEST)
        except Exception:
            block_kwargs["block_number"] = "latest"
    except Exception as e:
        raise HTTPException(500, f"starknet_py no disponible: {e}")

    try:
        res = await client.call_contract(
            call=Call(
                to_addr=ALIAS_CONTRACT,
                selector=get_selector_from_name("alias_of_external"),
                calldata=[chain_id, ext_int],
            ),
            **block_kwargs,
        )
        alias_key = int(res[0]) if res else 0
    except Exception as e:
        raise HTTPException(500, f"Error on-chain: {e}")

    starknet_address_hex = None
    alias_text = None
    if alias_key:
        try:
            addr_res = await client.call_contract(
                call=Call(
                    to_addr=ALIAS_CONTRACT,
                    selector=get_selector_from_name("addr_of_alias"),
                    calldata=[alias_key],
                ),
                **block_kwargs,
            )
            addr_int = int(addr_res[0]) if addr_res else 0
            if addr_int:
                starknet_address_hex = hex(addr_int)
                alias_res = await client.call_contract(
                    call=Call(
                        to_addr=ALIAS_CONTRACT,
                        selector=get_selector_from_name("alias_of_addr"),
                        calldata=[addr_int],
                    ),
                    **block_kwargs,
                )
                alias_felt = int(alias_res[0]) if alias_res else 0
                alias_text = felt_to_ascii_str(alias_felt)
                if alias_text and not ALIAS_REGEX.fullmatch(alias_text):
                    alias_text = None
        except Exception:
            pass

    chain_label = FELT_TO_CHAIN_LABEL.get(chain_id)
    mem = None
    if chain_label:
        mem = EXTERNAL_INDEX.get(chain_label, {}).get(hex(ext_int))
    if mem:
        mem_copy = dict(mem)
        if not alias_text:
            alias_text = mem_copy.get("alias")
        if not starknet_address_hex:
            starknet_address_hex = mem_copy.get("address")
    else:
        mem_copy = None

    return {
        "chain_id_hex": hex(chain_id),
        "chain_label": chain_label,
        "external_address_felt": hex(ext_int),
        "alias_key": hex(alias_key) if alias_key else None,
        "alias": alias_text,
        "starknet_address": starknet_address_hex,
        "memory_index": mem_copy,
    }


@app.get("/api/list")
async def list_local():
    items = [dict(item) for item in ALIAS_INDEX.values()]
    items.sort(key=lambda x: x["alias"])
    external_counts = {label: len(values) for label, values in EXTERNAL_INDEX.items()}
    return {"count": len(items), "items": items, "external_index_counts": external_counts}

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

from fastapi.responses import FileResponse
import os

@app.get("/aliascbu.js", include_in_schema=False)
def serve_aliascbu():
    # Intentar rutas posibles
    candidates = [
        os.path.join(os.path.dirname(__file__), "public", "aliascbu.js"),
        os.path.join(os.getcwd(), "public", "aliascbu.js"),
        "/var/task/public/aliascbu.js"  # ruta habitual en Vercel
    ]
    for p in candidates:
        if os.path.exists(p):
            return FileResponse(p, media_type="application/javascript")
    return {"detail": f"Not Found: tried {candidates}"}
