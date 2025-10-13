from dotenv import load_dotenv
load_dotenv()

import os, re
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from api.rpc_proxy import router as rpc_router
from api.estimate_v3 import  router as est_router

from pydantic import BaseModel

from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.net.account.account import Account
from starknet_py.net.client_models import Call
from starknet_py.net.client_models import ResourceBoundsMapping, ResourceBounds
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.signer.stark_curve_signer import KeyPair
from eth_hash.auto import keccak as keccak256

RPC_URL = os.getenv("RPC_URL")
ALIAS_CONTRACT = int(os.getenv("ALIAS_CONTRACT", "0"), 16)
AIC_TOKEN = int(os.getenv("AIC_TOKEN", "0"), 16)
RELAYER_ACCOUNT_ADDRESS = int(os.getenv("RELAYER_ACCOUNT_ADDRESS", "0"), 16)
RELAYER_PRIVATE_KEY = int(os.getenv("RELAYER_PRIVATE_KEY", "0"), 16)
FEE_AIC_WEI = int(os.getenv("FEE_AIC_WEI", "0"))
CHAIN_ID = int(os.getenv("CHAIN_ID", "0"), 16)

if not (RPC_URL and ALIAS_CONTRACT and AIC_TOKEN and RELAYER_ACCOUNT_ADDRESS and RELAYER_PRIVATE_KEY and FEE_AIC_WEI and CHAIN_ID):
    raise RuntimeError("Faltan variables de entorno (.env)")

client = FullNodeClient(node_url=RPC_URL)
relayer = Account(
    client=client,
    address=RELAYER_ACCOUNT_ADDRESS,
    key_pair=KeyPair.from_private_key(RELAYER_PRIVATE_KEY),
    chain=CHAIN_ID,
)

app = FastAPI(title="AliasCBU Relayer (Gasless AIC)")
templates = Jinja2Templates(directory="templates")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(rpc_router, prefix="/api")
app.include_router(est_router, prefix="/api")

ALIAS_REGEX = re.compile(r"^[a-z0-9.]{4,20}$")
NONCES: dict[str, int] = {}

def normalize_alias(s: str) -> str:
    alias = s.strip().lower()
    if not ALIAS_REGEX.match(alias):
        raise ValueError("Alias invalido: solo letras, numeros y puntos; longitud 4-20.")
    return alias


FIELD_P = (2**251) + (17 * 2**192) + 1

def alias_key(alias: str) -> int:
    """keccak256(alias) reducido a felt (< FIELD_P)"""
    h_bytes = keccak256(alias.encode("utf-8"))  # ← ya devuelve bytes
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

@app.get("/", response_class=HTMLResponse)
async def index(req: Request):
    return templates.TemplateResponse("index.html", {"request": req})

@app.get("/api/config")
async def config():
    """Devuelve config sin padding en chainId (critico para firma)"""
    return {
        "relayer_address": hex(RELAYER_ACCOUNT_ADDRESS),
        "aic_token": hex(AIC_TOKEN),
        "alias_contract": hex(ALIAS_CONTRACT),
        "chain_id": hex(CHAIN_ID),  # Sin padding, ej: 0x534e5f5345504f4c4941
        "fee_aic_wei": str(FEE_AIC_WEI),
    }

@app.post("/api/prepare")
async def prepare(data: PrepareIn):
    alias_norm = normalize_alias(data.alias)
    k = alias_key(alias_norm)
    ln = len(alias_norm)

    user_hex = data.user_address
    user_int = int(user_hex, 16)
    nonce = next_nonce(user_hex)

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
    alias_norm = normalize_alias(data.alias)
    k = alias_key(alias_norm)
    ln = len(alias_norm)
    user = int(data.user_address, 16)

    if NONCES.get(data.user_address.lower(), 0) < data.nonce:
        raise HTTPException(400, "Nonce invalido (prepare faltante)")

    msg = meta_message(k, ln, user, data.nonce).encode("utf-8")

    # Firmas: demo (passthrough).
    if data.signature and len(data.signature) >= 2:
        r_hex, s_hex = data.signature[0], data.signature[1]
    else:
        if not (data.signature_r and data.signature_s):
            raise HTTPException(400, "Falta firma (signature o r/s)")
        r_hex, s_hex = data.signature_r, data.signature_s

    r_int = int(r_hex, 16)
    s_int = int(s_hex, 16)
    # TODO: verificacion StarkCurve real si queres endurecer

    # Multicall: transfer_from + register
    erc20_transfer_from = Call(
        to_addr=AIC_TOKEN,
        selector=get_selector_from_name("transfer_from"),
        calldata=[user, relayer.address, FEE_AIC_WEI, 0]  # u256 simple (low, high)
    )
    alias_register = Call(
        to_addr=ALIAS_CONTRACT,
        selector=get_selector_from_name("register_my_alias"),
        calldata=[k, ln]
    )

    try:
        # Transacción v3 con STRK (si el relayer tiene STRK, sino usa ETH)
        resp = await relayer.execute_v3(
            calls=[erc20_transfer_from, alias_register],
            auto_estimate=True  # Calcula fees automáticamente (usa STRK si está disponible)
        )
        tx_hash = resp.transaction_hash
    except Exception as e:
        raise HTTPException(500, f"Error enviando tx: {e}")

    return {
        "ok": True, 
        "tx_hash": hex(tx_hash), 
        "relayer": hex(relayer.address)
    }