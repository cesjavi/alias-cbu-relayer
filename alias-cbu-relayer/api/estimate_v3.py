import os, json, httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from starknet_py.hash.selector import get_selector_from_name

print("[estimate_v3] MODULE LOADED:", __file__)

router = APIRouter()

class EstimateIn(BaseModel):
    sender: str
    calls: list[dict]  # Acepta formato starknet.js: contractAddress, entrypoint, calldata

HEADERS = {"content-type": "application/json", "accept": "application/json"}

async def rpc_post(client: httpx.AsyncClient, url: str, body: dict):
    r = await client.post(url, json=body, headers=HEADERS)
    text = r.text
    try:
        j = r.json()
    except Exception:
        j = None
    return r.status_code, text, j

def pick_result(j: dict | None, ctx: str):
    if not isinstance(j, dict):
        raise HTTPException(502, f"{ctx}: respuesta no-JSON del RPC")
    if "error" in j:
        raise HTTPException(502, f"{ctx}: {json.dumps(j['error'])}")
    if "result" not in j:
        raise HTTPException(502, f"{ctx}: JSON sin 'result' → {json.dumps(j)[:300]}")
    return j["result"]

@router.post("/estimate_v3")
async def estimate_v3(inp: EstimateIn):
    RPC_URL = os.getenv("RPC_URL")
    if not RPC_URL:
        raise HTTPException(500, "RPC_URL no configurado")

    print(f"[estimate_v3] INPUT: sender={inp.sender}, calls={inp.calls}")

    try:
        async with httpx.AsyncClient(timeout=30) as c:
            # 0) bloque por hash (evita 'latest')
            st0, txt0, j0 = await rpc_post(c, RPC_URL, {
                "jsonrpc": "2.0", "id": 0,
                "method": "starknet_blockHashAndNumber",
                "params": []
            })
            bh = pick_result(j0, f"blockHashAndNumber HTTP {st0}")
            block_id = {"block_hash": bh["block_hash"]}

            # 1) nonce (cuenta no desplegada => 0)
            st1, txt1, j1 = await rpc_post(c, RPC_URL, {
                "jsonrpc": "2.0", "id": 1,
                "method": "starknet_getNonce",
                "params": [block_id, inp.sender]
            })
            if isinstance(j1, dict) and "error" in j1:
                err = j1["error"]
                if (err.get("code") == 20) or ("Contract not found" in err.get("message", "")):
                    nonce = "0x0"
                else:
                    raise HTTPException(502, f"getNonce HTTP {st1}: {json.dumps(err)}")
            else:
                nonce = pick_result(j1, f"getNonce HTTP {st1}")

            # 2) Construir calldata desde inp.calls (soporta formato starknet.js)
            calldata = []
            if inp.calls and len(inp.calls) > 0:
                # Normalizar calls: soporta contractAddress/entrypoint O to/selector
                normalized_calls = []
                for call in inp.calls:
                    if "contractAddress" in call and "entrypoint" in call:
                        # Formato starknet.js -> convertir a RPC
                        to = call["contractAddress"]
                        selector = hex(get_selector_from_name(call["entrypoint"]))
                        cd = call.get("calldata", [])
                    elif "to" in call and "selector" in call:
                        # Formato RPC directo
                        to = call["to"]
                        selector = call["selector"]
                        cd = call.get("calldata", [])
                    else:
                        raise HTTPException(400, f"Call inválido: {call}")
                    
                    normalized_calls.append({"to": to, "selector": selector, "calldata": cd})
                
                # Construir calldata multicall
                calldata.append(str(len(normalized_calls)))
                
                total_offset = 0
                call_datas = []
                for call in normalized_calls:
                    cd = call["calldata"]
                    call_datas.append(cd)
                    calldata.extend([
                        call["to"],
                        call["selector"],
                        str(total_offset),
                        str(len(cd))
                    ])
                    total_offset += len(cd)
                
                for cd in call_datas:
                    calldata.extend(cd)
            
            print(f"[estimate_v3] Calldata construido: len={len(calldata)}, primeros 10: {calldata[:10]}")

            # 3) INVOKE v3 bien formado
            U64_MAX = "0xFFFFFFFFFFFFFFFF"
            resource_bounds = {
                "l1_gas":      { "max_amount": U64_MAX, "max_price_per_unit": U64_MAX },
                "l2_gas":      { "max_amount": U64_MAX, "max_price_per_unit": U64_MAX },
                "l1_data_gas": { "max_amount": U64_MAX, "max_price_per_unit": U64_MAX },
            }
            invoke = {
                "type": "INVOKE",
                "version": "0x3",
                "sender_address": inp.sender,
                "nonce": nonce,
                "calldata": calldata,
                "signature": [],
                "resource_bounds": resource_bounds,
                "tip": "0x0",
                "paymaster_data": [],
                "account_deployment_data": [],
                "fee_data_availability_mode": "L1",
                "nonce_data_availability_mode": "L1",
            }

            # 4) Variantes del 3er parámetro
            variants = [
                ("skip_validate", [[invoke], block_id, ["SKIP_VALIDATE"]]),
                ("empty", [[invoke], block_id, []]),
                ("skip_all", [[invoke], block_id, ["SKIP_VALIDATE","SKIP_FEE_CHARGE"]]),
            ]

            last_err = None
            for name, params in variants:
                body = {"jsonrpc": "2.0", "id": 2, "method": "starknet_estimateFee", "params": params}
                print(f"[estimate_v3] estimateFee body ({name}) =>",
                      json.dumps(body, separators=(",", ":"), ensure_ascii=False)[:500])

                st2, txt2, j2 = await rpc_post(c, RPC_URL, body)

                if not isinstance(j2, dict):
                    last_err = HTTPException(502, f"estimateFee HTTP {st2} ({name}): respuesta no-JSON → {txt2[:200]}")
                    continue

                if "error" in j2:
                    # Si el nodo sigue quejándose de simulation_flags/params, probamos la siguiente variante
                    reason = json.dumps(j2["error"])
                    if "-32602" in reason or "Invalid params" in reason or "simulation_flags" in reason:
                        last_err = HTTPException(502, f"estimateFee HTTP {st2} ({name}): {reason}")
                        continue
                    # Otros errores (AA/calldata/firma) → devolvemos
                    raise HTTPException(502, f"estimateFee HTTP {st2} ({name}): {reason}")

                res_arr = j2.get("result") or []
                res0 = (res_arr or [{}])[0]
                max_fee = res0.get("suggested_max_fee") or res0.get("overall_fee")
                if not max_fee:
                    raise HTTPException(502, f"estimateFee ({name}): sin suggested/overall_fee → {json.dumps(res0)[:300]}")
                return {"nonce": nonce, "max_fee": max_fee}

            # Si agotamos variantes:
            raise last_err or HTTPException(502, "estimateFee falló sin detalle")

    except HTTPException:
        raise
    except Exception as e:
        print("[estimate_v3] unexpected:", repr(e))
        raise HTTPException(500, f"estimate_v3 internal: {e}")