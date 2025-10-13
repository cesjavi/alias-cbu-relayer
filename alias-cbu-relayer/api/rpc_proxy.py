# api/rpc_proxy.py
import os, httpx
from fastapi import APIRouter, Request, Response

RPC_URL = os.getenv("RPC_URL")  # tu endpoint Sepolia
router = APIRouter()

@router.post("/rpc")
async def rpc_proxy(req: Request):
    body = await req.json()
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(RPC_URL, json=body, headers={"content-type":"application/json"})
    return Response(r.content, status_code=r.status_code, media_type="application/json")
