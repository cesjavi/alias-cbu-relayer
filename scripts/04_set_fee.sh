#!/usr/bin/env bash
set -euo pipefail
# Pararse en el root (donde está Scarb.toml)
cd "$(dirname "$0")/.."

: "${STARKNET_RPC_URL:?STARKNET_RPC_URL no seteado}"
: "${CONTRACT_ADDR:?CONTRACT_ADDR no seteado}"
: "${AIC_TOKEN_ADDR:?AIC_TOKEN_ADDR no seteado}"
: "${FEE_AIC_LOW:?FEE_AIC_LOW no seteado}"
: "${FEE_AIC_HIGH:?FEE_AIC_HIGH no seteado}"

echo "Seteando fee: token=$AIC_TOKEN_ADDR amount(low,high)=($FEE_AIC_LOW,$FEE_AIC_HIGH)"
sncast invoke \
  --url "$STARKNET_RPC_URL" \
  --contract-address "$CONTRACT_ADDR" \
  --function "admin_set_fee" \
  --calldata "$AIC_TOKEN_ADDR" "$FEE_AIC_LOW" "$FEE_AIC_HIGH"
