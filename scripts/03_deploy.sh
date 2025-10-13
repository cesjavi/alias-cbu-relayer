#!/usr/bin/env bash
set -euo pipefail

# Pararse en el root (donde está Scarb.toml)
cd "$(dirname "$0")/.."

: "${STARKNET_RPC_URL:?STARKNET_RPC_URL no seteado}"
: "${CLASS_HASH:?CLASS_HASH no seteado}"      # export CLASS_HASH=0x...
: "${OWNER_ADDR:?OWNER_ADDR no seteado}"
: "${AIC_TOKEN_ADDR:?AIC_TOKEN_ADDR no seteado}"
: "${FEE_AIC_LOW:?FEE_AIC_LOW no seteado}"
: "${FEE_AIC_HIGH:?FEE_AIC_HIGH no seteado}"

echo "Deploying class: $CLASS_HASH"
sncast deploy \
  --url "$STARKNET_RPC_URL" \
  --class-hash "$CLASS_HASH" \
  --constructor-calldata "$OWNER_ADDR" "$AIC_TOKEN_ADDR" "$FEE_AIC_LOW" "$FEE_AIC_HIGH"
