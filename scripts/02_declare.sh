#!/usr/bin/env bash
set -euo pipefail
# pararse en el root (donde está Scarb.toml)
cd "$(dirname "$0")/.."

: "${STARKNET_RPC_URL:?STARKNET_RPC_URL no seteado}"

# en tu caso el contrato se llama exactamente "alias_cbu"
CONTRACT_NAME="${CONTRACT_NAME:-alias_cbu}"

echo "Declarando contrato: $CONTRACT_NAME"
sncast declare \
  --contract-name "$CONTRACT_NAME" \
  --url "$STARKNET_RPC_URL"
