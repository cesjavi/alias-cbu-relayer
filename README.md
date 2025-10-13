# Alias CBU (Starknet) – Gasless con AIC (relayer)

Registro minimalista de alias tipo CBU: `alias (normalizado) -> address` y `address -> alias_key`,
compatible con integraciones estilo resolver (ENS/StarknetID).

- **On-chain**: `AliasCBU.cairo` (Cairo 1)
- **Off-chain**: Backend FastAPI (relayer) cobra en **AIC** vía `transfer_from`, paga STRK.
- **Frontend**: HTML+Jinja con `get-starknet` para firmar y hacer `approve`.

## Requisitos

- Scarb y Cairo 2.6.x
- `sncast` configurado con una cuenta (perfil `sepolia` de ejemplo)
- Python 3.10+ (`venv` recomendado)

## Compilar / Desplegar

```bash
source scripts/alias.env
bash scripts/01_build.sh

# Declarar
bash scripts/02_declare.sh
# => Tomá el CLASS_HASH e: export CLASS_HASH=0x...

# Desplegar
bash scripts/03_deploy.sh
# => Guardá CONTRACT_ADDR (ALIAS_CONTRACT)

# (Opcional) Actualizar fee
export CONTRACT_ADDR=0x... # address del contrato desplegado
bash scripts/04_set_fee.sh
