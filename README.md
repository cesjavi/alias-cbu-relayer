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

## Configurar el token AIC en tu wallet

Para poder pagar el registro el usuario debe tener saldo AIC y la wallet tiene que reconocer el token. El contrato actual de AIC en **Starknet Sepolia** es:

- **Dirección (contract address)**: `0x22945bb1d0742bde543b1fb2a1cefbddeaf4a907d53cb28c0e2fb37f6fcc544`
- **Símbolo**: `AIC`
- **Decimales**: `18`

Pasos recomendados por wallet:

- **ArgentX Ready**
  1. Abrí la extensión y seleccioná la red Starknet Sepolia.
  2. En la pestaña *Assets* elegí **Add token** → *Custom token*.
  3. Pegá la dirección del contrato AIC (se autocompleta el símbolo/decimales) y confirmá.

- **Braavos**
  1. Cambiá a la red Starknet Sepolia si aún no está activa.
  2. Entrá en *Tokens* → **+ Add custom token**.
  3. Pegá la dirección anterior y guardá; Braavos detecta automáticamente los metadatos del token.

- **Xverse**
  1. Asegurate de tener habilitada la cuenta Starknet (desde *Settings → Manage accounts*).
  2. Desde la vista de activos elegí **Add token**.
  3. Ingresá el contract address de AIC y confirmá el alta del activo.

> 💡 Si el frontend está desplegado, también podés consultar `https://alias-cbu-relayer.vercel.app/api/config` para verificar la dirección del token y el fee configurado por el relayer.
