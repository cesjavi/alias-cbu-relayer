(venv) cesar@DESKTOP-VJO5HF3:~/aliascbu/scripts$ ./02_declare.sh 
Declarando contrato: alias_cbu
   Compiling lib(alias_cbu) alias_cbu v0.1.0 (/home/cesar/aliascbu/Scarb.toml)
warn: artefacts produced by this build may be hard to utilize due to the build configuration
please make sure your build configuration is correct
help: if you want to use your build with a specialized tool that runs Sierra code (for
instance with a test framework like Forge), please make sure all required dependencies
are specified in your package manifest.
help: if you want to compile a Starknet contract, make sure to use the `starknet-contract`
target, by adding following excerpt to your package manifest
-> Scarb.toml
    [[target.starknet-contract]]
help: if you want to read the generated Sierra code yourself, consider enabling
the debug names, by adding the following excerpt to your package manifest.
-> Scarb.toml
    [cairo]
    sierra-replace-ids = true
   Compiling starknet-contract(alias_cbu) alias_cbu v0.1.0 (/home/cesar/aliascbu/Scarb.toml)
    Finished `release` profile target(s) in 6 seconds
Success: Declaration completed

Class Hash:       0x28ec5f06eac019627ae86506051fced3c59add25145e5fbc41354668e62321
Transaction Hash: 0x7c497fd7e42f9d09e56bc0277c6c2e8ea64db38ea47a061ae02a41e60862580

To see declaration details, visit:
class: https://sepolia.starkscan.co/class/0x0028ec5f06eac019627ae86506051fced3c59add25145e5fbc41354668e62321
transaction: https://sepolia.starkscan.co/tx/0x07c497fd7e42f9d09e56bc0277c6c2e8ea64db38ea47a061ae02a41e60862580

(venv) cesar@DESKTOP-VJO5HF3:~/aliascbu/scripts$ 

(venv) cesar@DESKTOP-VJO5HF3:~/aliascbu/scripts$ ./03_deploy.sh 
Deploying class: 0x28ec5f06eac019627ae86506051fced3c59add25145e5fbc41354668e62321
Success: Deployment completed

Contract Address: 0x05d066e4e6e956e9153c47fb98a4384b180d209d46c7f3a8c96cb4f0bc76423b
Transaction Hash: 0x0185683de903f26f442a082722ffbf635c74988b3f8285d2ece4beb8c7c599a5

To see deployment details, visit:
contract: https://sepolia.starkscan.co/contract/0x05d066e4e6e956e9153c47fb98a4384b180d209d46c7f3a8c96cb4f0bc76423b
transaction: https://sepolia.starkscan.co/tx/0x0185683de903f26f442a082722ffbf635c74988b3f8285d2ece4beb8c7c599a5


(venv) cesar@DESKTOP-VJO5HF3:~/aliascbu/scripts$ ./04_set_fee.sh 
Seteando fee: token=0x1 amount(low,high)=(1000000000000000000,0)
Success: Invoke completed

Transaction Hash: 0x0536ec58bf1cc031ad9899cfe94145367c51d260912fa95ec92cc96dd4652fc0

To see invocation details, visit:
transaction: https://sepolia.starkscan.co/tx/0x0536ec58bf1cc031ad9899cfe94145367c51d260912fa95ec92cc96dd4652fc0

uvicorn app:app --reload --port 8000