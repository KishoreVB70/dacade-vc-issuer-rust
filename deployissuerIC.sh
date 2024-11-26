dfx canister create issuer
dfx build issuer

candid-extractor target/wasm32-unknown-unknown/release/issuer.wasm > issuer/issuer.did

dfx generate issuer

rootkey_did=$(dfx ping ic \
    | sed -n 's/.*"root_key": \[\(.*\)\].*/{\1}/p' \
    | sed 's/\([0-9][0-9]*\)/\1:nat8/g' \
    | sed 's/,/;/g')
    
echo "Public key: ${rootkey_did}"

II_CANISTER_ID=$(dfx canister id internet_identity --network ic)
ISSUER_DERIVATION_ORIGIN="https://rp-dacade-demo.netlify.app"

echo "Internet identity canister: ${II_CANISTER_ID}"

dfx deploy issuer --network ic --argument '(
    opt record { 
        idp_canister_ids = vec{ principal "'"$II_CANISTER_ID"'" }; 
        ic_root_key_der = vec '"$rootkey_did"'; 
        derivation_origin = "'"$ISSUER_DERIVATION_ORIGIN"'" 
        }
    )'