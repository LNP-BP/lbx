```shell script
lbx state-geneis fungible test/data/candies.yaml test/data/candies.rgb
lbx state-transition fungible transfer -r <5000:txid:vout> -r <100:txid:vout> test/data/transfer-candies.rgb
lbx cv-commit test/data/dest_tx.psbt test/data/client_proofs.rgb \
    -f 404 -e 88b5990f3ff597306bb82cf38ac0d3ecbb7117d57d7424eab20cc938a5083bb1 \
    --message candies:test/data/transfer-candies.rgb \
    --message usdt:test/data/transfer-usdt.rgb \
    --tx test/data/source_tx.psbt \
    -v -v # Asking to be verbose
bx tx-send test/data/source_tx.psbt
```
