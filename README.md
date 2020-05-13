# lbx: 

Command-line tool for working with LNP/BP technology stack

## Install

### Get the dependencies

```shell script
sudo apt-get install -y rustup libyaml-dev
rustup default nightly
```

### Clone and compile lbx

```shell script
git clone https://github.com/lnp-bp/lbx
cd lbx
cargo install --path .
```

If the build fails, make sure you are using nightly channel for rust compiler:
```shell script
rustup default nightly
```

## Sample commands

Commits to the message by tweaking the public key according to LNPBP-1 standard:
```shell script
lbx pubkey-commit "The message" 02d1d80235fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679cceb
```

Embeds commitment to two messages into partially-signed bitcoin transaction:
```shell script
lbx cv-commit test/data/dest_tx.psbt test/data/client_proofs.rgb \
    -f 404 -e 88b5990f3ff597306bb82cf38ac0d3ecbb7117d57d7424eab20cc938a5083bb1 \
    --message test/data/message1.txt \
    --message test/data/message2.txt \
    --tx test/data/source_tx.psbt \
    -v -v # Asking to be verbose
```

Issues fungible asset named "Candy" with ticker $CNDY for Bitcoin Signet network:
```shell script
lbx fungible-issue --signet \
    CNDY Candies \
    1000000 \
    c202e4bbda988744f45650fc207da3531209dd1813efd701042d21692844bb2f 0 \
    test/data/candies.rgb \
    -v -v # Asking to be verbose
```

Generates client-validated proof of the fungible asset transfer:
```shell script
lbx fungible-transfer c202e4bbda988744f45650fc207da3531209dd1813efd701042d21692844bb2f:1:100 -v -v
```