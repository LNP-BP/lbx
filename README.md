# lbx: 

Command-line tool for working with LNP/BP technology stack

## Install

### Get the dependencies

```shell script
sudo apt-get install cargo
```

### Clone and compile lbx

```shell script
git clone https://github.com/lnp-bp/lbx
cd lbx
cargo build
```

## Sample commands

Note: run `lbx` command in `target/debug` or `target/release` directories inside the repository.

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
