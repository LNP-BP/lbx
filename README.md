# lbx: 

Command-line tool for working with LNP/BP technology stack

## Install

### Get the dependencies

```
sudo apt-get install cargo
```

### Clone and compile lbx

```
git clone https://github.com/lnp-bp/lbx
cd lbx
cargo build
```

## Sample commands

Run the commands in `~/lbx/target/debug/lbx`

```bash
# commits to the message by tweaking the public key according to LNPBP-1 standard:
$ lbx pubkey-commit "The message" 02d1d80235fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679cceb
```
