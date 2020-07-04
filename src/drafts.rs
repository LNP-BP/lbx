extern crate rand;
// TODO: get rid of this external dependency in favour of bitcoin::util::Uint256
extern crate bigint;
#[macro_use]
extern crate lnpbp;
extern crate bech32;
#[macro_use]
extern crate clap;

use core::panic;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::TryInto,
    fs::{self, File},
    io::{self, Read, Write},
    marker::PhantomData,
    str::FromStr,
};

use bech32::*;
use bigint::U256;
use rand::Rng;

use lnpbp::bitcoin::{
    self,
    consensus::{deserialize, serialize},
    hash_types::Txid,
    hashes::{hash160, hex::*, ripemd160, sha256, sha256d, Hash, HashEngine, Hmac, HmacEngine},
    secp256k1::{All, PublicKey, Secp256k1},
    util::psbt::PartiallySignedTransaction,
    util::uint::Uint256,
};
use lnpbp::{
    bp::tagged256::*,
    cmt::{EmbeddedCommitment, PubkeyCommitment},
    csv::serialize::{commitment::*, storage::*},
    rgb::{
        self,
        commit::Identifiable,
        data,
        data::amount,
        schema::Schema,
        schemata::{self, Rgb1, Rgb2, Schemata},
        state,
    },
    AsSlice, Wrapper,
};

enum Verbosity {
    Silent = 0,
    Laconic = 1,
    Verbose = 2,
}
use Verbosity::*;

impl From<u64> for Verbosity {
    fn from(level: u64) -> Self {
        match level {
            0 => Silent,
            1 => Laconic,
            2 => Verbose,
            _ => panic!("Unknown level of verbosity"),
        }
    }
}
impl From<&Verbosity> for i8 {
    fn from(verb: &Verbosity) -> Self {
        match verb {
            Silent => 0,
            Laconic => 1,
            Verbose => 2,
        }
    }
}

struct Config {
    verbosity: Verbosity,
}
static mut CONFIG: Config = Config {
    verbosity: Verbosity::Silent,
};

arg_enum! {
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    #[non_exhaustive]
    pub enum DisplayFormat {
        Bech32,
        Hex,
    }
}

arg_enum! {
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    #[non_exhaustive]
    pub enum DataFormat {
        Rgb,
        Yaml,
        Json,
        Toml,
    }
}

macro_rules! vprint {
    ( $level:expr, $($arg:tt)* ) => ({
        unsafe {
            let lvl = i8::from(&CONFIG.verbosity);
            if lvl - ($level) as i8 >= 0 {
                eprint!($($arg)*);
            }
        }
    })
}
macro_rules! vprintln {
    ( $level:expr, $($arg:tt)* ) => ({
        unsafe {
            let lvl = i8::from(&CONFIG.verbosity);
            if lvl - ($level) as i8 >= 0 {
                eprintln!($($arg)*);
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Message<'a>(&'a [u8]);
impl AsSlice for Message<'_> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BalanceAllocation(Txid, u16, data::Amount);

fn main() -> io::Result<()> {
    fn conv_file_or_stdout(file_name: Option<&str>) -> Result<Box<dyn io::Write>, io::Error> {
        Ok(match file_name {
            Some(file_name) => Box::new(io::BufWriter::new(File::create(file_name)?)),
            None => Box::new(io::stdout()),
        })
    }

    fn conv_txid(txid_str: &str) -> Result<Txid, String> {
        match Txid::from_hex(txid_str) {
            Ok(txid) => Ok(txid),
            Err(_) => Err(String::from(
                "The provided string does not corresponds to a transaction id",
            )),
        }
    };
    fn conv_pubkey(pubkey_str: &str) -> Result<PublicKey, String> {
        match PublicKey::from_str(pubkey_str) {
            Ok(pubkey) => Ok(pubkey),
            Err(_) => Err(String::from(
                "The provided string does not corresponds to a pubkey",
            )),
        }
    };
    fn conv_u256(hexdec_str: &str) -> Result<U256, String> {
        match U256::from_str(hexdec_str) {
            Ok(value) => Ok(value),
            Err(_) => Err(String::from(
                "The provided string does not corresponds to SHA256",
            )),
        }
    };
    fn conv_uint256(val: u64) -> Option<Uint256> {
        Uint256::from_u64(val)
    }
    fn conv_amount(val: u64) -> Option<data::Amount> {
        Some(val)
        // data::Amount::from_u64(val)
    }
    fn conv_digest(hexdec_str: &str) -> Result<sha256::Hash, String> {
        match sha256::Hash::from_hex(hexdec_str) {
            Ok(hexdec) => Ok(hexdec),
            Err(_) => Err(String::from(
                "The provided string does not corresponds to SHA256",
            )),
        }
    };
    fn conv_hexmsg(maybe_hexdec_str: &str) -> Result<Box<[u8]>, String> {
        match sha256::Hash::from_hex(maybe_hexdec_str) {
            Ok(hash) => Ok(Box::from(&hash[..])),
            Err(_) => Ok(Box::from(maybe_hexdec_str.as_bytes())),
        }
    };
    fn conv_schema(name: &str) -> Result<&Schema, String> {
        Ok(match name {
            "fungible" => Rgb1::get_schema(),
            "collectible" => Rgb2::get_schema(),
            _ => Err(format!("Unknown schema name: {}", name))?,
        })
    };
    fn conv_allocations(alloc: &str) -> Result<BalanceAllocation, String> {
    drak    let mut data = alloc.split(":");
        match (data.next(), data.next(), data.next(), data.next()) {
            (Some(a), Some(b), Some(c), None) => Ok(BalanceAllocation(
                conv_txid(a)?,
                u16::from_str(b).map_err(|_| {
                    String::from("Transaction output number must be a 16-bit integer")
                })?,
                conv_amount(
                    u64::from_str(c)
                        .map_err(|_| String::from("Amount must be be a 64-bit integer"))?,
                )
                .expect("We already converted the string to 64-bit number, must not fail now"),
            )),
            _ => Err(String::from("Can't parse asset allocation data")),
        }
    };

    let verify_pubkey = |pubkey_str: String| -> Result<(), String> {
        conv_pubkey(&pubkey_str)?;
        Ok(())
    };
    let verify_digest = |hexdec_str: String| -> Result<(), String> {
        conv_digest(&hexdec_str)?;
        Ok(())
    };

    let matches = clap_app!(lbx =>
        (@setting SubcommandRequiredElseHelp)
        (version: "0.1.0")
        (author: "Dr Maxim Orlovsky <orlovsky@pandoracore.com>")
        (about: "LNP/BP technology command-line utility")
        (@arg verbose: -v ... #{0,2} +global "Sets verbosity level")
        (@subcommand ("hex-u8") =>
            (about: "converts hexadecimal string into Rust [u8] array")
            (@arg HEX: +takes_value +required "source hexadecimal string")
        )
        (@subcommand ("ec-inv") =>
            (about: "inverses Secp256k1 point POINT y value")
            (@arg POINT: +required "Secp256k1 point")
        )
        (@subcommand ("ec-add") =>
            (about: "adds two Secp256k1 points POINT1 and POINT2")
            (@arg POINT1: +required "Secp256k1 point #1")
            (@arg POINT2: +required "Secp256k1 point #2")
        )
        (@subcommand ("ec-mul") =>
            (about: "multiplies Secp256k1 point POINT on a SCALAR")
            (@arg POINT: +required "Secp256k1 point")
            (@arg SCALAR: +required "Scalar for multiplication")
        )
        (@subcommand ("bp-ripemd160") =>
            (about: "computes RIPEMD160 digest for the given MSG")
            (@arg hex: -h --hex "Signifies that the message is a hexadecimal string")
            (@arg MSG: +required "Source message for the digest")
        )
        (@subcommand ("bp-sha256") =>
            (about: "computes SHA-256 digest for the given MSG")
            (@arg hex: -h --hex "Signifies that the message is a hexadecimal string")
            (@arg MSG: +required "Source message for the digest")
        )
        (@subcommand ("bp-hash160") =>
            (about: "computes Bitcoin 160-bit hash digest (SHA256 followed by RIPEMD160) for the given MSG")
            (@arg hex: -h --hex "Signifies that the message is a hexadecimal string")
            (@arg MSG: +required "Source message for the digest")
        )
        (@subcommand ("bp-hash256") =>
            (about: "computes Bitcoin 256-bit hash digest (double-SHA256) for the given MSG")
            (@arg hex: -h --hex "Signifies that the message is a hexadecimal string")
            (@arg MSG: +required "Source message for the digest")
        )
        (@subcommand ("bp-tagged256") =>
            (about: "computes Bitcoin tagged hash for the given MSG or produces a midstate for the TAG")
            (@arg hex: -h --hex requires[MSG] "Signifies that the message is a hexadecimal string")
            (@arg midstate: -m --midstate conflicts_with[hex MSG] "Prints hash engine midstate for the tag without processing the message")
            (@arg TAG: +required "The tag for the hash (usually protocol-specific)")
            (@arg MSG: conflicts_with[midstate]  "Source message for the tagged hash")
        )
        (@subcommand ("bp-hmacsha") =>
            (about: "computes HMAC-SHA256 over the MSG with a provided PUBKEY")
            (@arg hex: -h --hex "Signifies that the message is a hexadecimal string")
            (@arg MSG: +required "Source message for the HMAC procedure")
            (@arg PUBKEY: +required { verify_pubkey } "Public key for HMAC")
        )
        (@subcommand ("bp-tweak") =>
            (about: "tweaks a given PUBKEY with a DIGEST value")
            (@arg DIGEST: +required { verify_digest } "Hexadecimal 256-bit string")
            (@arg PUBKEY: +required { verify_pubkey } "Original public key to be tweaked")
        )
        (@subcommand ("pubkey-commit") =>
            (about: "commits to the given MSG by tweaking provided PUBKEY")
            (@arg hex: -h --hex "Signifies that the message is a hexadecimal string")
            (@arg MSG: +required  "Source message to commit to")
            (@arg PUBKEY: +required { verify_pubkey } "Original public key to be tweaked")
        )
        (@subcommand ("cv-commit") =>
            (about: "commits to a given set of messages and embeds commitment inside a transaction provided by TXFILE")
            (@arg FEE: -f --fee +takes_value +required "A fee (in satoshi) that will be used in the transaction")
            (@arg ENTROPY: -e --entropy +takes_value +required { verify_digest } "Protocol-specific entropy according to LNPBP-3")
            (@arg MSG: -m --message ... +takes_value +required "File containing message to commit to (may be used multiple times)")
            (@arg TX_INFILE: -t --tx +takes_value +required "Transaction data in PSBT format")
            (@arg TX_OUTFILE: +required "File name to save modified transaction")
            (@arg CV_OUTFILE: +required "File name to save extra-transaction data required for the commitment validation")
        )
        (@subcommand ("schema-id") =>
            (about: "returns SchemaID for a given known schema")
            (@arg NAME: * +case_insensitive possible_value[fungible collectible] "Name of the schema")
            (@arg format: -f --format possible_value[hex bech32] default_value[hex] "Output format")
        )
        (@subcommand ("schema-data") =>
            (about: "returns Schema raw data for a given known schema")
            (@arg NAME: * +case_insensitive possible_value[fungible collectible] "Name of the schema")
            (@arg format: -f --format possible_value[hex bech32] default_value[hex] "Output format")
        )
        (@subcommand ("fungible-issue") =>
            (about: "issues a fungible RGB asset")
            (@arg testnet: -T --testnet conflicts_with[signet regtest liquid] "Issues asset on Bitcoin testnet")
            (@arg signet: -S --signet conflicts_with[testnet regtest liquid] "Issues asset on Bitcoin signet network")
            (@arg regtest: -R --regtest conflicts_with[signet testnet liquid] "Issues asset on Bitcoin rigtest network")
            (@arg liquid: -L --liquid conflicts_with[signet regtest testnet] "Issues asset on Liquid network")
            (@arg ticker: <TICKER> "Ticker name for the issued asset")
            (@arg name: <name> "Asset name")
            (@arg balance: <balance> "Balance of the generated assets to allocate")
            (@arg txid: <txid> "Txid to bind the issued asset to")
            (@arg vout: <vout> "Output number within the given transaction if to bind the issued asset to")
            (@arg dest: [FILE] "Genesis output file in RGB format; if no provided prints to stdout")
            (@arg description: -d --description +takes_value "Asset detailed description")
            (@arg precision: -p --precision +takes_value "Precision, i.e. number of digits reserved for fractional part")
            (@arg dust: -l --("dust-limit") [dust] "Dust limit for asset transfers; defaults to no limit")
        )
        (@subcommand ("fungible-transfer") =>
            (about: "transfer a fungible RGB asset to the new owning UTXO")
            (@arg dest: -o --output [FILE] "Transfer proof output file in RGB format; if no provided prints to stdout")
            (@arg alloc: <allocation> ... "New asset allocations in format <txid>:<vout>:<balance>")
        )
    ).get_matches();
    /*
            (@subcommand ("state-genesis") =>
            (about: "generates genesis state file")
            (@arg SCHEMA: * +case_insensitive possible_value[fungible collectible] "Name of the schema")
            (@arg meta: -m --meta +takes_value ... "Adds metadata field in format <>")
            (@arg state: -s --s +takes_value ... "Adds state date bound to a seal")
            (@arg DEST: +takes_value +required "Genesis output file in RGB format")
        )
    */

    unsafe {
        CONFIG.verbosity = Verbosity::from(matches.occurrences_of("verbose"));
    }

    match matches.subcommand() {
        ("hex-u8", Some(sm)) => hex_u8(&*conv_hexmsg(sm.value_of("HEX").unwrap()).unwrap()),
        ("ec-inv", Some(sm)) => ec_inv(conv_pubkey(sm.value_of("POINT").unwrap()).unwrap()),
        ("ec-add", Some(sm)) => ec_add(
            conv_pubkey(sm.value_of("POINT1").unwrap()).unwrap(),
            conv_pubkey(sm.value_of("POINT2").unwrap()).unwrap(),
        ),
        ("ec-mul", Some(sm)) => ec_mul(
            conv_pubkey(sm.value_of("POINT").unwrap()).unwrap(),
            &*conv_hexmsg(sm.value_of("SCALAR").unwrap()).unwrap(),
        ),
        ("bp-ripemd160", Some(sm)) => {
            bp_ripemd160(&*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap())
        }
        ("bp-sha256", Some(sm)) => bp_sha256(&*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()),
        ("bp-hash160", Some(sm)) => bp_hash160(&*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()),
        ("bp-hash256", Some(sm)) => bp_hash256(&*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()),
        ("bp-tagged256", Some(sm)) => {
            let tag = sm.value_of("TAG").unwrap();
            if sm.is_present("midstate") {
                bp_tagged256_midstate(tag)
            } else {
                bp_tagged256(tag, &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap())
            }
        }
        ("bp-hmacsha", Some(sm)) => bp_hmacsha(
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap(),
            conv_pubkey(sm.value_of("PUBKEY").unwrap()).unwrap(),
        ),
        ("bp-tweak", Some(sm)) => bp_tweak(
            conv_digest(sm.value_of("DIGEST").unwrap()).unwrap(),
            conv_pubkey(sm.value_of("PUBKEY").unwrap()).unwrap(),
        ),
        ("pubkey-commit", Some(sm)) => pubkey_commit(
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap(),
            conv_pubkey(sm.value_of("PUBKEY").unwrap()).unwrap(),
        ),
        ("cv-commit", Some(sm)) => cv_commit(
            value_t!(sm, "FEE", u64).unwrap(),
            conv_u256(sm.value_of("ENTROPY").unwrap()).unwrap(),
            sm.values_of("MSG").unwrap().collect(),
            sm.value_of("TX_INFILE").unwrap(),
            sm.value_of("TX_OUTFILE").unwrap(),
            sm.value_of("CV_OUTFILE").unwrap(),
        ),
        ("schema-id", Some(sm)) => {
            let name = sm.value_of("NAME").expect("required argument");
            schema_id(
                name,
                conv_schema(name).expect("must be a predefined value"),
                value_t!(sm, "format", DisplayFormat).expect("argument has a default value"),
            )
        }
        ("schema-data", Some(sm)) => {
            let name = sm.value_of("NAME").expect("required argument");
            schema_data(
                name,
                conv_schema(name).expect("must be a predefined value"),
                value_t!(sm, "format", DisplayFormat).expect("argument has a default value"),
            )
        }
        /*("state-genesis", Some(sm)) => {
            let name = sm.value_of("SCHEMA").expect("required argument");
            state_genesis(
                name,
                conv_schema(name).expect("must be a predefined value"),
                value_t!(sm, "format", DataFormat).expect("argument has a default value"),
                sm.value_of("SRC").expect("required argument"),
                sm.value_of("DEST").expect("required argument")
            )
        },*/
        ("fungible-issue", Some(sm)) => fungible_issue(
            match (
                sm.is_present("testnet"),
                sm.is_present("regtest"),
                sm.is_present("signet"),
                sm.is_present("liquid"),
            ) {
                (true, false, false, false) => schemata::Network::Testnet,
                (false, true, false, false) => schemata::Network::Regtest,
                (false, false, true, false) => schemata::Network::Signet,
                (false, false, false, true) => schemata::Network::Liquid,
                _ => schemata::Network::Mainnet,
            },
            sm.value_of("ticker").expect("required argument"),
            sm.value_of("name").expect("required argument"),
            sm.value_of("description"),
            value_t!(sm, "precision", u8).unwrap_or(0),
            conv_amount(
                value_t!(sm, "balance", u64).expect("argument must be a 256-bit unsigned integer"),
            )
            .unwrap(),
            value_t!(sm, "dust", u64).ok().and_then(conv_uint256),
            conv_txid(sm.value_of("txid").expect("required argument"))
                .expect("not a valid transaction id"),
            value_t!(sm, "vout", u16).expect("argument must be a 16-bit unsigned integer"),
            &mut *conv_file_or_stdout(sm.value_of("dest"))
                .expect("unable to write to the specified file"),
        ),
        ("fungible-transfer", Some(sm)) => {
            let alloc = sm.values_of("alloc").expect("required argument");
            let map: Result<Vec<BalanceAllocation>, String> = alloc.map(conv_allocations).collect();
            fungible_tranfer(
                map.unwrap_or_else(|err| panic!("{:?}", err)),
                &mut *conv_file_or_stdout(sm.value_of("dest"))
                    .expect("unable to write to the specified file"),
            )
        }
        _ => (),
    }

    Ok(())
}

fn hex_u8(hex: &[u8]) {
    vprintln!(Laconic, "Converting hexadecimal value into Rust byte array");
    println!("{:?}", hex);
}

fn ec_inv(pubkey: PublicKey) {
    vprintln!(
        Laconic,
        "Computing elleptic curve point inversion over x axis"
    );
    let new_point = pubkey.clone();
    // TODO: Implement
    println!("{}", new_point.to_hex());
}

fn ec_add(point1: PublicKey, point2: PublicKey) {
    vprintln!(Laconic, "Computing addition of two elleptic curve points");
    let new_point = point1.combine(&point2).unwrap();
    println!("{}", new_point.to_hex());
}

fn ec_mul(pubkey: PublicKey, scalar: &[u8]) {
    vprintln!(
        Laconic,
        "Computing elleptic curve point multiplication on a scalar"
    );
    let ec: Secp256k1<All> = Secp256k1::new();
    let mut new_point = pubkey.clone();
    let _ = new_point.mul_assign(&ec, scalar);
    println!("{}", new_point.to_hex());
}

fn bp_ripemd160(msg: &[u8]) {
    vprintln!(Laconic, "Computing RIPEMD160 digest");
    let digest = ripemd160::Hash::hash(msg);
    println!("{}", digest.to_hex());
}

fn bp_hash160(msg: &[u8]) {
    vprintln!(Laconic, "Computing Bitcoin HASH-160 digest");
    let digest = hash160::Hash::hash(msg);
    println!("{}", digest.to_hex());
}

fn bp_sha256(msg: &[u8]) {
    vprintln!(Laconic, "Computing SHA256 digest");
    let digest = sha256::Hash::hash(msg);
    println!("{}", digest.to_hex());
}

fn bp_hash256(msg: &[u8]) {
    vprintln!(Laconic, "Computing double SHA256 digest");
    let digest = sha256d::Hash::hash(msg);
    println!("{}", digest.to_hex());
}

fn bp_tagged256_midstate(tag: &str) {
    vprintln!(Laconic, "Computing tagged digest");
    let mut engine = sha256::Hash::engine();
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    println!("{:?}", engine.midstate());
}

fn bp_tagged256(tag: &str, msg: &[u8]) {
    vprintln!(Laconic, "Computing tagged digest");
    let digest = tagged256hash(tag, msg.to_vec());
    println!("{}", digest.to_hex());
}

fn bp_hmacsha(msg: &[u8], pubkey: PublicKey) {
    vprintln!(
        Laconic,
        "Computing HMAC-SHA256 digest with the provided public key"
    );
    let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&pubkey.serialize());
    hmac_engine.input(msg);
    let digest = &Hmac::from_engine(hmac_engine);
    println!("{}", digest.to_hex());
}

fn bp_tweak(digest: sha256::Hash, pubkey: PublicKey) {
    vprintln!(Laconic, "Tweaking public key");
    let ec: Secp256k1<All> = Secp256k1::new();

    let mut tweaked = pubkey.clone();
    tweaked
        .add_exp_assign(&ec, &digest[..])
        .expect("Must not fail");

    println!("{}", tweaked.to_hex());
}

fn pubkey_commit(msg: &[u8], pubkey: PublicKey) {
    vprintln!(
        Laconic,
        "Committing to the message by tweaking the provided public key"
    );
    let msg = Message(msg);
    let commitment = PubkeyCommitment::commit_to(pubkey, &msg).unwrap();
    // let commitment: PubkeyCommitment = msg.commit_embed(&pubkey).unwrap();
    println!("{}", commitment.tweaked.to_hex());
}

fn cv_commit(fee: u64, entropy: U256, msgs: Vec<&str>, tx_from: &str, tx_to: &str, cv_to: &str) {
    vprintln!(Laconic, "Committing to the set of messages and embedding the commitment into the provided transaction");

    vprintln!(Verbose, "Reading messages...");
    let data: Vec<sha256d::Hash> = msgs
        .iter()
        .map(|msg_file| {
            vprint!(Verbose, "- {} ... ", msg_file);
            let msg = fs::read_to_string(msg_file)
                .expect(format!("unable to read {}", msg_file).as_str());
            let digest = sha256d::Hash::hash(msg.as_bytes());
            vprintln!(Verbose, "{}", digest.to_hex());
            digest
        })
        .collect();

    let mut n = msgs.len();
    vprint!(Verbose, "Computing LNPBP-4 bloom filter size ...");
    loop {
        let mut uniq = HashSet::new();
        if data.iter().into_iter().all(|hash| {
            let u = U256::from(hash.into_inner());
            uniq.insert(u % U256::from(n))
        }) {
            break;
        }
        vprint!(Verbose, ".");
        n += 1;
    }
    vprintln!(Verbose, " the matching size is found: {}", n);

    vprint!(Verbose, "Preparing LNPBP-4 message ...");
    // TODO: Move the functionality into the library
    let mut buf: Vec<u8> = vec![];
    let mut rng = rand::thread_rng();
    for i in 1..=n {
        match data
            .iter()
            .find(|hash| U256::from(hash.into_inner()) % U256::from(i) == U256::zero())
        {
            Some(hash) => buf.extend_from_slice(&hash[..]),
            None => {
                let r = rng.gen::<u64>().to_le_bytes();
                buf.extend_from_slice(&sha256d::Hash::hash(&r)[..])
            }
        }
    }
    let commitment = sha256d::Hash::hash(&buf[..]);
    vprintln!(Verbose, " success");
    vprintln!(Verbose, "- message: {}", buf.to_hex());
    vprintln!(Verbose, "- LNPBP-4 commitment: {}", commitment.to_hex());

    vprint!(Verbose, "Reading PSBT input file {} ... ", tx_from);
    let mut psbt_file = File::open(tx_from).expect("can't open the file");
    let mut raw_psbt = Vec::new();
    let _ = psbt_file.read_to_end(&mut raw_psbt);
    let mut psbt: PartiallySignedTransaction = deserialize(&raw_psbt).expect("invalid PSBT format");
    vprintln!(Verbose, "success");

    vprintln!(Verbose, "Embedding commitment ...");
    let output_count = psbt.global.unsigned_tx.output.len();
    if output_count == 0 {
        panic!("The provided PSBT transaction has zero outputs, can't commit");
    }
    let output_no = ((entropy + U256::from(fee)) % U256::from(output_count))
        .low_u64()
        .try_into()
        .unwrap();
    if psbt.outputs.len() < output_no {
        panic!("The provided PSBT transaction has less outputs than required, can't commit");
    }
    vprintln!(
        Verbose,
        "- {} outputs found, using output #{} for embedding",
        output_count,
        output_no
    );
    let mut new_outputs = BTreeMap::new();
    for (key, value) in psbt.outputs[output_no].hd_keypaths.iter() {
        let pk_cmt = PubkeyCommitment::commit_to(key.key, &commitment)
            .expect("internal error with public key commitment");
        new_outputs.insert(
            bitcoin::PublicKey {
                compressed: true,
                key: pk_cmt.tweaked,
            },
            value.clone(),
        );
    }
    vprintln!(Verbose, "- {} public key are tweaked", new_outputs.len());
    psbt.outputs[output_no].hd_keypaths = new_outputs;

    vprint!(
        Verbose,
        "Writing PSBT with commitment to the file {} ... ",
        tx_to
    );
    let mut out_file = File::create(tx_to).expect("can't create output file");
    out_file
        .write_all(&serialize(&psbt))
        .expect("can't write to output file");
    vprintln!(Verbose, "success");
}

fn schema_id(name: &str, schema: &Schema, format: DisplayFormat) {
    vprintln!(Laconic, "Schema ID for {} in {} format", name, format);
    let schema_id = schema.schema_id();
    println!(
        "{}",
        match format {
            DisplayFormat::Hex => schema_id.to_hex(),
            DisplayFormat::Bech32 => bech32::encode("rgb", &schema_id.to_base32()).unwrap(),
            _ => String::from("<unknown format>"),
        }
    );
}

fn schema_data(name: &str, schema: &Schema, format: DisplayFormat) {
    vprintln!(Laconic, "Schema ID for {} in {} format", name, format);
    println!("{}", storage_serialize(schema).unwrap().to_hex());
}

/*
fn state_genesis(name: &str, schema: &Schema, format: DataFormat, src: &str, dest: Box<dyn io::Write>) {
    vprintln!(Laconic, "Creating a genesis state from {} using schema {}", src, name);


}
*/

fn fungible_issue(
    network: schemata::Network,
    ticker: &str,
    name: &str,
    descr: Option<&str>,
    precision: u8,
    balance: data::Amount,
    dust: Option<Uint256>,
    txid: Txid,
    vout: u16,
    ostream: &mut dyn io::Write,
) {
    vprintln!(
        Laconic,
        "Issuing fungible asset ${} ({}) with balance of {} allocated to {}:{}",
        ticker,
        name,
        balance,
        txid,
        vout
    );

    // Doing this b/c Bitcoin protocol does not limit to 16-bit indexes, while RGB does
    let vout: u32 = vout as u32;

    vprint!(Verbose, "Initializing genesis state data ... ");
    let ca = amount::Confidential::from(balance);
    let genesis = Rgb1::issue(
        network,
        ticker,
        name,
        descr,
        map! {
            bitcoin::OutPoint{ txid, vout } => ca.commitment
        },
        precision,
        None,
        dust,
    )
    .unwrap_or_else(|err| {
        vprintln!(Verbose, " failed due to an error {:?}", err);
        panic!("Exiting because of error");
    });
    vprintln!(Verbose, "success");

    let asset_id = genesis
        .commitment()
        .expect("Probability of the commitment generation failure is less then negligible");
    let readable_id = bech32::encode(
        format!("rgb:{}:", ticker.to_lowercase()).as_str(),
        asset_id.to_vec().to_base32(),
    )
    .expect("Proper hash has always to be encoded into bech32");
    vprintln!(Verbose, "Issued asset id (genesis state hash) are:");
    vprintln!(Verbose, "\t{}", asset_id.to_hex());
    vprintln!(Verbose, "\t{}", readable_id);

    vprint!(Verbose, "Saving issuance state data ... ");
    genesis.storage_serialize(ostream);
    vprintln!(Verbose, "success");
}

fn fungible_tranfer(allocations: Vec<BalanceAllocation>, ostream: &mut dyn io::Write) {
    let map = allocations.into_iter().fold(
        HashMap::new(), |mut acc, alloc| {
            vprintln!(
                Laconic, "Transferring {} of some asset (the protocol implies no knowledge of its type) to {}:{}",
                alloc.2, alloc.0, alloc.1
            );
            let ca = amount::Confidential::from(alloc.2);
            acc.insert(bitcoin::OutPoint { txid: alloc.0, vout: alloc.1 as u32 }, ca.commitment);
            acc
        }
    );

    let transfer = Rgb1::transfer(map).unwrap_or_else(|err| {
        vprintln!(Verbose, " failed due to an error {:?}", err);
        panic!("Exiting because of error");
    });

    let commitment = transfer
        .commitment()
        .expect("Probability of the commitment generation failure is less then negligible");
    let readable_id = bech32::encode("rgb", commitment.to_vec().to_base32())
        .expect("Proper hash has always to be encoded into bech32");
    vprintln!(
        Verbose,
        "Asset transfer id (state transition commitment) is:"
    );
    vprintln!(Verbose, "\t{}", commitment.to_hex());
    vprintln!(Verbose, "\t{}", readable_id);

    vprint!(Verbose, "Saving transfer data ... ");
    transfer.storage_serialize(ostream);
    vprintln!(Verbose, "success");
}
