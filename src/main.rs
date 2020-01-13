extern crate rand;
extern crate bigint;
extern crate lnpbp;
#[macro_use] extern crate clap;

use std::{
    io::{self, Read, Write},
    fs::{self, File},
    str::FromStr,
    marker::PhantomData,
    convert::TryInto,
    collections::{HashSet, BTreeMap}
};

use rand::Rng;
use bigint::U256;

use lnpbp::bitcoin::{
    secp256k1::{Secp256k1, All, PublicKey},
    hashes::{hex::*, sha256, sha256d, ripemd160, hash160, HashEngine, Hash, Hmac, HmacEngine},
    PublicKey as BitcoinPublicKey,
    util::psbt::PartiallySignedTransaction,
    consensus::{serialize, deserialize}
};
use lnpbp::{
    AsSlice,
    bp::tagged256::*,
    cmt::{EmbeddedCommitment, PubkeyCommitment},
    csv::serialize::*,
    rgb::{schema::*, schemata::*},
};


enum Verbosity {
    Silent = 0,
    Laconic = 1,
    Verbose = 2
}
use Verbosity::*;
use lnpbp::csv::Commitment;

impl From<u64> for Verbosity {
    fn from(level: u64) -> Self {
        match level {
            0 => Silent,
            1 => Laconic,
            2 => Verbose,
            _ => panic!("Unknown level of verbosity")
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
    verbosity: Verbosity::Silent
};

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


fn main() -> io::Result<()> {
    fn conv_pubkey (pubkey_str: &str) -> Result<PublicKey, String> {
        match PublicKey::from_str(pubkey_str) {
            Ok(pubkey) => Ok(pubkey),
            Err(_) => Err(String::from("The provided string does not corresponds to a pubkey"))
        }
    };
    fn conv_u256 (hexdec_str: &str) -> Result<U256, String> {
        match U256::from_str(hexdec_str) {
            Ok(value) => Ok(value),
            Err(_) => Err(String::from("The provided string does not corresponds to SHA256")),
        }
    };
    fn conv_digest (hexdec_str: &str) -> Result<sha256::Hash, String> {
        match sha256::Hash::from_hex(hexdec_str) {
            Ok(hexdec) => Ok(hexdec),
            Err(_) => Err(String::from("The provided string does not corresponds to SHA256")),
        }
    };
    fn conv_hexmsg (maybe_hexdec_str: &str) -> Result<Box<[u8]>, String> {
        match sha256::Hash::from_hex(maybe_hexdec_str) {
            Ok(hash) => Ok(Box::from(&hash[..])),
            Err(_) => Ok(Box::from(maybe_hexdec_str.as_bytes())),
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
    ).get_matches();

    unsafe {
        CONFIG.verbosity = Verbosity::from(matches.occurrences_of("verbose"));
    }

    match matches.subcommand() {
        ("hex-u8", Some(sm)) => hex_u8(
            &*conv_hexmsg(sm.value_of("HEX").unwrap()).unwrap(),
        ),
        ("ec-inv", Some(sm)) => ec_inv(
            conv_pubkey(sm.value_of("POINT").unwrap()).unwrap()
        ),
        ("ec-add", Some(sm)) => ec_add(
            conv_pubkey(sm.value_of("POINT1").unwrap()).unwrap(),
            conv_pubkey(sm.value_of("POINT2").unwrap()).unwrap(),
        ),
        ("ec-mul", Some(sm)) => ec_mul(
            conv_pubkey(sm.value_of("POINT").unwrap()).unwrap(),
            &*conv_hexmsg(sm.value_of("SCALAR").unwrap()).unwrap()
        ),
        ("bp-ripemd160", Some(sm)) => bp_ripemd160(
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()
        ),
        ("bp-sha256", Some(sm)) => bp_sha256(
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()
        ),
        ("bp-hash160", Some(sm)) => bp_hash160(
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()
        ),
        ("bp-hash256", Some(sm)) => bp_hash256(
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()
        ),
        ("bp-tagged256", Some(sm)) => {
            let tag = sm.value_of("TAG").unwrap();
            if sm.is_present("midstate") {
                bp_tagged256_midstate(tag)
            } else {
                bp_tagged256(
                    tag,
                    &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()
                )
            }
        },
        ("bp-hmacsha", Some(sm)) => bp_hmacsha(
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap(),
            conv_pubkey(sm.value_of("PUBKEY").unwrap()).unwrap()
        ),
        ("bp-tweak", Some(sm)) => bp_tweak(
            conv_digest(sm.value_of("DIGEST").unwrap()).unwrap(),
            conv_pubkey(sm.value_of("PUBKEY").unwrap()).unwrap()
        ),
        ("pubkey-commit", Some(sm)) => pubkey_commit(
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap(),
            conv_pubkey(sm.value_of("PUBKEY").unwrap()).unwrap()
        ),
        ("cv-commit", Some(sm)) => cv_commit(
            value_t!(sm, "FEE", u64).unwrap(),
            conv_u256(sm.value_of("ENTROPY").unwrap()).unwrap(),
            sm.values_of("MSG").unwrap().collect(),
            sm.value_of("TX_INFILE").unwrap(),
            sm.value_of("TX_OUTFILE").unwrap(),
            sm.value_of("CV_OUTFILE").unwrap()
        ),
        ("schema-id", Some(sm)) => schema_id(
            sm.value_of("NAME").expect("required argument"),
            sm.value_of("format").expect("argument has a default value"),
        ),
        ("schema-data", Some(sm)) => schema_data(
            sm.value_of("NAME").expect("required argument"),
            sm.value_of("format").expect("argument has a default value"),
        ),
        _ => (),
    }

    Ok(())
}

fn hex_u8(hex: &[u8]) {
    vprintln!(Laconic, "Converting hexadecimal value into Rust byte array");
    println!("{:?}", hex);
}

fn ec_inv(pubkey: PublicKey) {
    vprintln!(Laconic, "Computing elleptic curve point inversion over x axis");
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
    vprintln!(Laconic, "Computing elleptic curve point multiplication on a scalar");
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
    vprintln!(Laconic, "Computing HMAC-SHA256 digest with the provided public key");
    let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&pubkey.serialize());
    hmac_engine.input(msg);
    let digest = &Hmac::from_engine(hmac_engine);
    println!("{}", digest.to_hex());
}

fn bp_tweak(digest: sha256::Hash, pubkey: PublicKey) {
    vprintln!(Laconic, "Tweaking public key");
    let ec: Secp256k1<All> = Secp256k1::new();

    let mut tweaked = pubkey.clone();
    tweaked.add_exp_assign(&ec, &digest[..]).expect("Must not fail");

    println!("{}", tweaked.to_hex());
}

fn pubkey_commit(msg: &[u8], pubkey: PublicKey) {
    vprintln!(Laconic, "Committing to the message by tweaking the provided public key");
    let msg = Message(msg);
    let commitment = PubkeyCommitment::commit_to(pubkey, msg).unwrap();
    // let commitment: PubkeyCommitment = msg.commit_embed(&pubkey).unwrap();
    println!("{}", commitment.tweaked.to_hex());
}

fn cv_commit(fee: u64, entropy: U256, msgs: Vec<&str>,
             tx_from: &str, tx_to: &str, cv_to: &str) {
    vprintln!(Laconic, "Committing to the set of messages and embedding the commitment into the provided transaction");

    vprintln!(Verbose, "Reading messages...");
    let data: Vec<sha256d::Hash> = msgs.iter().map(|msg_file| {
        vprint!(Verbose, "- {} ... ", msg_file);
        let msg = fs::read_to_string(msg_file)
            .expect(format!("unable to read {}", msg_file).as_str());
        let digest = sha256d::Hash::hash(msg.as_bytes());
        vprintln!(Verbose, "{}", digest.to_hex());
        digest
    }).collect();

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
        match data.iter().find(|hash| {
            U256::from(hash.into_inner()) % U256::from(i) == U256::zero()
        }) {
            Some(hash) => buf.extend_from_slice(&hash[..]),
            None => {
                let r = rng.gen::<u64>().to_le_bytes();
                buf.extend_from_slice(&sha256d::Hash::hash(&r)[..])
            },
        }
    }
    let commitment = sha256d::Hash::hash(&buf[..]);
    vprintln!(Verbose, " success");
    vprintln!(Verbose, "- message: {}", buf.to_hex());
    vprintln!(Verbose, "- LNPBP-4 commitment: {}", commitment.to_hex());

    vprint!(Verbose, "Reading PSBT input file {} ... ", tx_from);
    let mut psbt_file = File::open(tx_from)
        .expect("can't open the file");
    let mut raw_psbt = Vec::new();
    let _ = psbt_file.read_to_end(&mut raw_psbt);
    let mut psbt: PartiallySignedTransaction = deserialize(&raw_psbt)
        .expect("invalid PSBT format");
    vprintln!(Verbose, "success");

    vprintln!(Verbose, "Embedding commitment ...");
    let output_count = psbt.global.unsigned_tx.output.len();
    if output_count == 0 {
        panic!("The provided PSBT transaction has zero outputs, can't commit");
    }
    let output_no = ((entropy + U256::from(fee)) % U256::from(output_count)).low_u64().try_into().unwrap();
    if psbt.outputs.len() < output_no {
        panic!("The provided PSBT transaction has less outputs than required, can't commit");
    }
    vprintln!(Verbose, "- {} outputs found, using output #{} for embedding", output_count, output_no);
    let mut new_outputs = BTreeMap::new();
    for (key, value) in psbt.outputs[output_no].hd_keypaths.iter() {
        let pk_cmt = PubkeyCommitment::commit_to(key.key, commitment)
            .expect("internal error with public key commitment");
        new_outputs.insert(BitcoinPublicKey{ compressed: true, key: pk_cmt.tweaked }, value.clone());
    }
    vprintln!(Verbose, "- {} public key are tweaked", new_outputs.len());
    psbt.outputs[output_no].hd_keypaths = new_outputs;

    vprint!(Verbose, "Writing PSBT with commitment to the file {} ... ", tx_to);
    let mut out_file = File::create(tx_to)
        .expect("can't create output file");
    out_file.write_all(&serialize(&psbt))
        .expect("can't write to output file");
    vprintln!(Verbose, "success");
}

fn schema_id(name: &str, format: &str) {
    vprintln!(Laconic, "Schema ID for {} in {} format", name, format);
    let schema = match name {
        "fungible" => Rgb1::get_schema(),
        "collectible" => Rgb2::get_schema(),
        _ => panic!("Unknown schema name: {}", format),
    };
    println!("{}", schema.schema_id().to_hex());
}

fn schema_data(name: &str, format: &str) {
    vprintln!(Laconic, "Schema ID for {} in {} format", name, format);
    let schema = match name {
        "fungible" => Rgb1::get_schema(),
        "collectible" => Rgb2::get_schema(),
        _ => panic!("Unknown schema name: {}", format),
    };
    println!("{}", storage_serialize(schema).unwrap().to_hex());
}
