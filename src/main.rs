#[macro_use] extern crate clap;

use std::{io, fs, thread, env, str::FromStr};
use clap::ArgMatches;
use secp256k1::{Secp256k1, All, PublicKey, Error as Secp256k1Error};
use lbpbp::commitments::{base::*, secp256k1::*};
use bitcoin::hashes::{hex::*, sha256, sha256d, ripemd160, hash160, HashEngine, Hash, Hmac, HmacEngine};
use std::process::exit;

enum Verbosity {
    Silent = 0,
    Laconic = 1,
    Verbose = 2
}
use Verbosity::*;

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

fn main() -> io::Result<()> {
    fn conv_pubkey (pubkey_str: &str) -> Result<PublicKey, String> {
        match PublicKey::from_str(pubkey_str) {
            Ok(pubkey) => Ok(pubkey),
            Err(_) => Err(String::from("The provided string does not corresponds to a pubkey"))
        }
    };
    fn conv_digest (hexdec_str: &str) -> Result<sha256::Hash, String> {
        match sha256::Hash::from_hex(hexdec_str) {
            Ok(hexdec) => Ok(hexdec),
            Err(_) => Err(String::from("The provided string does not corresponds to a pubkey")),
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
            (about: "computes Bitcoin tagged hash for the given MSG")
            (@arg hex: -h --hex "Signifies that the message is a hexadecimal string")
            (@arg TAG: +required "The tag for the hash (usually protocol-specific)")
            (@arg MSG: +required  "Source message for the tagged hash")
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
    ).get_matches();

    unsafe {
        CONFIG.verbosity = Verbosity::from(matches.occurrences_of("verbose"));
    }

    match matches.subcommand() {
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
        ("bp-tagged256", Some(sm)) => bp_tagged256(
            sm.value_of("TAG").unwrap(),
            &*conv_hexmsg(sm.value_of("MSG").unwrap()).unwrap()
        ),
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
        _ => (),
    }

    Ok(())
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

fn bp_tagged256(tag: &str, msg: &[u8]) {
    vprintln!(Laconic, "Computing tagged digest");
    let tag_hash = sha256::Hash::hash(&tag.as_bytes()).to_vec();
    let mut s = tag_hash.clone();
    s.extend(&tag_hash);
    s.extend(msg);
    let digest = sha256::Hash::hash(&s[..]);
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
    let EC: Secp256k1<All> = Secp256k1::new();

    let mut tweaked = pubkey.clone();
    tweaked.add_exp_assign(&EC, &digest[..]).expect("Must not fail");

    println!("{}", tweaked.to_hex());
}

fn pubkey_commit(msg: &[u8], pubkey: PublicKey) {
    vprintln!(Laconic, "Committing to the message by tweaking the provided public key");

    let mut tweaked_pubkey = pubkey.clone();

    let engine = TweakEngine::new();
    let digest = sha256::Hash::hash(msg);
    let _ = engine.commit(&TweakSource(digest), &mut tweaked_pubkey);

    println!("{}", tweaked_pubkey.to_hex());
}
