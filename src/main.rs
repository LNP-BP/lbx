#[macro_use] extern crate clap;

use std::{io, fs, thread, env, str::FromStr};
use clap::ArgMatches;
use secp256k1::{PublicKey, Error as Secp256k1Error};
use lbpbp::commitments::{base::*, secp256k1::*};
use bitcoin::hashes::{sha256, HashEngine, Hash, hex::ToHex};
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
    let verify_pubkey = |pubkey_str: String| -> Result<PublicKey, String> {
        match PublicKey::from_str(&pubkey_str) {
            Ok(pubkey) => Ok(pubkey),
            Err(_) => Err(String::from("The provided string does not corresponds to a pubkey")),
        }
    };

    let matches = clap_app!(lbx =>
        (@setting SubcommandRequiredElseHelp)
        (version: "0.1.0")
        (author: "Dr Maxim Orlovsky <orlovsky@pandoracore.com>")
        (about: "LNP/BP technology command-line utility")
        (@arg verbose: -v ... #{0,2} "Sets verbosity level")
        (@subcommand ("pubkey-commit") =>
            (about: "commits to the given MSG by tweaking provided public key")
            (@arg hex: -h --hex "Signifies that the message is a hexadecimal string")
            (@arg MSG: +required "Source message to commit to")
            (@arg PUBKEY: +required { verify_pubkey } "Original public key for the tweak")
        )
    ).get_matches();

    unsafe {
        CONFIG.verbosity = Verbosity::from(matches.occurrences_of("verbose"));
    }

    match matches.subcommand() {
        ("pubkey-commit", Some(sm)) =>
            pubkey_commit(
                sm.value_of("MSG").unwrap(),
                PublicKey::from_str(&sm.value_of("PUBKEY").unwrap()).unwrap()
            ),
        _ => (),
    }

    Ok(())
}

fn pubkey_commit(msg: &str, pubkey: PublicKey) {
    vprintln!(Laconic, "Committing to the message by tweaking the provided public key");

    let mut tweaked_pubkey = pubkey.clone();

    let engine = TweakEngine::new();
    let digest = sha256::Hash::hash(msg.as_bytes());
    let _ = engine.commit(&TweakSource(digest), &mut tweaked_pubkey);

    println!("{}", tweaked_pubkey.to_hex());
}
