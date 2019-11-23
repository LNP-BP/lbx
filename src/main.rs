#[macro_use] extern crate clap;

use std::{io, fs, thread, env, str::FromStr};
use clap::*;
use secp256k1::PublicKey;
use lbpbp::commitments::{base::*, secp256k1::*};
use bitcoin::hashes::{sha256, HashEngine, Hash, hex::ToHex};
use std::process::exit;

fn main() -> io::Result<()> {
    let matches = clap_app!(lbx =>
        (@setting SubcommandRequiredElseHelp)
        (version: "0.1.0")
        (author: "Dr Maxim Orlovsky <orlovsky@pandoracore.com>")
        (about: "LNP/BP technology command-line utility")
        (@subcommand pubkey_commit =>
            (about: "commits to the given MSG by tweaking provided public key")
            (@arg MSG: +required "Source message to commit to")
            (@arg PUBKEY: +required "Original public key for the tweak")
        )
    ).get_matches();

    match matches.subcommand() {
        ("pubkey_commit", sm) => pubkey_commit(sm.unwrap()),
        _ => (),
    }

    Ok(())
}

fn pubkey_commit(matches: &ArgMatches) {
    eprintln!("Committing to the message by tweaking the provided public key");

    let msg = matches.value_of("MSG").unwrap();
    let pubkey = PublicKey::from_str(matches.value_of("PUBKEY").unwrap()).unwrap_or_else(|_| {
        eprintln!("The provided PUBKEY is invalid, exiting");
        exit(1);
    });
    let mut tweaked_pubkey = pubkey.clone();

    let engine = TweakEngine::new();
    let digest = sha256::Hash::hash(msg.as_bytes());
    let _ = engine.commit(&TweakSource(digest), &mut tweaked_pubkey);

    println!("{}", tweaked_pubkey.to_hex());
}
