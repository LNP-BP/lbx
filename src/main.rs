#[macro_use] extern crate clap;

use std::{io, fs, thread, env};

fn main() -> io::Result<()> {
    eprintln!("\nlbx: LNP/BP technology command-line utility\n");

    let matches = clapp_app!(lbx =>
        (version: "0.1.0")
        (author: "Dr Maxim Orlovsky <orlovsky@pandoracore.com>")
        (about: "LNP/BP technology command-line utility")
        ()
    ).get_matches();

    Ok(())
}
