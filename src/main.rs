// LNP/BP command-line tool
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

extern crate bech32;
extern crate env_logger;
extern crate rand;
extern crate toml;
extern crate yaml;
#[macro_use]
extern crate derive_wrapper;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate lnpbp;

mod commands;
mod error;

pub use commands::*;
pub use error::Error;

use clap::Clap;
use log::LevelFilter;
use std::env;

fn main() -> Result<(), Error> {
    let opts: Opts = Opts::parse();

    if env::var("RUST_LOG").is_err() {
        env::set_var(
            "RUST_LOG",
            match opts.verbose {
                0 => "error",
                1 => "warn",
                2 => "info",
                3 => "debug",
                4 => "trace",
                _ => "trace",
            },
        );
    }
    env_logger::init();
    log::set_max_level(LevelFilter::Trace);

    Ok(())
}
