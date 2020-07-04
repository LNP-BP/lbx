// LNP/BP toolkit
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

#![feature(never_type)]

#[macro_use]
extern crate derive_wrapper;

use clap::Clap;
use log::*;
use std::env;

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
#[clap(
    name = "lbx",
    version = "0.1.0-beta.2",
    author = "Dr Maxim Orlovsky <orlovsky@pandoracore.com>",
    about = "RGB node command-line interface; part of Lightning network protocol suite"
)]
pub struct Opts {
    /// Sets verbosity level; can be used multiple times to increase verbosity
    #[clap(short, long, global = true, parse(from_occurrences))]
    pub verbose: u8,

    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum Command {}

impl Command {
    pub fn exec(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Clone, Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum Error {}

fn main() -> Result<(), Error> {
    let opts = Opts::parse();

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

    opts.command.exec()
}
