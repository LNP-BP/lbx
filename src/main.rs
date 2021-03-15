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

use clap::Clap;

use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256d, Hash};

#[derive(Clap, Clone, Debug)]
#[clap(
    name = "lbx",
    version = "0.2.0",
    author = "Dr Maxim Orlovsky <orlovsky@pandoracore.com>",
    about = "Command-line tool for working with LNP/BP technology stack"
)]
pub struct Opts {
    /// Sets verbosity level; can be used multiple times to increase verbosity
    #[clap(short, long, global = true, parse(from_occurrences))]
    pub verbose: u8,

    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap, Clone, Debug)]
pub enum Command {
    HexDump {
        /// Use hexadecimal encoding
        #[clap(short = 'x', long, takes_value = false)]
        hex: bool,

        /// Use reversed (big-endian) hex encoding
        #[clap(short, long, takes_value = false)]
        reverse: bool,

        /// Hex value to dump
        value: String,
    },
}

impl Command {
    pub fn exec(self) {
        match self {
            Command::HexDump {
                hex,
                reverse,
                value,
            } => {
                let mut slice = sha256d::Hash::from_hex(&value)
                    .expect("error in the provided hex value")
                    .into_inner();
                if reverse {
                    slice.reverse();
                }
                if hex {
                    print!("[");
                    for byte in &slice {
                        print!("{:#04X}, ", byte);
                    }
                    println!("]");
                } else {
                    println!("[{:03?}]", slice);
                }
            }
        }
    }
}

fn main() {
    let opts = Opts::parse();

    opts.command.exec()
}
