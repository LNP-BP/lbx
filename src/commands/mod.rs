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

mod fungible;
mod rgb;

pub use fungible::FungibleCommand;

use clap::Clap;
use lnpbp::bp;

const BPD_RPC_ADDR: &'static str = "tcp://0.0.0.0:66601";
const BPD_PUSH_ADDR: &'static str = "tcp://0.0.0.0:66602";

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
#[clap(
    name = "lbx",
    version = "0.2.0",
    author = "Dr Maxim Orlovsky <orlovsky@pandoracore.com>",
    about = "Command-line tool for working with LNP/BP technology stack"
)]
pub struct Opts {
    /// Sets verbosity level; can be used multiple times to increase verbosity
    #[clap(
        global = true,
        short,
        long,
        min_values = 0,
        max_values = 4,
        parse(from_occurrences)
    )]
    pub verbose: u8,

    /// IPC connection string for bp daemon API
    #[clap(global=true, long, default_value=BPD_RPC_ADDR, env="LBX_BPD_RPC")]
    pub bpd_rpc: String,

    /// IPC connection string for bp daemon push notifications on transaction
    /// updates
    #[clap(global=true, long, default_value=BPD_PUSH_ADDR, env="LBX_BPD_PUSH")]
    pub bpd_push: String,

    /// Network to use
    #[clap(
        global = true,
        short,
        long,
        default_value = "signet",
        env = "LBX_NETWORK"
    )]
    pub network: bp::Network,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum Command {
    /// RGB smart contract manipulation commands
    Rgb20(FungibleCommand),
}
