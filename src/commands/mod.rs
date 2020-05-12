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
}
