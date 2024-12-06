pub fn build() -> clap::Command {
    use clap::{Arg, ArgAction, Command};

    Command::new(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u16))
                .value_name("NUM")
                .required(true)
                .help("Network port to listen to."),
        )
        .arg(
            Arg::new("vote-with")
                .long("vote-with")
                .action(ArgAction::SetTrue)
                .required(true)
                .conflicts_with("vote-against"),
        )
        .arg(
            Arg::new("vote-against")
                .long("vote-against")
                .action(ArgAction::SetTrue)
                .required(true)
                .conflicts_with("vote-with"),
        )
}
