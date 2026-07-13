use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "fkw",
    about = "protect an encrypted note with fido2 credentials",
    version,
    after_help = "examples:\n  fkw check\n  fkw new note.fkw\n  fkw open note.fkw\n  fkw add-key note.fkw backup"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// inspect connected fido authenticator capabilities.
    Check {
        /// show fido capability details.
        #[arg(short, long)]
        details: bool,
    },

    /// create an encrypted note; read one hidden line by default.
    New {
        /// encrypted note to create.
        path: PathBuf,

        /// read from a file; use - for multiline standard input.
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// require an additional application passphrase.
        #[arg(short, long)]
        passphrase: bool,

        /// require touch without a pin after setup.
        #[arg(short = 't', long)]
        touch_only: bool,
    },

    /// open and print an encrypted note.
    Open {
        /// encrypted note to open.
        path: PathBuf,

        /// recipient label or prefix such as id:0123abcd.
        #[arg(short, long)]
        key: Option<String>,
    },

    /// show the recipients that can recover a note's root key.
    Keys {
        /// encrypted note to inspect.
        path: PathBuf,

        /// include public recipient ids.
        #[arg(short, long)]
        details: bool,
    },

    /// add a recipient on a backup authenticator.
    AddKey {
        /// encrypted note to update.
        path: PathBuf,

        /// short lowercase label for the backup recipient.
        label: String,

        /// current recipient label or prefix such as id:0123abcd.
        #[arg(short, long)]
        key: Option<String>,

        /// require an application passphrase for the backup.
        #[arg(short, long)]
        passphrase: bool,

        /// require touch without a pin after setup.
        #[arg(short = 't', long)]
        touch_only: bool,
    },

    /// remove a recipient.
    RemoveKey {
        /// encrypted note to update.
        path: PathBuf,

        /// label or prefix such as id:0123abcd.
        recipient: String,

        /// recipient label or prefix such as id:0123abcd.
        #[arg(short, long)]
        key: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_commands_stay_short() {
        let cli = Cli::try_parse_from(["fkw", "new", "note.fkw", "-p", "-t"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::New {
                passphrase: true,
                touch_only: true,
                ..
            }
        ));

        let cli = Cli::try_parse_from(["fkw", "open", "note.fkw", "-k", "backup"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Open { key: Some(key), .. } if key == "backup"
        ));
    }

    #[test]
    fn backup_label_is_positional() {
        let cli = Cli::try_parse_from(["fkw", "add-key", "note.fkw", "off-site"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::AddKey { label, .. } if label == "off-site"
        ));
    }
}
