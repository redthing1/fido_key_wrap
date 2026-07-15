use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "fkw",
    about = "protect a small encrypted note with an application passphrase or security key",
    after_help = "examples:\n  printf 'a private note\\n' | fkw new note.fkd -a application-passphrase\n  fkw open note.fkd\n  fkw recipients note.fkd"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum Access {
    ApplicationPassphrase,
    FidoPresence,
    FidoUserVerification,
    FidoManagedPresence,
    FidoManagedUserVerification,
    FidoPresencePlusPassphrase,
    FidoUserVerificationPlusPassphrase,
}

#[derive(Args, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct KdfOptions {
    /// argon2 memory in mib; supply with --passes and --lanes.
    #[arg(long)]
    pub(crate) memory_mib: Option<u32>,

    /// argon2 pass count; supply with --memory-mib and --lanes.
    #[arg(long)]
    pub(crate) passes: Option<u32>,

    /// argon2 lane count; supply with --memory-mib and --passes.
    #[arg(long)]
    pub(crate) lanes: Option<u8>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// inspect security-key support without requesting a pin or touch.
    Check {
        /// show individual compatibility issues.
        #[arg(short, long)]
        details: bool,
    },

    /// create an encrypted note from standard input.
    New {
        /// encrypted .fkd file to create.
        file: PathBuf,

        /// exact recovery policy for the first recipient.
        #[arg(short, long, value_enum)]
        access: Access,

        /// presentation label for the first recipient.
        #[arg(short, long, default_value = "primary")]
        label: String,

        #[command(flatten)]
        kdf: KdfOptions,
    },

    /// decrypt a note to standard output.
    Open {
        /// encrypted .fkd file to open.
        file: PathBuf,

        /// exact id, unambiguous id prefix, or unique label.
        #[arg(short, long)]
        recipient: Option<String>,
    },

    /// list unauthenticated recipient metadata.
    Recipients {
        /// encrypted .fkd file to inspect.
        file: PathBuf,

        /// include canonical recipient ids and passphrase work.
        #[arg(short, long)]
        details: bool,
    },

    /// add an alternative recovery route.
    AddRecipient {
        /// encrypted .fkd file to update.
        file: PathBuf,

        /// recovery policy for the new recipient.
        #[arg(short, long, value_enum)]
        access: Access,

        /// presentation label for the new recipient.
        #[arg(short, long)]
        label: String,

        /// recipient used to authorize the mutation.
        #[arg(short = 'u', long)]
        using: Option<String>,

        #[command(flatten)]
        kdf: KdfOptions,
    },

    /// remove one recovery route; old file copies remain usable.
    RemoveRecipient {
        /// encrypted .fkd file to update.
        file: PathBuf,

        /// recipient to remove.
        recipient: String,

        /// recipient used to authorize the mutation.
        #[arg(short = 'u', long)]
        using: Option<String>,
    },

    /// verify that one managed security-key route is present.
    VerifyKey {
        /// encrypted .fkd file to inspect.
        file: PathBuf,

        /// managed recipient to verify.
        recipient: String,

        /// recipient used to authenticate the envelope.
        #[arg(short = 'u', long)]
        using: Option<String>,
    },

    /// permanently retire one managed security-key route.
    RetireKey {
        /// encrypted .fkd file whose route will be retired.
        file: PathBuf,

        /// managed recipient to retire.
        recipient: String,

        /// recipient used to authenticate the envelope.
        #[arg(short = 'u', long)]
        using: Option<String>,

        /// skip the destructive-operation confirmation.
        #[arg(long)]
        yes: bool,
    },

    /// change the application passphrase for one recipient.
    ChangePassphrase {
        /// encrypted .fkd file to update.
        file: PathBuf,

        /// passphrase-bearing recipient to change.
        recipient: String,

        /// recipient used to authorize the mutation.
        #[arg(short = 'u', long)]
        using: Option<String>,

        #[command(flatten)]
        kdf: KdfOptions,
    },

    /// replace the root and every current route with one new route.
    RotateRoot {
        /// encrypted .fkd file to update.
        file: PathBuf,

        /// recovery policy for the replacement recipient.
        #[arg(short, long, value_enum)]
        access: Access,

        /// presentation label for the replacement recipient.
        #[arg(short, long, default_value = "primary")]
        label: String,

        /// recipient used to unlock the current note.
        #[arg(short = 'u', long)]
        using: Option<String>,

        /// skip the destructive-operation confirmation.
        #[arg(long)]
        yes: bool,

        #[command(flatten)]
        kdf: KdfOptions,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_access_strings_and_short_surface_parse() {
        for access in [
            "application-passphrase",
            "fido-presence",
            "fido-user-verification",
            "fido-managed-presence",
            "fido-managed-user-verification",
            "fido-presence-plus-passphrase",
            "fido-user-verification-plus-passphrase",
        ] {
            let cli = Cli::try_parse_from(["fkw", "new", "note.fkd", "--access", access]);
            assert!(cli.is_ok(), "failed to parse {access}");
        }

        assert!(
            Cli::try_parse_from(["fkw", "new", "note.fkd", "--access", "fido-managed"]).is_err()
        );

        let cli = Cli::try_parse_from([
            "fkw",
            "new",
            "note.fkd",
            "-a",
            "application-passphrase",
            "-l",
            "primary",
        ]);
        assert!(cli.is_ok());

        let cli = Cli::try_parse_from([
            "fkw",
            "change-passphrase",
            "note.fkd",
            "primary",
            "-u",
            "primary",
            "--memory-mib",
            "64",
            "--passes",
            "3",
            "--lanes",
            "1",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::ChangePassphrase { .. }));
    }

    #[test]
    fn new_requires_an_explicit_access_policy() {
        assert!(Cli::try_parse_from(["fkw", "new", "note.fkd"]).is_err());
    }
}
