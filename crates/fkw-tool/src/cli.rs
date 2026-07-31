use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "fkw",
    about = "seal a small secret behind one recovery policy",
    after_help = "examples:\n  printf 'secret' | fkw seal secret.fkw -a passphrase\n  fkw unseal secret.fkw\n  fkw inspect secret.fkw"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum Access {
    Passphrase,
    FidoPresence,
    FidoUserVerification,
    FidoPresencePlusPassphrase,
    FidoUserVerificationPlusPassphrase,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// seal standard input into a new file.
    Seal {
        /// destination to create.
        file: PathBuf,

        /// factors required to unseal the secret.
        #[arg(short, long, value_enum)]
        access: Access,
    },

    /// write the unsealed secret to standard output.
    Unseal {
        /// sealed file to open.
        file: PathBuf,
    },

    /// show unauthenticated access metadata.
    Inspect {
        /// sealed file to inspect.
        file: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_is_small_and_access_is_explicit() {
        assert!(
            Cli::try_parse_from(["fkw", "seal", "secret.fkw", "--access", "passphrase"]).is_ok()
        );

        for access in [
            "fido-presence",
            "fido-user-verification",
            "fido-presence-plus-passphrase",
            "fido-user-verification-plus-passphrase",
        ] {
            assert!(
                Cli::try_parse_from(["fkw", "seal", "secret.fkw", "--access", access]).is_ok(),
                "failed to parse {access}"
            );
        }

        assert!(Cli::try_parse_from(["fkw", "seal", "secret.fkw"]).is_err());
        assert!(Cli::try_parse_from(["fkw", "unseal", "secret.fkw"]).is_ok());
        assert!(Cli::try_parse_from(["fkw", "inspect", "secret.fkw"]).is_ok());
    }
}
