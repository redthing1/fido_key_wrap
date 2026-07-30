use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    #[cfg(feature = "fido")]
    FidoPresence,
    #[cfg(feature = "fido")]
    FidoUserVerification,
    #[cfg(feature = "fido")]
    FidoPresencePlusPassphrase,
    #[cfg(feature = "fido")]
    FidoUserVerificationPlusPassphrase,
    #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
    MacUserPresence,
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
    /// seal standard input into a new file.
    Seal {
        /// destination to create.
        file: PathBuf,

        /// factors required to unseal the secret.
        #[arg(short, long, value_enum)]
        access: Access,

        #[command(flatten)]
        kdf: KdfOptions,
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

    /// remove this mac's user-presence factor.
    #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
    Forget {
        /// sealed file whose local factor will be removed.
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

        #[cfg(feature = "fido")]
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

        #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
        assert!(
            Cli::try_parse_from(["fkw", "seal", "secret.fkw", "--access", "mac-user-presence"])
                .is_ok()
        );

        assert!(Cli::try_parse_from(["fkw", "seal", "secret.fkw"]).is_err());
        assert!(Cli::try_parse_from(["fkw", "unseal", "secret.fkw"]).is_ok());
        assert!(Cli::try_parse_from(["fkw", "inspect", "secret.fkw"]).is_ok());
        #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
        assert!(Cli::try_parse_from(["fkw", "forget", "secret.fkw"]).is_ok());
    }
}
