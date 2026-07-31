mod app;
mod cli;
mod container;
mod interaction;
mod storage;

use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use fido_key_wrap::{ApplicationId, KeyProtector};
use zeroize::Zeroizing;

use crate::{
    app::{APPLICATION_ID, Application, policy_text},
    cli::{Cli, Command},
    interaction::TerminalInteraction,
};

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let application_id = ApplicationId::new(APPLICATION_ID)?;
    let protector = KeyProtector::new(application_id.clone());
    let mut interaction = TerminalInteraction;

    let mut application = Application::new(application_id, protector, &mut interaction);
    dispatch(cli.command, &mut application, &mut io::stdout().lock())
}

fn dispatch(
    command: Command,
    application: &mut Application<'_>,
    output: &mut dyn Write,
) -> Result<()> {
    match command {
        Command::Seal { file, access } => {
            storage::ensure_absent(&file)?;
            let plaintext = read_plaintext(&mut io::stdin().lock())?;
            application.seal(&file, access, &plaintext)?;
            writeln!(output, "sealed")?;
        }
        Command::Unseal { file } => {
            let plaintext = application.unseal(&file)?;
            output
                .write_all(&plaintext)
                .context("failed to write the unsealed secret")?;
            output.flush().context("failed to flush standard output")?;
        }
        Command::Inspect { file } => {
            let inspection = application.inspect(&file)?;
            writeln!(output, "access: {}", policy_text(inspection.policy))?;
            if let Some(parameters) = inspection.parameters {
                let memory = format_memory(parameters.memory_kib());
                writeln!(
                    output,
                    "argon2id: {memory}, {} passes, {} lanes",
                    parameters.passes(),
                    parameters.lanes()
                )?;
            }
            writeln!(
                output,
                "metadata is unauthenticated until the secret is unsealed"
            )?;
        }
    }
    Ok(())
}

fn read_plaintext(input: &mut dyn Read) -> Result<Zeroizing<Vec<u8>>> {
    let limit = u64::try_from(container::MAX_SECRET_BYTES + 1).expect("secret bound fits u64");
    let mut plaintext = Zeroizing::new(Vec::new());
    input
        .take(limit)
        .read_to_end(&mut plaintext)
        .context("failed to read the secret from standard input")?;
    if plaintext.is_empty() || plaintext.len() > container::MAX_SECRET_BYTES {
        bail!("the secret must contain between 1 byte and 1 MiB");
    }
    Ok(plaintext)
}

fn format_memory(memory_kib: u32) -> String {
    if memory_kib % 1024 == 0 {
        format!("{} mib", memory_kib / 1024)
    } else {
        format!("{memory_kib} kib")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_is_exact_and_bounded() {
        assert_eq!(
            read_plaintext(&mut b"\0secret\xff".as_slice())
                .unwrap()
                .as_slice(),
            b"\0secret\xff"
        );
        assert!(read_plaintext(&mut [].as_slice()).is_err());
        assert!(read_plaintext(&mut vec![0; container::MAX_SECRET_BYTES + 1].as_slice()).is_err());
    }

    #[test]
    fn argon2_memory_is_never_rounded() {
        assert_eq!(format_memory(262_144), "256 mib");
        assert_eq!(format_memory(65_540), "65540 kib");
    }
}
