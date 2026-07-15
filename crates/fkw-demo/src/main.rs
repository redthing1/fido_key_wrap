mod access;
mod app;
mod cli;
mod container;
mod inspection;
mod interaction;
mod storage;

use std::{
    io::{self, Read, Write},
    path::Path,
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::Parser;
use fido_key_wrap::{ApplicationId, RecipientId};
use zeroize::Zeroizing;

use crate::{
    access::ProductionKeyAccess,
    app::{APPLICATION_ID, Application, RecipientChoice, TerminalUi, parameters_text, policy_text},
    cli::{Access, Cli, Command, KdfOptions},
    inspection::{AuthenticatorInspection, Inspection, ProductionInspection},
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
    if let Command::Check { details } = cli.command {
        return check(details, &mut ProductionInspection);
    }

    if let Command::New { file, .. } = &cli.command {
        storage::ensure_absent(file)?;
    }

    let application_id = ApplicationId::new(APPLICATION_ID.to_owned())?;
    let mut access =
        ProductionKeyAccess::new(application_id.clone(), Box::new(TerminalInteraction));
    let mut ui = TerminalUi;
    let mut application = Application::new(application_id, &mut access, &mut ui);

    let mut output = io::stdout().lock();
    dispatch(
        cli.command,
        &mut application,
        &mut output,
        &mut read_plaintext,
    )
}

trait CommandApplication {
    fn create(
        &mut self,
        file: &Path,
        access: Access,
        label: String,
        kdf: KdfOptions,
        plaintext: &[u8],
    ) -> Result<RecipientId>;
    fn open(&mut self, file: &Path, recipient: Option<&str>) -> Result<Zeroizing<Vec<u8>>>;
    fn recipients(&mut self, file: &Path) -> Result<Vec<RecipientChoice>>;
    fn add_recipient(
        &mut self,
        file: &Path,
        using: Option<&str>,
        access: Access,
        label: &str,
        kdf: KdfOptions,
    ) -> Result<RecipientId>;
    fn remove_recipient(
        &mut self,
        file: &Path,
        recipient: &str,
        using: Option<&str>,
    ) -> Result<RecipientChoice>;
    fn rewrap_passphrase(
        &mut self,
        file: &Path,
        recipient: &str,
        using: Option<&str>,
        kdf: KdfOptions,
    ) -> Result<RecipientId>;
    fn verify_managed_recipient(
        &mut self,
        file: &Path,
        recipient: &str,
        using: Option<&str>,
    ) -> Result<RecipientChoice>;
    fn retire_managed_recipient(
        &mut self,
        file: &Path,
        recipient: &str,
        using: Option<&str>,
        confirmed: bool,
    ) -> Result<(RecipientChoice, bool)>;
    fn rotate_root(
        &mut self,
        file: &Path,
        using: Option<&str>,
        access: Access,
        label: String,
        kdf: KdfOptions,
        confirmed: bool,
    ) -> Result<RecipientId>;
}

impl CommandApplication for Application<'_> {
    fn create(
        &mut self,
        file: &Path,
        access: Access,
        label: String,
        kdf: KdfOptions,
        plaintext: &[u8],
    ) -> Result<RecipientId> {
        Application::create(self, file, access, label, kdf, plaintext)
    }

    fn open(&mut self, file: &Path, recipient: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
        Application::open(self, file, recipient)
    }

    fn recipients(&mut self, file: &Path) -> Result<Vec<RecipientChoice>> {
        Application::recipients(self, file)
    }

    fn add_recipient(
        &mut self,
        file: &Path,
        using: Option<&str>,
        access: Access,
        label: &str,
        kdf: KdfOptions,
    ) -> Result<RecipientId> {
        Application::add_recipient(self, file, using, access, label, kdf)
    }

    fn remove_recipient(
        &mut self,
        file: &Path,
        recipient: &str,
        using: Option<&str>,
    ) -> Result<RecipientChoice> {
        Application::remove_recipient(self, file, recipient, using)
    }

    fn rewrap_passphrase(
        &mut self,
        file: &Path,
        recipient: &str,
        using: Option<&str>,
        kdf: KdfOptions,
    ) -> Result<RecipientId> {
        Application::rewrap_passphrase(self, file, recipient, using, kdf)
    }

    fn verify_managed_recipient(
        &mut self,
        file: &Path,
        recipient: &str,
        using: Option<&str>,
    ) -> Result<RecipientChoice> {
        Application::verify_managed_recipient(self, file, recipient, using)
    }

    fn retire_managed_recipient(
        &mut self,
        file: &Path,
        recipient: &str,
        using: Option<&str>,
        confirmed: bool,
    ) -> Result<(RecipientChoice, bool)> {
        Application::retire_managed_recipient(self, file, recipient, using, confirmed)
    }

    fn rotate_root(
        &mut self,
        file: &Path,
        using: Option<&str>,
        access: Access,
        label: String,
        kdf: KdfOptions,
        confirmed: bool,
    ) -> Result<RecipientId> {
        Application::rotate_root(self, file, using, access, label, kdf, confirmed)
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch(
    command: Command,
    application: &mut dyn CommandApplication,
    output: &mut dyn Write,
    read_new_plaintext: &mut dyn FnMut() -> Result<Zeroizing<Vec<u8>>>,
) -> Result<()> {
    match command {
        Command::Check { .. } => unreachable!("check returned before constructing key access"),
        Command::New {
            file,
            access,
            label,
            kdf,
        } => {
            let plaintext = read_new_plaintext()?;
            application.create(&file, access, label, kdf, &plaintext)?;
            writeln!(output, "created {}", safe_path(&file))?;
            writeln!(
                output,
                "back up this file; recovery factors alone do not contain the note"
            )?;
        }
        Command::Open { file, recipient } => {
            let plaintext = application.open(&file, recipient.as_deref())?;
            output
                .write_all(&plaintext)
                .context("failed to write the decrypted note")?;
            output.flush().context("failed to flush standard output")?;
        }
        Command::Recipients { file, details } => {
            let recipients = application.recipients(&file)?;
            for recipient in recipients {
                writeln!(
                    output,
                    "{} — {}",
                    recipient.label,
                    policy_text(recipient.policy)
                )?;
                if details {
                    writeln!(output, "  id: {}", recipient.id)?;
                    if let Some(parameters) = parameters_text(recipient.parameters) {
                        writeln!(output, "  argon2id: {parameters}")?;
                    }
                }
            }
            writeln!(
                output,
                "recipient metadata is unauthenticated until the note is opened"
            )?;
        }
        Command::AddRecipient {
            file,
            access,
            label,
            using,
            kdf,
        } => {
            application.add_recipient(&file, using.as_deref(), access, &label, kdf)?;
            writeln!(output, "added {label} as an alternative recovery route")?;
        }
        Command::RemoveRecipient {
            file,
            recipient,
            using,
        } => {
            let removed = application.remove_recipient(&file, &recipient, using.as_deref())?;
            writeln!(output, "removed {}", removed.label)?;
            writeln!(
                output,
                "old complete file copies still contain the removed route"
            )?;
        }
        Command::VerifyKey {
            file,
            recipient,
            using,
        } => {
            let verified =
                application.verify_managed_recipient(&file, &recipient, using.as_deref())?;
            writeln!(
                output,
                "verified {} on the selected security key",
                verified.label
            )?;
        }
        Command::RetireKey {
            file,
            recipient,
            using,
            yes,
        } => {
            let (retired, final_route) =
                application.retire_managed_recipient(&file, &recipient, using.as_deref(), yes)?;
            writeln!(
                output,
                "retired {} from the selected security key",
                retired.label
            )?;
            if final_route {
                writeln!(output, "this file has no working recovery route")?;
            } else {
                writeln!(output, "removed the retired route from the current file")?;
            }
        }
        Command::ChangePassphrase {
            file,
            recipient,
            using,
            kdf,
        } => {
            application.rewrap_passphrase(&file, &recipient, using.as_deref(), kdf)?;
            writeln!(output, "changed the application passphrase for {recipient}")?;
            writeln!(
                output,
                "the root is unchanged; old file copies retain the old passphrase"
            )?;
        }
        Command::RotateRoot {
            file,
            access,
            label,
            using,
            yes,
            kdf,
        } => {
            application.rotate_root(&file, using.as_deref(), access, label.clone(), kdf, yes)?;
            writeln!(
                output,
                "rotated the root and installed {label} as the only recovery route"
            )?;
            writeln!(
                output,
                "old complete file copies remain independently usable"
            )?;
        }
    }
    Ok(())
}

fn check(details: bool, inspection: &mut dyn AuthenticatorInspection) -> Result<()> {
    match inspection.inspect()? {
        Inspection::SupportUnavailable => {
            println!("security-key support is unavailable in this build");
            println!("passphrase-only commands remain fully available");
        }
        Inspection::Reports(reports) if reports.is_empty() => {
            println!("no inspectable security key was found");
            println!("no pin, touch, credential, or prf operation was requested");
        }
        Inspection::Reports(reports) => {
            for (index, report) in reports.iter().enumerate() {
                println!(
                    "{}. {}",
                    index + 1,
                    if report.compatible {
                        "compatible"
                    } else {
                        "not compatible with every security-key access policy"
                    }
                );
                if details {
                    for issue in &report.issues {
                        println!("   {issue}");
                    }
                }
            }
            println!("no pin, touch, credential, or prf operation was requested");
        }
    }
    Ok(())
}

fn read_plaintext() -> Result<Zeroizing<Vec<u8>>> {
    let mut plaintext = Zeroizing::new(Vec::new());
    io::stdin()
        .take(u64::try_from(container::MAX_NOTE_BYTES + 1).expect("note bound fits u64"))
        .read_to_end(&mut plaintext)
        .context("failed to read note plaintext from standard input")?;
    Ok(plaintext)
}

fn safe_path(path: &Path) -> String {
    let text = path.display().to_string();
    if text.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    }) {
        "[unsafe path]".to_owned()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use fido_key_wrap::RecipientPolicy;

    use super::*;

    struct FakeInspection(Inspection);

    impl AuthenticatorInspection for FakeInspection {
        fn inspect(&mut self) -> Result<Inspection> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn check_has_a_hardware_free_unavailable_path() {
        check(true, &mut FakeInspection(Inspection::SupportUnavailable)).unwrap();
    }

    #[test]
    fn unsafe_paths_are_not_reflected() {
        assert_eq!(safe_path(Path::new("safe-note.fkd")), "safe-note.fkd");
        assert_eq!(safe_path(Path::new("bad\npath")), "[unsafe path]");
        assert_eq!(safe_path(Path::new("bad\u{202e}path")), "[unsafe path]");
    }

    #[test]
    fn parsed_management_commands_reach_their_application_operations() {
        let commands = [
            ["fkw", "recipients", "note.fkd", "--details"].as_slice(),
            [
                "fkw",
                "add-recipient",
                "note.fkd",
                "--access",
                "fido-presence",
                "--label",
                "backup",
                "--using",
                "primary",
            ]
            .as_slice(),
            [
                "fkw",
                "change-passphrase",
                "note.fkd",
                "primary",
                "--using",
                "backup",
            ]
            .as_slice(),
            [
                "fkw",
                "remove-recipient",
                "note.fkd",
                "backup",
                "--using",
                "primary",
            ]
            .as_slice(),
            [
                "fkw",
                "verify-key",
                "note.fkd",
                "managed",
                "--using",
                "primary",
            ]
            .as_slice(),
            [
                "fkw",
                "retire-key",
                "note.fkd",
                "managed",
                "--using",
                "primary",
                "--yes",
            ]
            .as_slice(),
            [
                "fkw",
                "rotate-root",
                "note.fkd",
                "--access",
                "fido-user-verification",
                "--label",
                "replacement",
                "--using",
                "primary",
                "--yes",
            ]
            .as_slice(),
        ];
        let mut application = RecordingApplication::default();
        let mut output = Vec::new();
        let mut plaintext_reads = 0;
        let mut unexpected_plaintext = || {
            plaintext_reads += 1;
            Ok(Zeroizing::new(b"not used".to_vec()))
        };

        for arguments in commands {
            let command = Cli::try_parse_from(arguments).unwrap().command;
            dispatch(
                command,
                &mut application,
                &mut output,
                &mut unexpected_plaintext,
            )
            .unwrap();
        }

        assert_eq!(
            application.calls,
            [
                "recipients",
                "add",
                "change-passphrase",
                "remove",
                "verify-key",
                "retire-key",
                "rotate"
            ]
        );
        assert_eq!(plaintext_reads, 0);
        let output = String::from_utf8(output).unwrap();
        assert_management_output(&output);
    }

    fn assert_management_output(output: &str) {
        assert!(output.contains("recipient metadata is unauthenticated"));
        assert!(output.contains("added backup as an alternative recovery route"));
        assert!(output.contains("changed the application passphrase for primary"));
        assert!(output.contains("removed backup"));
        assert!(output.contains("verified managed"));
        assert!(output.contains("retired managed"));
        assert!(output.contains("installed replacement as the only recovery route"));
    }

    #[derive(Default)]
    struct RecordingApplication {
        calls: Vec<&'static str>,
    }

    impl RecordingApplication {
        fn recipient() -> RecipientId {
            RecipientId::from_str(
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            )
            .unwrap()
        }

        fn choice(label: &str) -> RecipientChoice {
            RecipientChoice {
                id: Self::recipient(),
                label: label.to_owned(),
                policy: RecipientPolicy::Passphrase,
                parameters: None,
            }
        }
    }

    impl CommandApplication for RecordingApplication {
        fn create(
            &mut self,
            _file: &Path,
            _access: Access,
            _label: String,
            _kdf: KdfOptions,
            _plaintext: &[u8],
        ) -> Result<RecipientId> {
            self.calls.push("new");
            Ok(Self::recipient())
        }

        fn open(&mut self, _file: &Path, _recipient: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
            self.calls.push("open");
            Ok(Zeroizing::new(Vec::new()))
        }

        fn recipients(&mut self, _file: &Path) -> Result<Vec<RecipientChoice>> {
            self.calls.push("recipients");
            Ok(vec![Self::choice("primary")])
        }

        fn add_recipient(
            &mut self,
            _file: &Path,
            _using: Option<&str>,
            _access: Access,
            _label: &str,
            _kdf: KdfOptions,
        ) -> Result<RecipientId> {
            self.calls.push("add");
            Ok(Self::recipient())
        }

        fn remove_recipient(
            &mut self,
            _file: &Path,
            recipient: &str,
            _using: Option<&str>,
        ) -> Result<RecipientChoice> {
            self.calls.push("remove");
            Ok(Self::choice(recipient))
        }

        fn rewrap_passphrase(
            &mut self,
            _file: &Path,
            _recipient: &str,
            _using: Option<&str>,
            _kdf: KdfOptions,
        ) -> Result<RecipientId> {
            self.calls.push("change-passphrase");
            Ok(Self::recipient())
        }

        fn verify_managed_recipient(
            &mut self,
            _file: &Path,
            recipient: &str,
            _using: Option<&str>,
        ) -> Result<RecipientChoice> {
            self.calls.push("verify-key");
            Ok(Self::choice(recipient))
        }

        fn retire_managed_recipient(
            &mut self,
            _file: &Path,
            recipient: &str,
            _using: Option<&str>,
            _confirmed: bool,
        ) -> Result<(RecipientChoice, bool)> {
            self.calls.push("retire-key");
            Ok((Self::choice(recipient), false))
        }

        fn rotate_root(
            &mut self,
            _file: &Path,
            _using: Option<&str>,
            _access: Access,
            _label: String,
            _kdf: KdfOptions,
            _confirmed: bool,
        ) -> Result<RecipientId> {
            self.calls.push("rotate");
            Ok(Self::recipient())
        }
    }
}
