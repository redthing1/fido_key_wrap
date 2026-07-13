mod cli;
mod container;
mod interaction;
mod storage;

use std::{
    borrow::Cow,
    fs::File,
    io::{self, IsTerminal, Read, Write},
    path::Path,
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use fido_key_wrap::{
    ApplicationId, AuthenticatorIssue, AuthenticatorReport, Enrollment, KeyEnvelope, KeyProtector,
    RecipientId, RecipientPolicy, TokenPolicy, policy,
};
use zeroize::Zeroizing;

use crate::{
    cli::{Cli, Command},
    container::{EncryptedNote, NoteFile},
    interaction::{TerminalInteraction, display_text},
};

const DEFAULT_APPLICATION_ID: &str = "demo.fido-key-wrap.local";
const MAX_NOTE_BYTES: usize = 1024 * 1024;

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
    match cli.command {
        Command::Check { details } => check(details),
        Command::New {
            path,
            passphrase,
            touch_only,
            input,
        } => new_note(&NewOptions {
            path: &path,
            passphrase,
            touch_only,
            input: input.as_deref(),
        }),
        Command::Open { path, key } => open(&path, key.as_deref()),
        Command::Keys { path, details } => keys(&path, details),
        Command::AddKey {
            path,
            label,
            key,
            passphrase,
            touch_only,
        } => add_key(&path, key.as_deref(), &label, touch_only, passphrase),
        Command::RemoveKey {
            path,
            recipient,
            key,
        } => remove_key(&path, &recipient, key.as_deref()),
    }
}

fn check(details: bool) -> Result<()> {
    let application_id = parse_application_id(DEFAULT_APPLICATION_ID)?;
    let protector = KeyProtector::system(application_id);
    let reports = protector.inspect_authenticators()?;
    for (index, report) in reports.iter().enumerate() {
        let manufacturer = report
            .manufacturer()
            .map_or_else(|| Cow::Borrowed("unknown"), display_text);
        let product = report
            .product()
            .map_or_else(|| Cow::Borrowed("authenticator"), display_text);
        println!("{}. {manufacturer} {product}", index + 1);
        println!(
            "   {}",
            if report.compatible() {
                "ready"
            } else {
                "not ready"
            }
        );
        if let Some(issue) = report.issue() {
            println!("   {}", issue_text(issue));
        }
        if details {
            println!("   fido2: {}", yes_no(report.fido2()));
            println!("   pin supported: {}", yes_no(report.pin_supported()));
            println!("   pin configured: {}", yes_no(report.pin_configured()));
            println!(
                "   touch-only mode: {}",
                yes_no(report.compatible() && !report.always_uv())
            );
            println!("   hmac-secret: {}", yes_no(report.hmac_secret()));
            println!(
                "   credential protection: {}",
                yes_no(report.credential_protection())
            );
            println!("   es256: {}", yes_no(report.es256()));
            println!("   always-uv: {}", yes_no(report.always_uv()));
        }
    }
    println!();
    println!("no pin, touch, or credential operation was requested");
    if reports.is_empty() {
        bail!("no fido authenticator detected");
    }
    if !reports.iter().any(AuthenticatorReport::compatible) {
        bail!("no compatible fido authenticator is ready");
    }
    Ok(())
}

struct NewOptions<'a> {
    path: &'a Path,
    passphrase: bool,
    touch_only: bool,
    input: Option<&'a Path>,
}

fn new_note(options: &NewOptions<'_>) -> Result<()> {
    let _lock = storage::NoteLock::acquire(options.path)?;
    storage::ensure_absent(options.path)?;
    let application_id = parse_application_id(DEFAULT_APPLICATION_ID)?;
    let note = read_note(options.input)?;
    let enrollment = enrollment("main".to_owned(), options.touch_only, options.passphrase)?;
    let mut protector = KeyProtector::system(application_id.clone());
    let mut interaction = TerminalInteraction::new();

    eprintln!("enrolling the main recipient");
    let (root, envelope, _recipient) = protector.provision(enrollment, &mut interaction)?;
    let envelope_bytes = envelope.encode();
    let encrypted_note =
        EncryptedNote::encrypt(&root, &application_id, &envelope_bytes, note.as_ref())?;
    let container = NoteFile::new(envelope_bytes, encrypted_note)?;
    storage::create_atomic(options.path, &container.encode())?;

    println!("created {}", safe_path(options.path));
    println!();
    println!("back up this file; the authenticator cannot recover the note without it");
    Ok(())
}

fn open(path: &Path, requested: Option<&str>) -> Result<()> {
    let loaded = load(path)?;
    let recipient = choose_key(&loaded.envelope, requested)?;
    let mut protector = KeyProtector::system(loaded.envelope.application_id().clone());
    let mut interaction = TerminalInteraction::new();
    let root = protector.unlock(&loaded.envelope, recipient, &mut interaction)?;
    let note = loaded.container.note().decrypt(
        &root,
        loaded.envelope.application_id(),
        loaded.container.envelope_bytes(),
    )?;
    let note = std::str::from_utf8(note.as_ref()).context("the decrypted note is not utf-8")?;
    print!("{note}");
    if !note.ends_with('\n') {
        println!();
    }
    io::stdout().flush().context("failed to write the note")?;
    Ok(())
}

fn keys(path: &Path, details: bool) -> Result<()> {
    let loaded = load(path)?;
    println!("recipients for {}:", safe_path(path));
    println!();
    for (index, key) in loaded.envelope.recipients().iter().enumerate() {
        println!(
            "  {}. {} — {}",
            index + 1,
            display_text(key.label()),
            policy_text(key.policy())
        );
        if details {
            println!("     id:{}", key.id());
        }
    }
    println!();
    println!("recipient labels and policies are authenticated only when the note is opened");
    Ok(())
}

fn add_key(
    path: &Path,
    current: Option<&str>,
    label: &str,
    touch_only: bool,
    passphrase: bool,
) -> Result<()> {
    let enrollment = enrollment(label.to_owned(), touch_only, passphrase)?;
    let _lock = storage::NoteLock::acquire(path)?;
    let mut loaded = load(path)?;
    if loaded
        .envelope
        .recipients()
        .iter()
        .any(|key| key.label() == label)
    {
        bail!("a recipient with that label already exists");
    }
    let current = choose_key(&loaded.envelope, current)?;
    let application_id = loaded.envelope.application_id().clone();
    let mut protector = KeyProtector::system(application_id.clone());
    let mut interaction = TerminalInteraction::new();

    eprintln!("unlocking the root key with the current recipient");
    let root = protector.unlock(&loaded.envelope, current, &mut interaction)?;
    loaded
        .container
        .note()
        .decrypt(&root, &application_id, loaded.container.envelope_bytes())?;

    confirm_backup_authenticator()?;
    let new_recipient =
        protector.add_recipient(&mut loaded.envelope, &root, enrollment, &mut interaction)?;

    let staged_envelope_bytes = loaded.envelope.encode();
    let staged_envelope = KeyEnvelope::decode(&staged_envelope_bytes)
        .context("the updated note failed an internal consistency check")?;
    drop(root);
    eprintln!("verifying the backup recipient before saving");
    let verified_root = protector.unlock(&staged_envelope, new_recipient, &mut interaction)?;
    let note = loaded.container.note().decrypt(
        &verified_root,
        &application_id,
        loaded.container.envelope_bytes(),
    )?;

    let encrypted_note = EncryptedNote::encrypt(
        &verified_root,
        &application_id,
        &staged_envelope_bytes,
        note.as_ref(),
    )?;
    let staged = NoteFile::new(staged_envelope_bytes, encrypted_note)?;
    storage::replace_atomic_if_unchanged(path, &loaded.original_bytes, &staged.encode())?;
    println!("added and verified recipient: {}", display_text(label));
    println!();
    println!("store the backup authenticator separately");
    println!("the program cannot prove that two recipients use different authenticators");
    Ok(())
}

fn remove_key(path: &Path, selector: &str, current: Option<&str>) -> Result<()> {
    let _lock = storage::NoteLock::acquire(path)?;
    let mut loaded = load(path)?;
    let recipient = resolve_key(&loaded.envelope, selector)?;
    let removed_label = loaded
        .envelope
        .recipients()
        .into_iter()
        .find(|key| key.id() == recipient)
        .map_or("recipient", |key| key.label())
        .to_owned();
    let current = choose_key(&loaded.envelope, current)?;
    let application_id = loaded.envelope.application_id().clone();
    let mut protector = KeyProtector::system(application_id.clone());
    let mut interaction = TerminalInteraction::new();

    let root = protector.unlock(&loaded.envelope, current, &mut interaction)?;
    let note = loaded.container.note().decrypt(
        &root,
        &application_id,
        loaded.container.envelope_bytes(),
    )?;
    protector.remove_recipient(&mut loaded.envelope, &root, recipient)?;
    let staged_envelope_bytes = loaded.envelope.encode();
    KeyEnvelope::decode(&staged_envelope_bytes)
        .context("the updated note failed an internal consistency check")?;
    let encrypted_note = EncryptedNote::encrypt(
        &root,
        &application_id,
        &staged_envelope_bytes,
        note.as_ref(),
    )?;
    let staged = NoteFile::new(staged_envelope_bytes, encrypted_note)?;
    storage::replace_atomic_if_unchanged(path, &loaded.original_bytes, &staged.encode())?;

    println!("removed recipient: {}", display_text(&removed_label));
    println!();
    println!("older copies of this file may still recover through that recipient");
    Ok(())
}

struct LoadedNote {
    original_bytes: Vec<u8>,
    container: NoteFile,
    envelope: KeyEnvelope,
}

fn load(path: &Path) -> Result<LoadedNote> {
    let bytes = storage::read_private(path)?;
    let container = NoteFile::decode(&bytes)?;
    let envelope = KeyEnvelope::decode(container.envelope_bytes())?;
    Ok(LoadedNote {
        original_bytes: bytes,
        container,
        envelope,
    })
}

fn choose_key(envelope: &KeyEnvelope, requested: Option<&str>) -> Result<RecipientId> {
    if let Some(requested) = requested {
        return resolve_key(envelope, requested);
    }
    let keys = envelope.recipients();
    if keys.len() == 1 {
        return Ok(keys[0].id());
    }
    if !io::stdin().is_terminal() {
        let labels = keys
            .iter()
            .map(|key| display_text(key.label()))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("choose a recipient with -k <label>; available: {labels}");
    }

    eprintln!("choose a recipient:");
    for (index, key) in keys.iter().enumerate() {
        eprintln!(
            "  {}. {} — {}",
            index + 1,
            display_text(key.label()),
            policy_text(key.policy())
        );
    }
    eprint!("key [1-{}]: ", keys.len());
    io::stderr().flush().context("failed to show key choices")?;
    let mut choice = String::new();
    io::stdin()
        .read_line(&mut choice)
        .context("failed to read the key choice")?;
    let index = choice
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|index| (1..=keys.len()).contains(index))
        .context("choose one of the listed numbers")?;
    Ok(keys[index - 1].id())
}

fn resolve_key(envelope: &KeyEnvelope, selector: &str) -> Result<RecipientId> {
    let keys = envelope.recipients();
    if let Some(prefix) = selector.strip_prefix("id:") {
        if prefix.len() < 8 || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!(
                "recipient id prefixes use id: followed by at least eight hexadecimal characters"
            );
        }
        let prefix = prefix.to_ascii_lowercase();
        let matching = keys
            .iter()
            .filter(|key| key.id().to_string().starts_with(&prefix))
            .collect::<Vec<_>>();
        return match matching.as_slice() {
            [key] => Ok(key.id()),
            [_, _, ..] => bail!("that recipient id prefix is ambiguous; provide more characters"),
            [] => bail!("no recipient matches that id prefix"),
        };
    }

    let labeled = keys
        .iter()
        .filter(|key| key.label() == selector)
        .collect::<Vec<_>>();
    match labeled.as_slice() {
        [key] => return Ok(key.id()),
        [_, _, ..] => bail!("more than one recipient has that label; use an id:<prefix> selector"),
        [] => {}
    }
    bail!("no recipient matches that label")
}

fn enrollment(label: String, touch_only: bool, passphrase: bool) -> Result<Enrollment> {
    validate_recipient_label(&label)?;
    let mut recipient_policy: RecipientPolicy = if touch_only {
        policy::presence()
    } else {
        policy::user_verified()
    };
    if passphrase {
        recipient_policy = recipient_policy.and_passphrase();
    }
    Enrollment::new(label, recipient_policy).map_err(Into::into)
}

fn validate_recipient_label(label: &str) -> Result<()> {
    if label.is_empty()
        || label.len() > 32
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || label.starts_with('-')
        || label.ends_with('-')
    {
        bail!(
            "recipient labels use 1-32 lowercase letters, numbers, or hyphens and must begin and end with a letter or number"
        );
    }
    Ok(())
}

fn read_note(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    let limit = u64::try_from(MAX_NOTE_BYTES + 1).expect("note limit fits u64");
    let mut bytes = Zeroizing::new(Vec::new());
    match path {
        Some(path) if path == Path::new("-") => {
            io::stdin()
                .take(limit)
                .read_to_end(&mut bytes)
                .context("failed to read the note")?;
        }
        Some(path) => {
            File::open(path)
                .with_context(|| format!("failed to open note input {}", safe_path(path)))?
                .take(limit)
                .read_to_end(&mut bytes)
                .context("failed to read the note")?;
        }
        None if io::stdin().is_terminal() => {
            let value = rpassword::prompt_password("note (input hidden): ")
                .context("failed to read the note")?;
            bytes = Zeroizing::new(value.into_bytes());
        }
        None => {
            io::stdin()
                .take(limit)
                .read_to_end(&mut bytes)
                .context("failed to read the note")?;
        }
    }
    validate_note(&bytes)?;
    Ok(bytes)
}

fn validate_note(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_NOTE_BYTES {
        bail!("the note is larger than 1 mib");
    }
    if bytes.is_empty() {
        bail!("the note is empty");
    }
    std::str::from_utf8(bytes).context("the note must be utf-8")?;
    Ok(())
}

fn parse_application_id(value: &str) -> Result<ApplicationId> {
    ApplicationId::new(value.to_owned()).map_err(Into::into)
}

fn confirm_backup_authenticator() -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("adding a backup requires an interactive terminal");
    }
    eprintln!();
    eprintln!("unplug the current authenticator and connect the backup authenticator");
    eprintln!("press enter when ready");
    let mut confirmation = String::new();
    let read = io::stdin()
        .read_line(&mut confirmation)
        .context("failed to confirm the authenticator swap")?;
    if read == 0 {
        bail!("backup authenticator swap was not confirmed");
    }
    Ok(())
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

const fn issue_text(issue: AuthenticatorIssue) -> &'static str {
    match issue {
        AuthenticatorIssue::Busy => "another program is using this authenticator",
        AuthenticatorIssue::TimedOut => "the authenticator did not respond in time",
        AuthenticatorIssue::Inaccessible => "the authenticator is not accessible",
        _ => "the authenticator could not be inspected",
    }
}

const fn policy_text(policy: RecipientPolicy) -> &'static str {
    match (policy.token_policy(), policy.has_passphrase()) {
        (TokenPolicy::Presence, false) => "touch only",
        (TokenPolicy::Presence, true) => "touch + passphrase",
        (TokenPolicy::UserVerified, false) => "pin + touch",
        (TokenPolicy::UserVerified, true) => "pin + touch + passphrase",
    }
}

fn safe_path(path: &Path) -> String {
    display_text(&path.to_string_lossy()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &str = include_str!("../../../test-vectors/v1-token-only.txt");

    fn vector_envelope() -> KeyEnvelope {
        let encoded = VECTOR
            .lines()
            .find_map(|line| line.strip_prefix("envelope="))
            .unwrap();
        let bytes = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid vector hex"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect::<Vec<_>>();
        KeyEnvelope::decode(&bytes).unwrap()
    }

    #[test]
    fn recipient_selector_distinguishes_labels_and_id_prefixes() {
        let envelope = vector_envelope();
        let expected = envelope.recipients()[0].id();
        assert_eq!(resolve_key(&envelope, "primary").unwrap(), expected);
        assert_eq!(resolve_key(&envelope, "id:E499E42D").unwrap(), expected);
        assert!(resolve_key(&envelope, "missing").is_err());
        assert!(resolve_key(&envelope, "E499E42D").is_err());
        assert!(resolve_key(&envelope, "id:e499").is_err());
    }

    #[test]
    fn policy_language_is_plain() {
        assert_eq!(policy_text(policy::presence()), "touch only");
        assert_eq!(
            policy_text(policy::user_verified().and_passphrase()),
            "pin + touch + passphrase"
        );
    }

    #[test]
    fn recipient_labels_are_short_and_terminal_safe() {
        assert!(validate_recipient_label("off-site").is_ok());
        assert!(validate_recipient_label("Backup").is_err());
        assert!(validate_recipient_label("bad name").is_err());
        assert!(validate_recipient_label("-backup").is_err());
    }

    #[test]
    fn note_validation_rejects_empty_oversize_and_non_utf8_input() {
        assert!(validate_note(b"one line").is_ok());
        assert!(validate_note(b"").is_err());
        assert!(validate_note(&vec![b'x'; MAX_NOTE_BYTES + 1]).is_err());
        assert!(validate_note(&[0xff]).is_err());
    }
}
