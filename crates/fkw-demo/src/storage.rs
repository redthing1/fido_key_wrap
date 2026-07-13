use std::{
    fmt::Write as FmtWrite,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

const PRIVATE_MODE: u32 = 0o600;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) struct NoteLock {
    _file: File,
}

impl NoteLock {
    pub(crate) fn acquire(note: &Path) -> Result<Self> {
        let parent = note.parent().unwrap_or_else(|| Path::new("."));
        let file_name = note.file_name().context("the note path has no file name")?;
        let mut lock_name = std::ffi::OsString::from(".");
        lock_name.push(file_name);
        lock_name.push(".fkw-lock");
        let lock_path = parent.join(lock_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(PRIVATE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&lock_path)
            .context("failed to open the note lock")?;
        let metadata = file.metadata().context("failed to inspect the note lock")?;
        if !metadata.file_type().is_file() || metadata.mode() & 0o777 != PRIVATE_MODE {
            bail!("the note lock must be a mode-0600 regular file");
        }
        <File as fs2::FileExt>::try_lock_exclusive(&file)
            .context("another fkw operation is using this note")?;
        Ok(Self { _file: file })
    }
}

pub(crate) fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("the destination already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect the destination"),
    }
}

pub(crate) fn read_private(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("failed to open the note file")?;
    let metadata = file.metadata().context("failed to inspect the note file")?;
    if !metadata.file_type().is_file() {
        bail!("the note path is not a regular file");
    }
    if metadata.mode() & 0o777 != PRIVATE_MODE {
        bail!("the note file must have mode 0600");
    }
    if metadata.len() > MAX_FILE_BYTES {
        bail!("the encrypted note file is too large");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read the note file")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        bail!("the encrypted note file is too large");
    }
    Ok(bytes)
}

pub(crate) fn create_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_size(bytes)?;
    let temporary = write_temporary(path, bytes)?;
    let result = (|| {
        fs::hard_link(&temporary, path).context("failed to save the new note")?;
        let _ = fs::remove_file(&temporary);
        sync_parent(path).context("the note was saved, but its directory sync failed")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn replace_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_size(bytes)?;
    let temporary = write_temporary(path, bytes)?;
    let result = (|| {
        fs::rename(&temporary, path).context("failed to replace the note")?;
        sync_parent(path).context("the note was saved, but its directory sync failed")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn replace_atomic_if_unchanged(
    path: &Path,
    expected: &[u8],
    replacement: &[u8],
) -> Result<()> {
    if read_private(path)? != expected {
        bail!("the note changed during this operation; no update was saved");
    }
    replace_atomic(path, replacement)
}

fn write_temporary(destination: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    for _ in 0..32 {
        let mut random = [0u8; 12];
        getrandom::fill(&mut random).context("secure randomness is unavailable")?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            write!(suffix, "{byte:02x}").expect("writing to a String cannot fail");
        }
        let temporary = parent.join(format!(".fkw-{suffix}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_MODE)
            .open(&temporary)
        {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(bytes)
                        .context("failed to write the temporary note")?;
                    file.sync_all().context("failed to sync the temporary note")
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&temporary);
                }
                result?;
                return Ok(temporary);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("failed to create a temporary note"),
        }
    }
    bail!("failed to allocate a temporary note name")
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("failed to sync the note directory")
}

fn ensure_size(bytes: &[u8]) -> Result<()> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        bail!("the encrypted note file is too large");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            for _ in 0..32 {
                let mut random = [0u8; 12];
                getrandom::fill(&mut random).unwrap();
                let name = random.map(|byte| format!("{byte:02x}")).concat();
                let path = std::env::temp_dir().join(format!("fkw-demo-test-{name}"));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("failed to create test directory: {error}"),
                }
            }
            panic!("failed to allocate test directory")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn atomic_create_and_replace_preserve_private_mode() {
        let directory = TestDirectory::new();
        let note = directory.0.join("note.fkw");
        create_atomic(&note, b"first").unwrap();
        assert_eq!(read_private(&note).unwrap(), b"first");
        assert_eq!(fs::metadata(&note).unwrap().mode() & 0o777, PRIVATE_MODE);

        assert!(create_atomic(&note, b"must not replace").is_err());
        assert_eq!(read_private(&note).unwrap(), b"first");

        replace_atomic(&note, b"second").unwrap();
        assert_eq!(read_private(&note).unwrap(), b"second");
        assert_eq!(fs::metadata(&note).unwrap().mode() & 0o777, PRIVATE_MODE);
    }

    #[test]
    fn private_reader_rejects_links_and_permissive_files() {
        let directory = TestDirectory::new();
        let target = directory.0.join("target");
        let link = directory.0.join("link");
        fs::write(&target, b"not secret").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_private(&link).is_err());

        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&target).is_err());

        let note = directory.0.join("note.fkw");
        let lock = directory.0.join(".note.fkw.fkw-lock");
        symlink(&target, &lock).unwrap();
        assert!(NoteLock::acquire(&note).is_err());
    }

    #[test]
    fn lock_excludes_concurrent_mutations_and_conflicts_are_detected() {
        let directory = TestDirectory::new();
        let note = directory.0.join("note.fkw");
        create_atomic(&note, b"first").unwrap();
        let lock = NoteLock::acquire(&note).unwrap();
        assert!(NoteLock::acquire(&note).is_err());
        drop(lock);
        let _lock = NoteLock::acquire(&note).unwrap();

        replace_atomic_if_unchanged(&note, b"first", b"second").unwrap();
        assert!(replace_atomic_if_unchanged(&note, b"first", b"third").is_err());
        assert_eq!(read_private(&note).unwrap(), b"second");
    }
}
