use std::{
    fmt::Write as FmtWrite,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

const PRIVATE_MODE: u32 = 0o600;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct CreateError {
    error: anyhow::Error,
    may_be_published: bool,
}

impl CreateError {
    pub(crate) const fn may_be_published(&self) -> bool {
        self.may_be_published
    }

    pub(crate) fn into_error(self) -> anyhow::Error {
        self.error
    }

    pub(crate) fn unpublished(error: anyhow::Error) -> Self {
        Self {
            error,
            may_be_published: false,
        }
    }

    pub(crate) fn uncertain(error: anyhow::Error) -> Self {
        Self {
            error,
            may_be_published: true,
        }
    }
}

pub(crate) fn ensure_absent(path: &Path) -> Result<()> {
    path.file_name()
        .context("the destination path has no file name")?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::metadata(parent).context("failed to inspect the destination directory")?;
    if !parent_metadata.is_dir() {
        bail!("the destination directory is not a directory");
    }
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
        .context("failed to open the secret file")?;
    let metadata = file
        .metadata()
        .context("failed to inspect the secret file")?;
    if !metadata.file_type().is_file() {
        bail!("the secret path is not a regular file");
    }
    if metadata.mode() & 0o7777 != PRIVATE_MODE {
        bail!("the secret file must have mode 0600");
    }
    if metadata.len() > MAX_FILE_BYTES {
        bail!("the encrypted secret file is too large");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read the secret file")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        bail!("the encrypted secret file is too large");
    }
    Ok(bytes)
}

pub(crate) fn create_atomic(path: &Path, bytes: &[u8]) -> Result<(), CreateError> {
    create_atomic_with_sync(path, bytes, sync_parent)
}

fn create_atomic_with_sync(
    path: &Path,
    bytes: &[u8],
    sync: impl FnOnce(&Path) -> Result<()>,
) -> Result<(), CreateError> {
    ensure_size(bytes).map_err(CreateError::unpublished)?;
    let temporary = write_temporary(path, bytes).map_err(CreateError::unpublished)?;
    if let Err(error) = fs::hard_link(&temporary, path).context("failed to save the new secret") {
        let _ = fs::remove_file(&temporary);
        return Err(CreateError::unpublished(error));
    }
    let _ = fs::remove_file(&temporary);
    sync(path)
        .context("the secret was saved, but its directory sync failed")
        .map_err(CreateError::uncertain)
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
                    file.set_permissions(fs::Permissions::from_mode(PRIVATE_MODE))
                        .context("failed to set private temporary-secret permissions")?;
                    file.write_all(bytes)
                        .context("failed to write the temporary secret")?;
                    file.sync_all()
                        .context("failed to sync the temporary secret")
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&temporary);
                }
                result?;
                return Ok(temporary);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("failed to create a temporary secret"),
        }
    }
    bail!("failed to allocate a temporary secret name")
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("failed to sync the secret directory")
}

fn ensure_size(bytes: &[u8]) -> Result<()> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        bail!("the encrypted secret file is too large");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            for _ in 0..32 {
                let mut random = [0u8; 12];
                getrandom::fill(&mut random).unwrap();
                let name = random.map(|byte| format!("{byte:02x}")).concat();
                let path = std::env::temp_dir().join(format!("fkw-tool-test-{name}"));
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
    fn atomic_create_is_exclusive_and_private() {
        let directory = TestDirectory::new();
        let secret = directory.0.join("secret.fkw");
        create_atomic(&secret, b"first").unwrap();
        assert_eq!(read_private(&secret).unwrap(), b"first");
        assert_eq!(fs::metadata(&secret).unwrap().mode() & 0o7777, PRIVATE_MODE);

        assert!(create_atomic(&secret, b"must not replace").is_err());
        assert_eq!(read_private(&secret).unwrap(), b"first");
        assert!(fs::read_dir(&directory.0).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            !(name.starts_with(".fkw-") && name.ends_with(".tmp"))
        }));
    }

    #[test]
    fn destination_is_validated_before_secret_input() {
        let directory = TestDirectory::new();
        assert!(ensure_absent(&directory.0.join("secret.fkw")).is_ok());
        assert!(ensure_absent(&directory.0.join("missing/secret.fkw")).is_err());
        assert!(ensure_absent(Path::new("/")).is_err());
    }

    #[test]
    fn post_publication_sync_failure_is_distinct() {
        let directory = TestDirectory::new();
        let secret = directory.0.join("secret.fkw");
        let error = create_atomic_with_sync(&secret, b"sealed", |_| {
            Err(anyhow::anyhow!("injected sync failure"))
        })
        .expect_err("the injected sync failed");

        assert!(error.may_be_published());
        assert_eq!(read_private(&secret).unwrap(), b"sealed");
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
        fs::set_permissions(&target, fs::Permissions::from_mode(0o4600)).unwrap();
        assert!(read_private(&target).is_err());
    }
}
