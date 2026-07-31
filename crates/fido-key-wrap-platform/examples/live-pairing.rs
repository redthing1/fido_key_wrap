use std::{error::Error as StdError, io};

use fido_key_wrap::{
    ApplicationId, FidoCeremony, Interaction, InteractionError, KeyProtector, Pin, PinPrompt,
    SelectionPrompt, TouchPrompt,
};
use fido_key_wrap_platform::{LocalSecretStore, NativeLocalSecretStore, Removal, StoreError};
use subtle::ConstantTimeEq;

type Result<T> = std::result::Result<T, Box<dyn StdError>>;

fn main() -> Result<()> {
    let application = ApplicationId::new("live-test.fido-key-wrap.local")?;
    let mut protector = KeyProtector::new(application.clone());
    let mut interaction = TerminalInteraction;

    eprintln!("creating a disposable paired-machine recipient");
    let (root, envelope, local) =
        protector.create_root_with_fido_and_local_secret("live test", &mut interaction)?;
    let recipient = local.recipient_id();
    let store = native_store(application);

    if let Err(error) = store.create(recipient, local.secret()) {
        if error == StoreError::StateUncertain {
            if let Err(cleanup_error) = store.remove(recipient) {
                return Err(io::Error::other(format!(
                    "{error}; cleanup for recipient {recipient} also failed: {cleanup_error}"
                ))
                .into());
            }
        }
        return Err(error.into());
    }

    let test = (|| -> Result<()> {
        let stored = store.load(recipient)?;
        eprintln!("opening through the stored machine factor");
        let recovered = protector.unlock_with_fido_and_local_secret(
            &envelope,
            recipient,
            &stored,
            &mut interaction,
        )?;
        let matches =
            root.expose(|expected| recovered.expose(|actual| bool::from(expected.ct_eq(actual))));
        if !matches {
            return Err(io::Error::other("the recovered root did not match").into());
        }
        Ok(())
    })();

    let cleanup = store.remove(recipient);
    match (test, cleanup) {
        (Ok(()), Ok(Removal::Removed)) => {
            eprintln!("paired-machine round trip succeeded; native entry removed");
            Ok(())
        }
        (Ok(()), Ok(Removal::Absent)) => {
            Err(io::Error::other("the native entry disappeared before cleanup").into())
        }
        (Ok(()), Err(error)) => Err(io::Error::other(format!(
            "cleanup for recipient {recipient} failed: {error}"
        ))
        .into()),
        (Err(error), Ok(_)) => Err(error),
        (Err(test_error), Err(cleanup_error)) => Err(io::Error::other(format!(
            "{test_error}; cleanup for recipient {recipient} also failed: {cleanup_error}"
        ))
        .into()),
    }
}

#[cfg(target_os = "macos")]
fn native_store(application: ApplicationId) -> NativeLocalSecretStore {
    NativeLocalSecretStore::macos_login_keychain(application)
}

#[cfg(not(target_os = "macos"))]
fn native_store(application: ApplicationId) -> NativeLocalSecretStore {
    NativeLocalSecretStore::new(application)
}

struct TerminalInteraction;

impl Interaction for TerminalInteraction {
    fn select_authenticator_by_touch(
        &mut self,
        _prompt: &SelectionPrompt,
    ) -> std::result::Result<(), InteractionError> {
        eprintln!("touch the security key you want to test");
        Ok(())
    }

    fn request_pin(&mut self, _prompt: &PinPrompt) -> std::result::Result<Pin, InteractionError> {
        let pin = rpassword::prompt_password("security key pin: ")
            .map_err(|_| InteractionError::Failed)?;
        Pin::new(pin).map_err(|_| InteractionError::Failed)
    }

    fn touch_required(
        &mut self,
        prompt: &TouchPrompt,
    ) -> std::result::Result<(), InteractionError> {
        let action = match prompt.ceremony() {
            FidoCeremony::Enrollment => "create the disposable recipient",
            FidoCeremony::Assertion => "continue the live test",
        };
        eprintln!("touch your security key to {action}");
        Ok(())
    }
}
