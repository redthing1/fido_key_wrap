use fido_key_wrap as core;
use pyo3::PyClass;
use pyo3::{exceptions::PyAttributeError, prelude::*};

use crate::{
    errors::Cancelled,
    prompts::{PassphrasePrompt, PinPrompt, SelectionPrompt, TouchPrompt},
    types::take_exact_bytearray,
};

pub struct PythonInteraction {
    object: Py<PyAny>,
    pending: Option<PyErr>,
}

impl PythonInteraction {
    pub fn new(object: Py<PyAny>) -> Self {
        Self {
            object,
            pending: None,
        }
    }

    pub fn take_pending(&mut self) -> Option<PyErr> {
        self.pending.take()
    }

    fn finish<T>(
        &mut self,
        result: Result<T, CallbackFailure>,
    ) -> Result<T, core::InteractionError> {
        match result {
            Ok(value) => Ok(value),
            Err(CallbackFailure::Unsupported) => Err(core::InteractionError::Unsupported),
            Err(CallbackFailure::Python(error)) => {
                let cancelled = Python::attach(|py| error.is_instance_of::<Cancelled>(py));
                self.pending = Some(error);
                if cancelled {
                    Err(core::InteractionError::Cancelled)
                } else {
                    Err(core::InteractionError::Failed)
                }
            }
        }
    }

    fn call_unit<T>(&self, name: &str, prompt: T) -> Result<(), CallbackFailure>
    where
        T: PyClass<BaseType = PyAny>,
    {
        Python::attach(|py| {
            let callback = callback(py, self.object.bind(py), name)?;
            let prompt = Py::new(py, prompt).map_err(CallbackFailure::Python)?;
            let result = callback.call1((prompt,)).map_err(CallbackFailure::Python)?;
            require_none(&result).map_err(CallbackFailure::Python)
        })
    }

    fn call_passphrase(
        &self,
        prompt: &core::PassphrasePrompt,
    ) -> Result<core::Passphrase, CallbackFailure> {
        Python::attach(|py| {
            let callback = callback(py, self.object.bind(py), "request_passphrase")?;
            let prompt =
                Py::new(py, PassphrasePrompt::from(prompt)).map_err(CallbackFailure::Python)?;
            let value = callback.call1((prompt,)).map_err(CallbackFailure::Python)?;
            let mut bytes = take_exact_bytearray(py, &value, core::Passphrase::MAX_BYTES, || {
                crate::errors::map_error(py, &core::Error::InvalidPassphrase)
            })
            .map_err(CallbackFailure::Python)?;
            let owned = std::mem::take(&mut *bytes);
            core::Passphrase::new(owned)
                .map_err(|error| CallbackFailure::Python(crate::errors::map_error(py, &error)))
        })
    }

    fn call_pin(&self, prompt: &core::PinPrompt) -> Result<core::Pin, CallbackFailure> {
        Python::attach(|py| {
            let callback = callback(py, self.object.bind(py), "request_pin")?;
            let prompt = Py::new(py, PinPrompt::from(prompt)).map_err(CallbackFailure::Python)?;
            let value = callback.call1((prompt,)).map_err(CallbackFailure::Python)?;
            take_pin(py, &value).map_err(CallbackFailure::Python)
        })
    }
}

fn require_none(value: &Bound<'_, PyAny>) -> PyResult<()> {
    if value.is_none() {
        Ok(())
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "interaction callback must return None",
        ))
    }
}

fn take_pin(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<core::Pin> {
    let bytes = take_exact_bytearray(py, value, core::Pin::MAX_BYTES, || {
        crate::errors::map_error(py, &core::Error::InvalidPin)
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| crate::errors::map_error(py, &core::Error::InvalidPin))?;
    core::Pin::new(text.to_owned()).map_err(|error| crate::errors::map_error(py, &error))
}

impl core::Interaction for PythonInteraction {
    fn select_authenticator_by_touch(
        &mut self,
        prompt: &core::SelectionPrompt,
    ) -> Result<(), core::InteractionError> {
        let result = self.call_unit(
            "select_authenticator_by_touch",
            SelectionPrompt::from(prompt),
        );
        self.finish(result)
    }

    fn request_pin(
        &mut self,
        prompt: &core::PinPrompt,
    ) -> Result<core::Pin, core::InteractionError> {
        let result = self.call_pin(prompt);
        self.finish(result)
    }

    fn request_passphrase(
        &mut self,
        prompt: &core::PassphrasePrompt,
    ) -> Result<core::Passphrase, core::InteractionError> {
        let result = self.call_passphrase(prompt);
        self.finish(result)
    }

    fn touch_required(&mut self, prompt: &core::TouchPrompt) -> Result<(), core::InteractionError> {
        let result = self.call_unit("touch_required", TouchPrompt::from(prompt));
        self.finish(result)
    }
}

enum CallbackFailure {
    Unsupported,
    Python(PyErr),
}

fn callback<'py>(
    _py: Python<'py>,
    object: &'py Bound<'py, PyAny>,
    name: &str,
) -> Result<Bound<'py, PyAny>, CallbackFailure> {
    match object.getattr(name) {
        Ok(callback) => Ok(callback),
        Err(error) if error.is_instance_of::<PyAttributeError>(object.py()) => {
            Err(CallbackFailure::Unsupported)
        }
        Err(error) => Err(CallbackFailure::Python(error)),
    }
}

#[cfg(test)]
mod tests {
    use pyo3::{exceptions::PyTypeError, types::PyByteArray};

    use super::*;
    use crate::errors::{Error, ErrorCode};

    fn assert_invalid_pin(py: Python<'_>, error: &PyErr) {
        assert!(error.is_instance_of::<Error>(py));
        let code = error.value(py).getattr("code").unwrap();
        let expected = Py::new(py, ErrorCode::InvalidPin).unwrap();
        assert!(code.eq(expected.bind(py)).unwrap());
    }

    #[test]
    fn pin_transfer_clears_and_bounds_every_bytearray() {
        Python::initialize();
        Python::attach(|py| {
            for input in [vec![], vec![0xff], b"12\0".to_vec(), vec![b'x'; 64]] {
                let value = PyByteArray::new(py, &input);
                let error = take_pin(py, value.as_any()).unwrap_err();
                assert_invalid_pin(py, &error);
                assert!(value.to_vec().iter().all(|byte| *byte == 0));
            }

            let value = PyByteArray::new(py, b"1234");
            assert!(take_pin(py, value.as_any()).is_ok());
            assert_eq!(value.to_vec(), vec![0; 4]);
        });
    }

    #[test]
    fn unit_callback_results_must_be_none() {
        Python::initialize();
        Python::attach(|py| {
            assert!(require_none(py.None().bind(py)).is_ok());
            let value = 1_u8.into_pyobject(py).unwrap();
            let error = require_none(value.as_any()).unwrap_err();
            assert!(error.is_instance_of::<PyTypeError>(py));
        });
    }
}
