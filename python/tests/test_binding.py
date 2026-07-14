import copy
import pickle
import sys
import threading
import unittest

import fido_key_wrap as fkw


PARAMETERS = fkw.PassphraseParameters(65_536, 3, 1)


class Passphrases:
    def __init__(self, *values: bytes):
        self._values = iter(values)
        self.returned: list[bytearray] = []
        self.prompts: list[fkw.PassphrasePrompt] = []

    def request_passphrase(self, prompt: fkw.PassphrasePrompt) -> bytearray:
        self.prompts.append(prompt)
        value = bytearray(next(self._values))
        self.returned.append(value)
        return value

    def assert_cleared(self) -> None:
        if not all(not any(value) for value in self.returned):
            raise AssertionError("secret input was not cleared")


class BindingTests(unittest.TestCase):
    def enrollment(self, label: str = "primary") -> fkw.Enrollment:
        return fkw.Enrollment(label, fkw.Policy.PASSPHRASE, PARAMETERS)

    def test_complete_passphrase_lifecycle(self) -> None:
        protector = fkw.KeyProtector("tests.example")
        create = Passphrases(b"first passphrase", b"first passphrase")
        root, original, first = protector.create_root(self.enrollment(), create)
        create.assert_cleared()
        self.assertEqual(
            [prompt.purpose for prompt in create.prompts],
            [fkw.PassphrasePurpose.NEW, fkw.PassphrasePurpose.CONFIRM],
        )
        for prompt in create.prompts:
            self.assertEqual(prompt.operation, fkw.Operation.CREATE_ROOT)
            self.assertEqual(prompt.label, "primary")

        encoded = original.encode()
        decoded = fkw.KeyEnvelope.decode(encoded)
        self.assertEqual(decoded.encode(), encoded)
        self.assertEqual(decoded.application_id, "tests.example")
        self.assertIsInstance(decoded.recipients, tuple)
        self.assertEqual(decoded.recipients[0].id, first)
        self.assertEqual(decoded.recipients[0].policy, fkw.Policy.PASSPHRASE)

        class Unexpected:
            def __getattr__(self, _name):
                raise AssertionError("interaction was requested")

        with self.assertRaises(fkw.Error) as caught:
            fkw.KeyProtector("other.example").unlock(decoded, first, Unexpected())
        self.assertEqual(caught.exception.code, fkw.ErrorCode.APPLICATION_MISMATCH)

        unlock = Passphrases(b"first passphrase")
        recovered = protector.unlock(decoded, first, unlock)
        unlock.assert_cleared()
        self.assertEqual(unlock.prompts[0].operation, fkw.Operation.UNLOCK)
        self.assertEqual(unlock.prompts[0].purpose, fkw.PassphrasePurpose.UNLOCK)
        self.assertEqual(unlock.prompts[0].label, "primary")
        expected = root.export()
        actual = recovered.export()
        self.assertEqual(expected, actual)
        expected[:] = b"\0" * len(expected)
        actual[:] = b"\0" * len(actual)

        add = Passphrases(b"second passphrase", b"second passphrase")
        expanded, second = protector.add_recipient(
            decoded, root, self.enrollment("secondary"), add
        )
        add.assert_cleared()
        self.assertEqual(len(decoded.recipients), 1)
        self.assertEqual(len(expanded.recipients), 2)

        reduced = protector.remove_recipient(expanded, root, first)
        self.assertEqual(len(expanded.recipients), 2)
        self.assertEqual(tuple(item.id for item in reduced.recipients), (second,))

        change = Passphrases(b"replacement", b"replacement")
        changed = protector.rewrap_passphrase(reduced, root, second, change)
        change.assert_cleared()
        self.assertEqual(
            reduced.encode(),
            protector.remove_recipient(expanded, root, first).encode(),
        )

        final_unlock = Passphrases(b"replacement")
        protector.unlock(changed, second, final_unlock)
        final_unlock.assert_cleared()

        old_unlock = Passphrases(b"second passphrase")
        protector.unlock(reduced, second, old_unlock)
        old_unlock.assert_cleared()

        wrong = Passphrases(b"wrong passphrase")
        with self.assertRaises(fkw.Error) as caught:
            protector.unlock(changed, second, wrong)
        self.assertEqual(caught.exception.code, fkw.ErrorCode.UNLOCK_FAILED)
        wrong.assert_cleared()

    def test_secret_transfer_and_root_boundary(self) -> None:
        material = bytearray(range(32))
        root = fkw.RootKey.from_bytearray(material)
        self.assertEqual(material, bytearray(32))
        exported = root.export()
        self.assertEqual(exported, bytearray(range(32)))
        exported[:] = b"\0" * 32
        self.assertEqual(repr(root), "RootKey([REDACTED])")

        protector = fkw.KeyProtector("import.example")
        interaction = Passphrases(b"passphrase", b"passphrase")
        envelope, recipient = protector.protect_root(
            root,
            self.enrollment(),
            interaction,
        )
        interaction.assert_cleared()
        unlock = Passphrases(b"passphrase")
        recovered = protector.unlock(envelope, recipient, unlock)
        unlock.assert_cleared()
        expected = root.export()
        actual = recovered.export()
        self.assertEqual(expected, actual)
        expected[:] = b"\0" * len(expected)
        actual[:] = b"\0" * len(actual)

        with self.assertRaises(TypeError):
            fkw.RootKey.from_bytearray(bytes(32))
        short = bytearray(b"secret")
        with self.assertRaises(TypeError):
            fkw.RootKey.from_bytearray(short)
        self.assertEqual(short, bytearray(len(short)))
        oversized = bytearray(b"secret" * 1_000)
        with self.assertRaises(TypeError):
            fkw.RootKey.from_bytearray(oversized)
        self.assertFalse(any(oversized))
        with self.assertRaises(TypeError):
            copy.copy(root)
        with self.assertRaises(TypeError):
            copy.deepcopy(root)
        with self.assertRaises(TypeError):
            pickle.dumps(root)
        with self.assertRaises(TypeError):
            hash(root)

    def test_callback_failures_are_preserved_and_inputs_are_cleared(self) -> None:
        protector = fkw.KeyProtector("callbacks.example")
        enrollment = self.enrollment()

        class Sentinel(Exception):
            pass

        failure = Sentinel("application callback failed")

        class Raises:
            def request_passphrase(self, _prompt):
                raise failure

        with self.assertRaises(Sentinel) as caught:
            protector.create_root(enrollment, Raises())
        self.assertIs(caught.exception, failure)

        cancelled = fkw.Cancelled("cancelled")

        class Cancels:
            def request_passphrase(self, _prompt):
                raise cancelled

        with self.assertRaises(fkw.Cancelled) as caught:
            protector.create_root(enrollment, Cancels())
        self.assertIs(caught.exception, cancelled)

        with self.assertRaises(fkw.Error) as caught:
            protector.create_root(enrollment, object())
        self.assertEqual(caught.exception.code, fkw.ErrorCode.INTERACTION_UNSUPPORTED)

        invalid = bytearray(b"x" * 1_025)

        class Invalid:
            def request_passphrase(self, _prompt):
                return invalid

        with self.assertRaises(fkw.Error) as caught:
            protector.create_root(enrollment, Invalid())
        self.assertEqual(caught.exception.code, fkw.ErrorCode.INVALID_PASSPHRASE)
        self.assertFalse(any(invalid))

        class Immutable:
            def request_passphrase(self, _prompt):
                return b"immutable"

        with self.assertRaises(TypeError):
            protector.create_root(enrollment, Immutable())

        class BytearraySubclass(bytearray):
            pass

        subclass = BytearraySubclass(b"subclass")

        class ReturnsSubclass:
            def request_passphrase(self, _prompt):
                return subclass

        with self.assertRaises(TypeError):
            protector.create_root(enrollment, ReturnsSubclass())
        self.assertEqual(subclass, b"subclass")

    def test_confirmation_mismatch_is_bounded_and_cleared(self) -> None:
        interaction = Passphrases(b"first", b"second")
        with self.assertRaises(fkw.Error) as caught:
            fkw.KeyProtector("confirmation.example").create_root(
                self.enrollment(), interaction
            )
        self.assertEqual(
            caught.exception.code,
            fkw.ErrorCode.PASSPHRASE_CONFIRMATION_MISMATCH,
        )
        interaction.assert_cleared()

    def test_fido_disabled_build_fails_before_interaction(self) -> None:
        if fkw.FIDO_SUPPORT:
            self.skipTest("the extension was built with fido support")

        class Unexpected:
            def __getattr__(self, _name):
                raise AssertionError("interaction was requested")

        enrollment = fkw.Enrollment(
            "security key", fkw.Policy.FIDO_USER_VERIFICATION
        )
        with self.assertRaises(fkw.Error) as caught:
            fkw.KeyProtector("fido-disabled.example").create_root(
                enrollment, Unexpected()
            )
        self.assertEqual(caught.exception.code, fkw.ErrorCode.FIDO_SUPPORT_UNAVAILABLE)
        with self.assertRaises(fkw.Error) as caught:
            fkw.inspect_authenticators()
        self.assertEqual(caught.exception.code, fkw.ErrorCode.FIDO_SUPPORT_UNAVAILABLE)

    def test_same_protector_reentrancy_fails_without_deadlock(self) -> None:
        protector = fkw.KeyProtector("busy.example")
        enrollment = self.enrollment()

        class Reentrant(Passphrases):
            def __init__(self):
                super().__init__(b"passphrase", b"passphrase")
                self.codes = []

            def request_passphrase(self, prompt):
                try:
                    protector.create_root(enrollment, object())
                except fkw.Error as error:
                    self.codes.append(error.code)
                return super().request_passphrase(prompt)

        interaction = Reentrant()
        protector.create_root(enrollment, interaction)
        self.assertEqual(
            interaction.codes,
            [fkw.ErrorCode.BUSY, fkw.ErrorCode.BUSY],
        )
        interaction.assert_cleared()

    def test_argon2_work_releases_the_gil(self) -> None:
        ready = threading.Event()
        armed = threading.Event()
        stop = threading.Event()
        ticks = 0

        def ticker() -> None:
            nonlocal ticks
            ready.set()
            armed.wait()
            if not stop.is_set():
                ticks += 1

        class CoordinatedPassphrases(Passphrases):
            def request_passphrase(self, prompt):
                value = super().request_passphrase(prompt)
                if len(self.returned) == 2:
                    armed.set()
                return value

        thread = threading.Thread(target=ticker)
        thread.start()
        ready.wait()
        previous_interval = sys.getswitchinterval()
        sys.setswitchinterval(1_000.0)
        try:
            fkw.KeyProtector("threading.example").create_root(
                self.enrollment(),
                CoordinatedPassphrases(b"passphrase", b"passphrase"),
            )
        finally:
            stop.set()
            armed.set()
            sys.setswitchinterval(previous_interval)
            thread.join()
        self.assertGreater(ticks, 0)

    def test_values_are_validated_and_immutable(self) -> None:
        with self.assertRaises(fkw.Error) as caught:
            fkw.KeyProtector("invalid")
        self.assertEqual(caught.exception.code, fkw.ErrorCode.INVALID_APPLICATION_ID)

        with self.assertRaises(TypeError):
            fkw.Enrollment(
                "primary",
                fkw.Policy.FIDO_PRESENCE,
                PARAMETERS,
            )
        policies = (
            fkw.Policy.PASSPHRASE,
            fkw.Policy.FIDO_PRESENCE,
            fkw.Policy.FIDO_USER_VERIFICATION,
            fkw.Policy.FIDO_PRESENCE_AND_PASSPHRASE,
            fkw.Policy.FIDO_USER_VERIFICATION_AND_PASSPHRASE,
        )
        for index, policy in enumerate(policies):
            enrollment = fkw.Enrollment(f"policy {index}", policy, None)
            self.assertEqual(enrollment.policy, policy)
        self.assertEqual(len(set(policies)), len(policies))
        self.assertNotEqual(fkw.Policy.PASSPHRASE, 1)
        self.assertIsInstance(hash(fkw.Policy.PASSPHRASE), int)
        self.assertIsInstance(hash(fkw.ErrorCode.UNLOCK_FAILED), int)
        with self.assertRaises(fkw.Error):
            fkw.RecipientId("AA" * 32)
        with self.assertRaises(fkw.Error):
            fkw.KeyEnvelope.decode(b"not an envelope")

        parameters = fkw.PassphraseParameters.desktop()
        limits = fkw.PassphraseLimits.desktop()
        self.assertEqual(parameters, fkw.PassphraseParameters.desktop())
        self.assertEqual(limits, fkw.PassphraseLimits.desktop())
        self.assertEqual(
            fkw.Enrollment("primary", fkw.Policy.PASSPHRASE, parameters).parameters,
            parameters,
        )
        self.assertEqual(
            fkw.KeyProtector("values.example", limits).passphrase_limits,
            limits,
        )
        self.assertTrue(limits.accepts(parameters))
        with self.assertRaises(AttributeError):
            parameters.memory_kib = 1


if __name__ == "__main__":
    unittest.main()
