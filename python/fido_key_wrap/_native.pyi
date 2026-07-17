from typing import ClassVar, Final

FIDO_SUPPORT: Final[bool]

class ErrorCode:
    INVALID_APPLICATION_ID: Final[ErrorCode]
    INVALID_RECIPIENT_ID: Final[ErrorCode]
    INVALID_LABEL: Final[ErrorCode]
    INVALID_PASSPHRASE: Final[ErrorCode]
    INVALID_PIN: Final[ErrorCode]
    INVALID_PASSPHRASE_PARAMETERS: Final[ErrorCode]
    INVALID_PASSPHRASE_LIMITS: Final[ErrorCode]
    INVALID_FIDO_CONFIG: Final[ErrorCode]
    INVALID_ENVELOPE: Final[ErrorCode]
    APPLICATION_MISMATCH: Final[ErrorCode]
    RECIPIENT_NOT_FOUND: Final[ErrorCode]
    WOULD_REMOVE_LAST_RECIPIENT: Final[ErrorCode]
    TOO_MANY_RECIPIENTS: Final[ErrorCode]
    RECIPIENT_DOES_NOT_USE_PASSPHRASE: Final[ErrorCode]
    PASSPHRASE_CONFIRMATION_MISMATCH: Final[ErrorCode]
    PASSPHRASE_LIMIT_EXCEEDED: Final[ErrorCode]
    KDF_RESOURCE_UNAVAILABLE: Final[ErrorCode]
    FIDO_SUPPORT_UNAVAILABLE: Final[ErrorCode]
    NO_COMPATIBLE_AUTHENTICATOR: Final[ErrorCode]
    FIDO_PIN_INVALID: Final[ErrorCode]
    FIDO_PIN_BLOCKED: Final[ErrorCode]
    FIDO_PIN_TEMPORARILY_BLOCKED: Final[ErrorCode]
    FIDO_TIMEOUT: Final[ErrorCode]
    FIDO_BUSY: Final[ErrorCode]
    FIDO_CREDENTIAL_UNAVAILABLE: Final[ErrorCode]
    FIDO_TRANSPORT: Final[ErrorCode]
    FIDO_OPERATION_FAILED: Final[ErrorCode]
    AUTHENTICATOR_RESPONSE_INVALID: Final[ErrorCode]
    INTERACTION_CANCELLED: Final[ErrorCode]
    INTERACTION_UNSUPPORTED: Final[ErrorCode]
    INTERACTION_FAILED: Final[ErrorCode]
    RANDOM_UNAVAILABLE: Final[ErrorCode]
    ENVELOPE_AUTHENTICATION_FAILED: Final[ErrorCode]
    UNLOCK_FAILED: Final[ErrorCode]
    BUSY: Final[ErrorCode]
    INTERNAL: Final[ErrorCode]
    RECIPIENT_IS_NOT_MANAGED: Final[ErrorCode]
    FIDO_CREDENTIAL_STORE_FULL: Final[ErrorCode]
    FIDO_RETIREMENT_UNCERTAIN: Final[ErrorCode]
    FIDO_CREDENTIAL_MAY_REMAIN: Final[ErrorCode]

class Error(Exception):
    code: ErrorCode
    pin_retries: int | None

class Cancelled(Exception): ...

class Policy:
    PASSPHRASE: Final[Policy]
    RECOVERY_SECRET: Final[Policy]
    FIDO_PRESENCE: Final[Policy]
    FIDO_USER_VERIFICATION: Final[Policy]
    MANAGED_FIDO_PRESENCE: Final[Policy]
    MANAGED_FIDO_USER_VERIFICATION: Final[Policy]
    FIDO_PRESENCE_AND_PASSPHRASE: Final[Policy]
    FIDO_USER_VERIFICATION_AND_PASSPHRASE: Final[Policy]
    FIDO_PRESENCE_AND_LOCAL_SECRET: Final[Policy]

class FidoPolicy:
    PRESENCE: Final[FidoPolicy]
    USER_VERIFICATION: Final[FidoPolicy]

class FidoConfig:
    def __init__(
        self,
        operation_timeout_ms: int,
        selection_timeout_ms: int,
        max_devices: int,
    ) -> None: ...
    @staticmethod
    def standard() -> FidoConfig: ...
    @property
    def operation_timeout_ms(self) -> int: ...
    @property
    def selection_timeout_ms(self) -> int: ...
    @property
    def max_devices(self) -> int: ...

class Operation:
    CREATE_ROOT: Final[Operation]
    PROTECT_ROOT: Final[Operation]
    UNLOCK: Final[Operation]
    ADD_RECIPIENT: Final[Operation]
    REWRAP_PASSPHRASE: Final[Operation]
    VERIFY_MANAGED_RECIPIENT: Final[Operation]
    RETIRE_MANAGED_RECIPIENT: Final[Operation]

class FidoCeremony:
    ENROLLMENT: Final[FidoCeremony]
    ASSERTION: Final[FidoCeremony]

class PassphrasePurpose:
    UNLOCK: Final[PassphrasePurpose]
    NEW: Final[PassphrasePurpose]
    CONFIRM: Final[PassphrasePurpose]

class PassphraseParameters:
    def __init__(self, memory_kib: int, passes: int, lanes: int) -> None: ...
    @staticmethod
    def desktop() -> PassphraseParameters: ...
    @property
    def memory_kib(self) -> int: ...
    @property
    def passes(self) -> int: ...
    @property
    def lanes(self) -> int: ...

class PassphraseLimits:
    def __init__(self, max_memory_kib: int, max_work_kib_passes: int) -> None: ...
    @staticmethod
    def desktop() -> PassphraseLimits: ...
    @staticmethod
    def protocol_max() -> PassphraseLimits: ...
    @property
    def max_memory_kib(self) -> int: ...
    @property
    def max_work_kib_passes(self) -> int: ...
    def accepts(self, parameters: PassphraseParameters) -> bool: ...

class Enrollment:
    def __init__(
        self,
        label: str,
        policy: Policy,
        parameters: PassphraseParameters | None = None,
    ) -> None: ...
    @property
    def label(self) -> str: ...
    @property
    def policy(self) -> Policy: ...
    @property
    def parameters(self) -> PassphraseParameters | None: ...

class RecipientId:
    def __init__(self, value: str) -> None: ...
    def __str__(self) -> str: ...

class RecipientSummary:
    @property
    def id(self) -> RecipientId: ...
    @property
    def label(self) -> str: ...
    @property
    def policy(self) -> Policy: ...
    @property
    def passphrase_parameters(self) -> PassphraseParameters | None: ...

class KeyEnvelope:
    @staticmethod
    def decode(encoded: bytes) -> KeyEnvelope: ...
    def encode(self) -> bytes: ...
    @property
    def application_id(self) -> str: ...
    @property
    def recipients(self) -> tuple[RecipientSummary, ...]: ...

class RootKey:
    __hash__: ClassVar[None]
    @staticmethod
    def from_bytearray(material: bytearray) -> RootKey: ...
    def export(self) -> bytearray: ...

class RecoverySecret:
    __hash__: ClassVar[None]
    @staticmethod
    def from_bytearray(material: bytearray) -> RecoverySecret: ...
    def export(self) -> bytearray: ...

class RecoverySecretRecipient:
    __hash__: ClassVar[None]
    @property
    def recipient_id(self) -> RecipientId: ...
    @property
    def secret(self) -> RecoverySecret: ...

class LocalSecret:
    __hash__: ClassVar[None]
    @staticmethod
    def from_bytearray(material: bytearray) -> LocalSecret: ...
    def export(self) -> bytearray: ...

class LocalSecretRecipient:
    __hash__: ClassVar[None]
    @property
    def recipient_id(self) -> RecipientId: ...
    @property
    def secret(self) -> LocalSecret: ...

class SelectionPrompt:
    @property
    def operation(self) -> Operation: ...
    @property
    def label(self) -> str: ...
    @property
    def policy(self) -> FidoPolicy: ...

class PinPrompt:
    @property
    def operation(self) -> Operation: ...
    @property
    def label(self) -> str: ...
    @property
    def ceremony(self) -> FidoCeremony: ...

class PassphrasePrompt:
    @property
    def operation(self) -> Operation: ...
    @property
    def label(self) -> str: ...
    @property
    def purpose(self) -> PassphrasePurpose: ...

class TouchPrompt:
    @property
    def operation(self) -> Operation: ...
    @property
    def label(self) -> str: ...
    @property
    def ceremony(self) -> FidoCeremony: ...
    @property
    def policy(self) -> FidoPolicy: ...

class KeyProtector:
    def __init__(
        self,
        application_id: str,
        *,
        passphrase_limits: PassphraseLimits | None = None,
        fido_config: FidoConfig | None = None,
    ) -> None: ...
    @property
    def application_id(self) -> str: ...
    @property
    def passphrase_limits(self) -> PassphraseLimits: ...
    @property
    def fido_config(self) -> FidoConfig: ...
    def create_root(
        self, enrollment: Enrollment, interaction: object
    ) -> tuple[RootKey, KeyEnvelope, RecipientId]: ...
    def protect_root(
        self, root: RootKey, enrollment: Enrollment, interaction: object
    ) -> tuple[KeyEnvelope, RecipientId]: ...
    def unlock(
        self,
        envelope: KeyEnvelope,
        recipient: RecipientId,
        interaction: object,
    ) -> RootKey: ...
    def add_recipient(
        self,
        envelope: KeyEnvelope,
        root: RootKey,
        enrollment: Enrollment,
        interaction: object,
    ) -> tuple[KeyEnvelope, RecipientId]: ...
    def remove_recipient(
        self,
        envelope: KeyEnvelope,
        root: RootKey,
        recipient: RecipientId,
    ) -> KeyEnvelope: ...
    def verify_managed_recipient(
        self,
        envelope: KeyEnvelope,
        root: RootKey,
        recipient: RecipientId,
        interaction: object,
    ) -> None: ...
    def retire_managed_recipient(
        self,
        envelope: KeyEnvelope,
        root: RootKey,
        recipient: RecipientId,
        interaction: object,
    ) -> None: ...
    def rewrap_passphrase(
        self,
        envelope: KeyEnvelope,
        root: RootKey,
        recipient: RecipientId,
        interaction: object,
        parameters: PassphraseParameters | None = None,
    ) -> KeyEnvelope: ...
    def create_root_with_recovery_secret(
        self, label: str
    ) -> tuple[RootKey, KeyEnvelope, RecoverySecretRecipient]: ...
    def protect_root_with_recovery_secret(
        self, root: RootKey, label: str
    ) -> tuple[KeyEnvelope, RecoverySecretRecipient]: ...
    def unlock_with_recovery_secret(
        self,
        envelope: KeyEnvelope,
        recipient: RecipientId,
        secret: RecoverySecret,
    ) -> RootKey: ...
    def add_recovery_secret(
        self,
        envelope: KeyEnvelope,
        root: RootKey,
        label: str,
    ) -> tuple[KeyEnvelope, RecoverySecretRecipient]: ...
    def create_root_with_fido_and_local_secret(
        self,
        label: str,
        interaction: object,
    ) -> tuple[RootKey, KeyEnvelope, LocalSecretRecipient]: ...
    def protect_root_with_fido_and_local_secret(
        self,
        root: RootKey,
        label: str,
        interaction: object,
    ) -> tuple[KeyEnvelope, LocalSecretRecipient]: ...
    def add_fido_and_local_secret(
        self,
        envelope: KeyEnvelope,
        root: RootKey,
        label: str,
        interaction: object,
    ) -> tuple[KeyEnvelope, LocalSecretRecipient]: ...
    def unlock_with_fido_and_local_secret(
        self,
        envelope: KeyEnvelope,
        recipient: RecipientId,
        secret: LocalSecret,
        interaction: object,
    ) -> RootKey: ...

class AuthenticatorIssue:
    UNAVAILABLE: Final[AuthenticatorIssue]
    FIDO2_UNAVAILABLE: Final[AuthenticatorIssue]
    ES256_UNAVAILABLE: Final[AuthenticatorIssue]
    HMAC_SECRET_UNAVAILABLE: Final[AuthenticatorIssue]
    CREDENTIAL_PROTECTION_UNAVAILABLE: Final[AuthenticatorIssue]
    USER_VERIFICATION_UNAVAILABLE: Final[AuthenticatorIssue]
    USER_VERIFICATION_NOT_CONFIGURED: Final[AuthenticatorIssue]
    PRESENCE_RECOVERY_UNAVAILABLE: Final[AuthenticatorIssue]
    DISCOVERABLE_CREDENTIALS_UNAVAILABLE: Final[AuthenticatorIssue]
    CREDENTIAL_MANAGEMENT_UNAVAILABLE: Final[AuthenticatorIssue]

class AuthenticatorReport:
    @property
    def compatible(self) -> bool: ...
    @property
    def issues(self) -> tuple[AuthenticatorIssue, ...]: ...

def inspect_authenticators() -> list[AuthenticatorReport]: ...
