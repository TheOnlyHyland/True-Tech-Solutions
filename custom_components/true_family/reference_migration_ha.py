"""Home Assistant adapters for reference migration authority and journals.

``HomeAssistantMigrationAuthority`` is a synchronous, worker-thread-only
adapter around Home Assistant's event-loop-owned config entry, runtime, and
registries.  Its immutable policy identifies every provider target explicitly;
each resolution revalidates the complete persisted and live identity chain.

``ReferenceJournal`` is intentionally synchronous.  The adapter returned by
``HomeAssistantReferenceJournal.async_create`` must therefore be called only
from a worker thread.  Each call is marshalled to Home Assistant's event loop
with ``asyncio.run_coroutine_threadsafe`` and returns only after the backend has
been loaded back and matched exactly.  Calling a journal method from any
running event-loop thread is rejected instead of blocking that loop.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import InitVar, dataclass, field
from datetime import datetime
from enum import StrEnum
import hashlib
import json
import re
import secrets
import threading
from types import MappingProxyType
from typing import Any, NoReturn, Protocol, TypeVar, runtime_checkable

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

from . import reference_journal_file, reference_journal_remote
from .bootstrap import BootstrapError, BootstrapRecord, CANONICAL_ROOM_IDS
from .bootstrap_ha import validate_bootstrap_rooms
from .const import CONF_BOOTSTRAP, CONF_ROOMS, DOMAIN
from .models import RoomBinding, RoomSlot, rooms_as_dict, rooms_from_dict
from .reference_migration import (
    JournaledCompletion,
    JournaledOriginal,
    MalformedReferenceDocumentError,
    MigrationPlan,
    MigrationResult,
    MigrationState,
    MigrationSubject,
    PlannedDocument,
    ReferenceDocument,
    TRUE_FAMILY_PROVIDER_MANIFEST,
    _DocumentSnapshot,
    _validate_journaled_completion,
    canonical_document_fingerprint,
)
from .reference_journal_discovery import (
    async_schedule_pending_reference_journal_reload,
    get_reference_journal_endpoint,
)
from .reference_transaction import (
    BridgeAttemptState,
    BridgeBlockReason,
    BridgeDispatchAuthorization,
    BridgeExpectedWrite,
    BridgeJournalConflict,
    BridgeOperationAttempt,
    BridgeOperationIntent,
    BridgeOperationKind,
    BridgeOperationReceipt,
    BridgeOperationRecord,
    BridgeOperationState,
    BridgeOperationVerification,
    BridgeReceiptOutcome,
    FenceAcquisitionIntent,
    FenceAcquisitionNoEffectReceipt,
    FenceAcquisitionReceipt,
    FenceAcquisitionRecord,
    FenceReleaseIntent,
    FenceReleaseNoEffectReceipt,
    FenceReleaseReceipt,
    FenceReleaseRecord,
    InMemoryBridgeOperationJournal,
    decode_bridge_operation_attempt,
    encode_bridge_operation_attempt,
)


REFERENCE_JOURNAL_SCHEMA = 4
REFERENCE_JOURNAL_RUNTIME_DATA = f"{DOMAIN}_reference_journal_runtime"
REFERENCE_JOURNAL_FILESYSTEM_POLICY_DATA = (
    f"{DOMAIN}_reference_journal_filesystem_policy"
)
REFERENCE_JOURNAL_FILESYSTEM_CERTIFICATION_DATA = (
    f"{DOMAIN}_reference_journal_filesystem_certification"
)

_ROOT_KEYS = frozenset(
    {"schema", "journal_id", "generation", "content", "content_digest"}
)
_CONTENT_KEYS = frozenset(
    {"states", "active_plans", "originals", "completions", "bridge_operations"}
)
_ACTIVE_PLAN_KEYS = frozenset({"plan", "manifest_digest", "execution_binding"})
_EXECUTION_BINDING_KEYS = frozenset(
    {
        "execution_scope_digest",
        "recorder_id",
        "journal_id",
        "provider_bridge_ids",
        "binding_digest",
    }
)
_PROVIDER_BRIDGE_KEYS = frozenset({"provider", "bridge_id"})
_BOUND_ATTEMPT_KEYS = frozenset({"execution_binding_digest", "attempt"})
_BOUND_COMPLETION_KEYS = frozenset({"execution_binding_digest", "completion"})
_STATE_KEYS = frozenset({"state", "reason"})
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PLAN_ID_PATTERN = re.compile(r"^tf-reference-[0-9a-f]{24}$")
_CLIMATE_ENTITY_PATTERN = re.compile(r"^climate\.[a-z0-9_]+$")
_LOGICAL_UNIQUE_ID_PATTERN = re.compile(r"^logical_valve_[a-z0-9_]+$")
_PLATFORM_PATTERN = re.compile(r"^[a-z0-9_]+$")

_T = TypeVar("_T")


class MigrationAuthorityError(RuntimeError):
    """Raised when authoritative Home Assistant state cannot be proven."""


class MigrationAuthorityPolicyError(ValueError):
    """Raised when the immutable provider-target policy is incomplete."""


class MigrationAuthorityThreadError(MigrationAuthorityError):
    """Raised when synchronous authority resolution runs on an event loop."""


class MigrationTargetRole(StrEnum):
    """Explicit target roles accepted by the production authority."""

    LOGICAL_VALVE = "logical_valve"
    FACADE = "facade"


def _policy_text(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise MigrationAuthorityPolicyError(
            f"{label} must be canonical non-empty text without control characters."
        )
    return value


@dataclass(frozen=True, slots=True)
class FacadeRegistryIdentity:
    """Exact allowlisted registry identity for one existing climate facade."""

    registry_entry_id: str
    platform: str
    unique_id: str

    def __post_init__(self) -> None:
        _policy_text(self.registry_entry_id, "Facade registry entry ID")
        platform = _policy_text(self.platform, "Facade platform")
        _policy_text(self.unique_id, "Facade unique ID")
        if not _PLATFORM_PATTERN.fullmatch(platform):
            raise MigrationAuthorityPolicyError("Facade platform is not canonical.")
        if platform in {"mqtt", DOMAIN}:
            raise MigrationAuthorityPolicyError(
                "Physical and logical valve platforms cannot be facade targets."
            )


@dataclass(frozen=True, slots=True)
class ProviderTargetPolicy:
    """One provider's explicit target role; no target is inferred by default."""

    provider: str
    role: MigrationTargetRole
    facade: FacadeRegistryIdentity | None

    def __post_init__(self) -> None:
        provider = _policy_text(self.provider, "Provider name")
        if provider not in TRUE_FAMILY_PROVIDER_MANIFEST:
            raise MigrationAuthorityPolicyError("Provider target is not in the manifest.")
        if not isinstance(self.role, MigrationTargetRole):
            raise MigrationAuthorityPolicyError("Provider target role must be explicit.")
        if self.role is MigrationTargetRole.LOGICAL_VALVE:
            if self.facade is not None:
                raise MigrationAuthorityPolicyError(
                    "A logical-valve target cannot contain a facade identity."
                )
            return
        if self.role is MigrationTargetRole.FACADE and not isinstance(
            self.facade, FacadeRegistryIdentity
        ):
            raise MigrationAuthorityPolicyError(
                "A facade target requires its exact registry identity."
            )


@dataclass(frozen=True, slots=True)
class RoomMigrationTargetPolicy:
    """Canonical five-provider target policy for one immutable room ID."""

    room_id: str
    provider_targets: tuple[ProviderTargetPolicy, ...]

    def __post_init__(self) -> None:
        room_id = _policy_text(self.room_id, "Policy room ID")
        if room_id not in CANONICAL_ROOM_IDS:
            raise MigrationAuthorityPolicyError("Policy contains an unknown room.")
        if type(self.provider_targets) is not tuple:
            raise MigrationAuthorityPolicyError(
                "Room provider targets must be an immutable tuple."
            )
        if any(
            not isinstance(target, ProviderTargetPolicy)
            for target in self.provider_targets
        ):
            raise MigrationAuthorityPolicyError("Room provider target is malformed.")
        providers = tuple(target.provider for target in self.provider_targets)
        if providers != tuple(sorted(TRUE_FAMILY_PROVIDER_MANIFEST)):
            raise MigrationAuthorityPolicyError(
                "Every room must cover the provider manifest exactly and canonically."
            )


@dataclass(frozen=True, slots=True)
class HomeAssistantMigrationTargetPolicy:
    """Immutable, server-owned target policy for exactly seven room slots."""

    rooms: tuple[RoomMigrationTargetPolicy, ...]

    def __post_init__(self) -> None:
        if type(self.rooms) is not tuple:
            raise MigrationAuthorityPolicyError(
                "Migration room policy must be an immutable tuple."
            )
        if any(not isinstance(room, RoomMigrationTargetPolicy) for room in self.rooms):
            raise MigrationAuthorityPolicyError("Migration room policy is malformed.")
        if tuple(room.room_id for room in self.rooms) != CANONICAL_ROOM_IDS:
            raise MigrationAuthorityPolicyError(
                "Migration policy must contain the canonical seven rooms in order."
            )

        facade_registry_owners: dict[str, tuple[str, FacadeRegistryIdentity]] = {}
        facade_identity_owners: dict[tuple[str, str], tuple[str, str]] = {}
        for room in self.rooms:
            for target in room.provider_targets:
                facade = target.facade
                if facade is None:
                    continue
                registry_owner = facade_registry_owners.setdefault(
                    facade.registry_entry_id,
                    (room.room_id, facade),
                )
                if registry_owner != (room.room_id, facade):
                    raise MigrationAuthorityPolicyError(
                        "A facade registry entry has conflicting room or identity policy."
                    )
                identity = (facade.platform, facade.unique_id)
                identity_owner = facade_identity_owners.setdefault(
                    identity,
                    (room.room_id, facade.registry_entry_id),
                )
                if identity_owner != (room.room_id, facade.registry_entry_id):
                    raise MigrationAuthorityPolicyError(
                        "A facade platform identity is allocated more than once."
                    )


class ReferenceJournalCodecError(ValueError):
    """Raised when persisted journal data is not exact and canonical."""


class ReferenceJournalNotProvisionedError(RuntimeError):
    """Raised when no readable, explicitly provisioned journal exists."""


class ReferenceJournalAlreadyProvisionedError(RuntimeError):
    """Raised when explicit provisioning would overwrite a journal."""


class ReferenceJournalDurabilityError(RuntimeError):
    """Raised when a Store mutation cannot establish crash durability."""


class ReferenceJournalBusyError(ReferenceJournalDurabilityError):
    """Raised when another backend owns the durable journal lock."""


class ReferenceJournalUnsupportedFilesystemError(ReferenceJournalDurabilityError):
    """Raised when the configured filesystem cannot prove crash durability."""


class ReferenceJournalCertificationError(ReferenceJournalUnsupportedFilesystemError):
    """Raised when external production durability certification is unavailable."""


class ReferenceJournalIOError(ReferenceJournalDurabilityError):
    """Raised when durable journal storage is temporarily unavailable."""


class ReferenceJournalConflictError(ReferenceJournalDurabilityError):
    """Raised when durable journal compare-and-swap detects a stale writer."""


class ReferenceJournalCorruptionError(ReferenceJournalCodecError):
    """Raised when durable journal bytes are malformed or inconsistent."""


class ReferenceJournalSecurityError(ReferenceJournalCorruptionError):
    """Raised when durable journal storage violates the trusted-file policy."""


class ReferenceJournalThreadError(RuntimeError):
    """Raised when the synchronous adapter is called from an event loop."""


class ReferenceJournalOwnershipError(RuntimeError):
    """Raised when another adapter owns the process-local journal lease."""


@runtime_checkable
class ReferenceJournalStore(Protocol):
    """Small Store surface accepted by the async factory and tests."""

    async def async_load(self) -> dict[str, Any] | None:
        """Load one Store payload."""

        ...

    async def async_save(self, data: dict[str, Any]) -> None:
        """Save one Store payload."""

        ...


_ATOMIC_FILE_DURABILITY_GUARANTEE = (
    "atomic-replace-file-fsync-parent-directory-fsync/v1"
)
_REMOTE_SQLITE_DURABILITY_GUARANTEE = "sqlite-wal-full-process-crash-cas/v1"
_REMOTE_SQLITE_DURABILITY_PROVIDER_ID = (
    "tf/remote-sqlite-full-process-crash-cas-reference-journal/v1"
)
_SUPPORTED_DURABILITY_GUARANTEES = frozenset(
    {
        _ATOMIC_FILE_DURABILITY_GUARANTEE,
        _REMOTE_SQLITE_DURABILITY_GUARANTEE,
    }
)
_DURABILITY_PROOF_DOMAIN = "true-family/reference-journal-durability-proof/v1"
_TEST_DURABILITY_PROOF_DOMAIN = (
    "true-family/reference-journal-test-durability-proof/v1"
)
_PRODUCTION_DURABILITY_PROOF_SEAL = object()
_TEST_DURABILITY_PROOF_SEAL = object()


class ReferenceJournalDurabilityScope(StrEnum):
    """Capability scope carried by every sealed durability proof."""

    PROCESS_CRASH_ONLY = "process_crash_only"
    POWER_LOSS_HOST_MUTATION = "power_loss_host_mutation"
    TEST_ONLY_HOST_MUTATION = "test_only_host_mutation"


def _durability_proof_digest(
    provider_id: str,
    guarantee: str,
    scope: ReferenceJournalDurabilityScope,
    *,
    test_only: bool,
) -> str:
    encoded = json.dumps(
        {
            "domain": (
                _TEST_DURABILITY_PROOF_DOMAIN
                if test_only
                else _DURABILITY_PROOF_DOMAIN
            ),
            "provider_id": provider_id,
            "guarantee": guarantee,
            "scope": scope.value,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_durability_proof_fields(
    provider_id: str,
    guarantee: str,
    scope: ReferenceJournalDurabilityScope,
    identity_digest: str,
    *,
    test_only: bool,
) -> None:
    if (
        type(provider_id) is not str
        or not provider_id
        or len(provider_id) > 255
        or provider_id != provider_id.strip()
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in provider_id
        )
    ):
        raise ValueError("Durability proof provider ID is not canonical.")
    if (
        type(guarantee) is not str
        or guarantee not in _SUPPORTED_DURABILITY_GUARANTEES
    ):
        raise ValueError("Durability proof does not provide a supported guarantee.")
    if type(scope) is not ReferenceJournalDurabilityScope:
        raise ValueError("Durability proof does not provide a canonical scope.")
    if test_only:
        if guarantee == _REMOTE_SQLITE_DURABILITY_GUARANTEE:
            raise ValueError(
                "Test durability proofs cannot claim the production SQLite guarantee."
            )
        if scope is not ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION:
            raise ValueError("Test durability proofs require their test-only scope.")
    elif provider_id == _REMOTE_SQLITE_DURABILITY_PROVIDER_ID:
        if guarantee != _REMOTE_SQLITE_DURABILITY_GUARANTEE:
            raise ValueError(
                "The remote SQLite provider requires its exact guarantee."
            )
        if scope is not ReferenceJournalDurabilityScope.PROCESS_CRASH_ONLY:
            raise ValueError("The remote SQLite provider is process-crash-only.")
    else:
        if guarantee == _REMOTE_SQLITE_DURABILITY_GUARANTEE:
            raise ValueError(
                "Only the exact remote SQLite provider can claim its guarantee."
            )
        if scope is not ReferenceJournalDurabilityScope.POWER_LOSS_HOST_MUTATION:
            raise ValueError(
                "Certified raw durability requires power-loss host-mutation scope."
            )
    expected = _durability_proof_digest(
        provider_id,
        guarantee,
        scope,
        test_only=test_only,
    )
    if identity_digest != expected:
        raise ValueError("Durability proof identity digest is not canonical.")


@dataclass(frozen=True, slots=True)
class ReferenceJournalDurabilityProof:
    """Sealed production proof bound to one exact known backend object."""

    provider_id: str
    guarantee: str
    scope: ReferenceJournalDurabilityScope
    identity_digest: str
    _backend: object = field(repr=False, compare=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if (
            type(self) is not ReferenceJournalDurabilityProof
            or _seal is not _PRODUCTION_DURABILITY_PROOF_SEAL
            or self._backend is None
        ):
            raise TypeError(
                "Production durability proofs are issued by known backends only."
            )
        _validate_durability_proof_fields(
            self.provider_id,
            self.guarantee,
            self.scope,
            self.identity_digest,
            test_only=False,
        )


@dataclass(frozen=True, slots=True)
class ReferenceJournalTestDurabilityProof(ReferenceJournalDurabilityProof):
    """Explicit test-only proof accepted only with an injected test backend."""

    def __post_init__(self, _seal: object | None) -> None:
        if (
            type(self) is not ReferenceJournalTestDurabilityProof
            or _seal is not _TEST_DURABILITY_PROOF_SEAL
        ):
            raise TypeError(
                "Use ReferenceJournalTestDurabilityProof.create() in tests."
            )
        _validate_durability_proof_fields(
            self.provider_id,
            self.guarantee,
            self.scope,
            self.identity_digest,
            test_only=True,
        )

    @classmethod
    def create(
        cls,
        provider_id: str,
        guarantee: str | None = None,
    ) -> ReferenceJournalTestDurabilityProof:
        """Create a visibly test-only proof for an explicit injected fake."""

        selected_guarantee = guarantee or _ATOMIC_FILE_DURABILITY_GUARANTEE
        return cls(
            provider_id=provider_id,
            guarantee=selected_guarantee,
            scope=ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION,
            identity_digest=_durability_proof_digest(
                provider_id,
                selected_guarantee,
                ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION,
                test_only=True,
            ),
            _backend=None,
            _seal=_TEST_DURABILITY_PROOF_SEAL,
        )

    @classmethod
    def _for_backend(
        cls,
        provider_id: str,
        backend: object,
    ) -> ReferenceJournalTestDurabilityProof:
        return cls(
            provider_id=provider_id,
            guarantee=_ATOMIC_FILE_DURABILITY_GUARANTEE,
            scope=ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION,
            identity_digest=_durability_proof_digest(
                provider_id,
                _ATOMIC_FILE_DURABILITY_GUARANTEE,
                ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION,
                test_only=True,
            ),
            _backend=backend,
            _seal=_TEST_DURABILITY_PROOF_SEAL,
        )


def _new_production_durability_proof(
    provider_id: str,
    guarantee: str,
    scope: ReferenceJournalDurabilityScope,
    backend: object,
) -> ReferenceJournalDurabilityProof:
    return ReferenceJournalDurabilityProof(
        provider_id=provider_id,
        guarantee=guarantee,
        scope=scope,
        identity_digest=_durability_proof_digest(
            provider_id,
            guarantee,
            scope,
            test_only=False,
        ),
        _backend=backend,
        _seal=_PRODUCTION_DURABILITY_PROOF_SEAL,
    )


def _issue_remote_reference_journal_durability_proof(
    backend: object,
) -> ReferenceJournalDurabilityProof:
    """Issue proof only to the exact signed-capability remote backend."""

    if type(backend) is not reference_journal_remote.RemoteReferenceJournalStore:
        raise TypeError(
            "Only the exact remote reference journal can receive this proof."
        )
    if (
        backend.capabilities != reference_journal_remote.REMOTE_JOURNAL_CAPABILITIES
        or reference_journal_remote.REMOTE_JOURNAL_DURABILITY_CAPABILITY
        not in backend.capabilities
    ):
        raise ReferenceJournalDurabilityError(
            "The signed remote journal does not advertise its required durability "
            "capability."
        )
    return _new_production_durability_proof(
        _REMOTE_SQLITE_DURABILITY_PROVIDER_ID,
        _REMOTE_SQLITE_DURABILITY_GUARANTEE,
        ReferenceJournalDurabilityScope.PROCESS_CRASH_ONLY,
        backend,
    )


def _issue_file_reference_journal_durability_proof(
    backend: object,
    provider_id: str,
) -> ReferenceJournalDurabilityProof | ReferenceJournalTestDurabilityProof:
    """Issue the raw backend's grade only after its own policy certification."""

    if type(backend) is not reference_journal_file.CrashDurableReferenceJournalStore:
        raise TypeError(
            "Only the exact raw reference journal can receive this proof."
        )
    if backend._filesystem_policy.test_only:
        return ReferenceJournalTestDurabilityProof._for_backend(provider_id, backend)
    certification = backend._filesystem_certification
    if (
        certification is None
        or certification.test_only
        or backend._storage_stack_binding_digest is None
    ):
        raise ReferenceJournalCertificationError(
            "Production durability proof lacks validated external evidence."
        )
    return _new_production_durability_proof(
        provider_id,
        _ATOMIC_FILE_DURABILITY_GUARANTEE,
        ReferenceJournalDurabilityScope.POWER_LOSS_HOST_MUTATION,
        backend,
    )


@runtime_checkable
class ReferenceJournalDurabilityBarrier(Protocol):
    """Explicit post-save crash-durability checkpoint for Store adapters."""

    @property
    def durability_proof(
        self,
    ) -> (
        ReferenceJournalDurabilityProof
        | ReferenceJournalTestDurabilityProof
        | None
    ):
        """Identify the exact strong guarantee, or return no proof."""

        ...

    async def async_barrier(self) -> None:
        """Return only after the preceding Store save is crash durable."""

        ...


@runtime_checkable
class ReferenceJournalOwnedStore(
    ReferenceJournalStore,
    ReferenceJournalDurabilityBarrier,
    Protocol,
):
    """Backend-neutral lifecycle surface for a production-owned journal store."""

    async def async_close(self) -> None:
        """Drain accepted work and release the owned backend."""

        ...


def _codec_error(path: str, message: str) -> ReferenceJournalCodecError:
    return ReferenceJournalCodecError(f"{path}: {message}")


def _exact_mapping(
    value: Any,
    path: str,
    keys: frozenset[str] | None = None,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise _codec_error(path, "must be a built-in mapping")
    if any(type(key) is not str for key in value):
        raise _codec_error(path, "must contain only string keys")
    if keys is not None and set(value) != keys:
        missing = sorted(keys - set(value))
        unexpected = sorted(set(value) - keys)
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        raise _codec_error(path, "; ".join(details))
    return value


def _exact_list(value: Any, path: str) -> list[Any]:
    if type(value) is not list:
        raise _codec_error(path, "must be a built-in list")
    return value


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise _codec_error(path, f"must be {qualifier}")
    return value


def _optional_string(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _string(value, path, allow_empty=True)


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise _codec_error(path, f"must be an integer greater than or equal to {minimum}")
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise _codec_error(path, "must be a boolean")
    return value


def _fingerprint(value: Any, path: str) -> str:
    rendered = _string(value, path)
    if not _SHA256_PATTERN.fullmatch(rendered):
        raise _codec_error(path, "must be a canonical SHA-256 digest")
    return rendered


def _plan_id(value: Any, path: str) -> str:
    rendered = _string(value, path)
    if not _PLAN_ID_PATTERN.fullmatch(rendered):
        raise _codec_error(path, "must be a canonical reference migration plan ID")
    return rendered


def _provider(value: Any, path: str) -> str:
    rendered = _string(value, path)
    if rendered not in TRUE_FAMILY_PROVIDER_MANIFEST:
        raise _codec_error(path, "contains an unknown reference provider")
    return rendered


def _climate_entity(value: Any, path: str) -> str:
    rendered = _string(value, path)
    if not _CLIMATE_ENTITY_PATTERN.fullmatch(rendered):
        raise _codec_error(path, "must be a canonical climate entity ID")
    return rendered


def _journal_id(value: Any, path: str = "journal_id") -> str:
    rendered = _string(value, path)
    if (
        len(rendered) > 255
        or rendered != rendered.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in rendered)
    ):
        raise _codec_error(path, "must be a trimmed identifier without control characters")
    return rendered


def _canonical_bytes(value: Any, path: str) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as err:
        raise _codec_error(path, "cannot be represented as canonical JSON") from err
    return rendered.encode("utf-8")


def _content_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value, "journal root")).hexdigest()


@dataclass(frozen=True, slots=True)
class ReferencePlanExecutionBinding:
    """Exact non-secret execution identity durably bound to one active plan."""

    execution_scope_digest: str
    recorder_id: str
    journal_id: str
    provider_bridge_ids: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _fingerprint(
            self.execution_scope_digest,
            "execution_binding.execution_scope_digest",
        )
        _journal_id(self.recorder_id, "execution_binding.recorder_id")
        _journal_id(self.journal_id, "execution_binding.journal_id")
        if type(self.provider_bridge_ids) is not tuple or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            for item in self.provider_bridge_ids
        ):
            raise TypeError(
                "Execution provider bridge IDs must be immutable provider-ID pairs."
            )
        providers = tuple(provider for provider, _bridge_id in self.provider_bridge_ids)
        if providers != tuple(sorted(TRUE_FAMILY_PROVIDER_MANIFEST)):
            raise ValueError(
                "Execution binding must cover every provider once in canonical order."
            )
        bridge_ids = tuple(
            _journal_id(bridge_id, f"execution_binding.{provider}.bridge_id")
            for provider, bridge_id in self.provider_bridge_ids
        )
        if len(set(bridge_ids)) != len(bridge_ids):
            raise ValueError("Execution bridge IDs must be unique.")

    @property
    def digest(self) -> str:
        """Return a domain-separated digest of the persisted binding identity."""

        return _content_digest(
            {
                "domain": "true-family/reference-plan-execution-binding/v1",
                "execution_scope_digest": self.execution_scope_digest,
                "recorder_id": self.recorder_id,
                "journal_id": self.journal_id,
                "provider_bridge_ids": [
                    {"provider": provider, "bridge_id": bridge_id}
                    for provider, bridge_id in self.provider_bridge_ids
                ],
            }
        )


def _encode_revision(value: Any, path: str) -> dict[str, Any]:
    if type(value) is int:
        return {"type": "integer", "value": value}
    if type(value) is str and value:
        return {"type": "string", "value": value}
    raise _codec_error(path, "must be a non-empty string or an integer")


def _decode_revision(value: Any, path: str) -> str | int:
    raw = _exact_mapping(value, path, frozenset({"type", "value"}))
    revision_type = _string(raw["type"], f"{path}.type")
    if revision_type == "integer":
        if type(raw["value"]) is not int:
            raise _codec_error(f"{path}.value", "must be an integer")
        return raw["value"]
    if revision_type == "string":
        return _string(raw["value"], f"{path}.value")
    raise _codec_error(f"{path}.type", "must be integer or string")


def _encode_path(value: Any, path: str) -> list[dict[str, Any]]:
    if type(value) is not tuple:
        raise _codec_error(path, "must be a tuple")
    encoded: list[dict[str, Any]] = []
    for index, part in enumerate(value):
        if type(part) is int and part >= 0:
            encoded.append({"type": "index", "value": part})
        elif type(part) is str:
            encoded.append({"type": "key", "value": part})
        else:
            raise _codec_error(
                f"{path}[{index}]", "must be a string key or non-negative integer index"
            )
    return encoded


def _decode_path(value: Any, path: str) -> tuple[str | int, ...]:
    raw = _exact_list(value, path)
    decoded: list[str | int] = []
    for index, item in enumerate(raw):
        item_path = f"{path}[{index}]"
        part = _exact_mapping(item, item_path, frozenset({"type", "value"}))
        part_type = _string(part["type"], f"{item_path}.type")
        if part_type == "index":
            decoded.append(_integer(part["value"], f"{item_path}.value"))
        elif part_type == "key":
            decoded.append(_string(part["value"], f"{item_path}.value", allow_empty=True))
        else:
            raise _codec_error(f"{item_path}.type", "must be index or key")
    return tuple(decoded)


def _copy_valid_payload(document: ReferenceDocument, path: str) -> Any:
    try:
        canonical_document_fingerprint(document)
    except (MalformedReferenceDocumentError, TypeError, ValueError) as err:
        raise _codec_error(path, f"contains an invalid reference payload: {err}") from err
    return deepcopy(document.payload)


def encode_reference_document(value: ReferenceDocument) -> dict[str, Any]:
    """Encode one reference document with explicit revision typing."""

    if not isinstance(value, ReferenceDocument):
        raise _codec_error("reference_document", "must be a ReferenceDocument")
    provider = _provider(value.provider, "reference_document.provider")
    object_id = _string(value.object_id, "reference_document.object_id")
    revision = _encode_revision(value.revision, "reference_document.revision")
    writable = _boolean(value.writable, "reference_document.writable")
    payload = _copy_valid_payload(value, "reference_document.payload")
    return {
        "provider": provider,
        "object_id": object_id,
        "revision": revision,
        "payload": payload,
        "writable": writable,
    }


def decode_reference_document(value: Any) -> ReferenceDocument:
    """Decode one strict reference document."""

    path = "reference_document"
    raw = _exact_mapping(
        value,
        path,
        frozenset({"provider", "object_id", "revision", "payload", "writable"}),
    )
    try:
        document = ReferenceDocument(
            provider=_provider(raw["provider"], f"{path}.provider"),
            object_id=_string(raw["object_id"], f"{path}.object_id"),
            revision=_decode_revision(raw["revision"], f"{path}.revision"),
            payload=deepcopy(raw["payload"]),
            writable=_boolean(raw["writable"], f"{path}.writable"),
        )
    except ValueError as err:
        raise _codec_error(path, str(err)) from err
    _copy_valid_payload(document, f"{path}.payload")
    return document


def encode_journaled_original(value: JournaledOriginal) -> dict[str, Any]:
    """Encode one durable original and its attested postimage digest."""

    if not isinstance(value, JournaledOriginal):
        raise _codec_error("journaled_original", "must be a JournaledOriginal")
    return {
        "document": encode_reference_document(value.document),
        "post_fingerprint": _fingerprint(
            value.post_fingerprint,
            "journaled_original.post_fingerprint",
        ),
    }


def decode_journaled_original(value: Any) -> JournaledOriginal:
    """Decode one strict durable original."""

    path = "journaled_original"
    raw = _exact_mapping(
        value,
        path,
        frozenset({"document", "post_fingerprint"}),
    )
    return JournaledOriginal(
        document=decode_reference_document(raw["document"]),
        post_fingerprint=_fingerprint(
            raw["post_fingerprint"],
            f"{path}.post_fingerprint",
        ),
    )


def encode_planned_document(value: PlannedDocument) -> dict[str, Any]:
    """Encode one planned provider document."""

    if not isinstance(value, PlannedDocument):
        raise _codec_error("planned_document", "must be a PlannedDocument")
    if type(value.exact_paths) is not tuple:
        raise _codec_error("planned_document.exact_paths", "must be a tuple")
    exact_paths = [
        _encode_path(item, f"planned_document.exact_paths[{index}]")
        for index, item in enumerate(value.exact_paths)
    ]
    if len(set(value.exact_paths)) != len(value.exact_paths):
        raise _codec_error("planned_document.exact_paths", "contains duplicate paths")
    return {
        "provider": _provider(value.provider, "planned_document.provider"),
        "object_id": _string(value.object_id, "planned_document.object_id"),
        "revision": _encode_revision(value.revision, "planned_document.revision"),
        "writable": _boolean(value.writable, "planned_document.writable"),
        "fingerprint": _fingerprint(
            value.fingerprint,
            "planned_document.fingerprint",
        ),
        "post_fingerprint": _fingerprint(
            value.post_fingerprint,
            "planned_document.post_fingerprint",
        ),
        "exact_paths": exact_paths,
    }


def decode_planned_document(value: Any) -> PlannedDocument:
    """Decode one strict planned provider document."""

    path = "planned_document"
    raw = _exact_mapping(
        value,
        path,
        frozenset(
            {
                "provider",
                "object_id",
                "revision",
                "writable",
                "fingerprint",
                "post_fingerprint",
                "exact_paths",
            }
        ),
    )
    exact_paths = tuple(
        _decode_path(item, f"{path}.exact_paths[{index}]")
        for index, item in enumerate(_exact_list(raw["exact_paths"], f"{path}.exact_paths"))
    )
    if len(set(exact_paths)) != len(exact_paths):
        raise _codec_error(f"{path}.exact_paths", "contains duplicate paths")
    return PlannedDocument(
        provider=_provider(raw["provider"], f"{path}.provider"),
        object_id=_string(raw["object_id"], f"{path}.object_id"),
        revision=_decode_revision(raw["revision"], f"{path}.revision"),
        writable=_boolean(raw["writable"], f"{path}.writable"),
        fingerprint=_fingerprint(raw["fingerprint"], f"{path}.fingerprint"),
        post_fingerprint=_fingerprint(
            raw["post_fingerprint"],
            f"{path}.post_fingerprint",
        ),
        exact_paths=exact_paths,
    )


def _encode_provider_targets(value: Any, path: str) -> dict[str, str]:
    if type(value) is not tuple:
        raise _codec_error(path, "must be a tuple")
    targets: dict[str, str] = {}
    for index, item in enumerate(value):
        if type(item) is not tuple or len(item) != 2:
            raise _codec_error(f"{path}[{index}]", "must be a two-item tuple")
        provider = _provider(item[0], f"{path}[{index}].provider")
        if provider in targets:
            raise _codec_error(path, "contains duplicate providers")
        targets[provider] = _climate_entity(item[1], f"{path}[{index}].target")
    if set(targets) != set(TRUE_FAMILY_PROVIDER_MANIFEST):
        raise _codec_error(path, "must cover the provider manifest exactly")
    if value != tuple(sorted(targets.items())):
        raise _codec_error(path, "must be sorted canonically")
    return {provider: targets[provider] for provider in sorted(targets)}


def _decode_provider_targets(value: Any, path: str) -> tuple[tuple[str, str], ...]:
    raw = _exact_mapping(value, path)
    if set(raw) != set(TRUE_FAMILY_PROVIDER_MANIFEST):
        raise _codec_error(path, "must cover the provider manifest exactly")
    return tuple(
        (
            _provider(provider, f"{path}.{provider}"),
            _climate_entity(raw[provider], f"{path}.{provider}"),
        )
        for provider in sorted(raw)
    )


def _validate_plan(value: MigrationPlan) -> None:
    path = "migration_plan"
    _plan_id(value.plan_id, f"{path}.plan_id")
    _fingerprint(value.digest, f"{path}.digest")
    _string(value.room_id, f"{path}.room_id")
    _integer(value.room_revision, f"{path}.room_revision")
    old_entity_id = _climate_entity(value.old_entity_id, f"{path}.old_entity_id")
    logical_unique_id = _string(value.logical_unique_id, f"{path}.logical_unique_id")
    if not _LOGICAL_UNIQUE_ID_PATTERN.fullmatch(logical_unique_id):
        raise _codec_error(f"{path}.logical_unique_id", "is malformed")
    target_entity_id = value.target_entity_id
    if target_entity_id is not None:
        target_entity_id = _climate_entity(target_entity_id, f"{path}.target_entity_id")
    targets = _encode_provider_targets(value.provider_targets, f"{path}.provider_targets")
    if any(target == old_entity_id for target in targets.values()):
        raise _codec_error(f"{path}.provider_targets", "contains an unsafe target")
    if target_entity_id is not None and set(targets.values()) != {target_entity_id}:
        raise _codec_error(
            f"{path}.provider_targets",
            "must match the shared target entity ID",
        )
    if type(value.providers) is not tuple or value.providers != tuple(
        sorted(TRUE_FAMILY_PROVIDER_MANIFEST)
    ):
        raise _codec_error(f"{path}.providers", "must be the sorted provider manifest")
    _boolean(value.references_expected, f"{path}.references_expected")
    if type(value.documents) is not tuple:
        raise _codec_error(f"{path}.documents", "must be a tuple")
    for document in value.documents:
        encode_planned_document(document)
        changed = document.fingerprint != document.post_fingerprint
        if changed != bool(document.exact_paths):
            raise _codec_error(
                f"{path}.documents",
                "must identify changed documents exactly by their replacement paths",
            )
    document_keys = tuple((item.provider, item.object_id) for item in value.documents)
    if document_keys != tuple(sorted(document_keys)) or len(set(document_keys)) != len(
        document_keys
    ):
        raise _codec_error(
            f"{path}.documents",
            "must be unique and sorted by provider and object ID",
        )
    exact_replacements = _integer(
        value.exact_replacements,
        f"{path}.exact_replacements",
    )
    if exact_replacements != sum(len(item.exact_paths) for item in value.documents):
        raise _codec_error(f"{path}.exact_replacements", "does not match exact paths")

    validation_result = MigrationResult(
        plan_id=value.plan_id,
        digest=value.digest,
        state=MigrationState.COMPLETE,
        changed_documents=sum(bool(item.exact_paths) for item in value.documents),
        exact_replacements=value.exact_replacements,
        idempotent=False,
    )
    validation_snapshots = tuple(
        _DocumentSnapshot(
            provider=item.provider,
            object_id=item.object_id,
            revision=item.revision,
            writable=item.writable,
            fingerprint=item.post_fingerprint,
        )
        for item in value.documents
    )
    try:
        _validate_journaled_completion(
            JournaledCompletion(value, validation_result, validation_snapshots),
            value.plan_id,
        )
    except (MalformedReferenceDocumentError, TypeError, ValueError) as err:
        raise _codec_error(path, str(err)) from err


def encode_migration_plan(value: MigrationPlan) -> dict[str, Any]:
    """Encode one deterministic migration plan and validate its digest."""

    if not isinstance(value, MigrationPlan):
        raise _codec_error("migration_plan", "must be a MigrationPlan")
    _validate_plan(value)
    return {
        "plan_id": value.plan_id,
        "digest": value.digest,
        "room_id": value.room_id,
        "room_revision": value.room_revision,
        "old_entity_id": value.old_entity_id,
        "logical_unique_id": value.logical_unique_id,
        "target_entity_id": value.target_entity_id,
        "provider_targets": _encode_provider_targets(
            value.provider_targets,
            "migration_plan.provider_targets",
        ),
        "providers": list(value.providers),
        "references_expected": value.references_expected,
        "documents": [encode_planned_document(item) for item in value.documents],
        "exact_replacements": value.exact_replacements,
    }


def decode_migration_plan(value: Any) -> MigrationPlan:
    """Decode one strict migration plan and revalidate its canonical digest."""

    path = "migration_plan"
    raw = _exact_mapping(
        value,
        path,
        frozenset(
            {
                "plan_id",
                "digest",
                "room_id",
                "room_revision",
                "old_entity_id",
                "logical_unique_id",
                "target_entity_id",
                "provider_targets",
                "providers",
                "references_expected",
                "documents",
                "exact_replacements",
            }
        ),
    )
    providers = tuple(
        _provider(item, f"{path}.providers[{index}]")
        for index, item in enumerate(_exact_list(raw["providers"], f"{path}.providers"))
    )
    documents = tuple(
        decode_planned_document(item)
        for item in _exact_list(raw["documents"], f"{path}.documents")
    )
    target_entity_id = raw["target_entity_id"]
    if target_entity_id is not None:
        target_entity_id = _climate_entity(target_entity_id, f"{path}.target_entity_id")
    plan = MigrationPlan(
        plan_id=_plan_id(raw["plan_id"], f"{path}.plan_id"),
        digest=_fingerprint(raw["digest"], f"{path}.digest"),
        room_id=_string(raw["room_id"], f"{path}.room_id"),
        room_revision=_integer(raw["room_revision"], f"{path}.room_revision"),
        old_entity_id=_climate_entity(raw["old_entity_id"], f"{path}.old_entity_id"),
        logical_unique_id=_string(
            raw["logical_unique_id"],
            f"{path}.logical_unique_id",
        ),
        target_entity_id=target_entity_id,
        provider_targets=_decode_provider_targets(
            raw["provider_targets"],
            f"{path}.provider_targets",
        ),
        providers=providers,
        references_expected=_boolean(
            raw["references_expected"],
            f"{path}.references_expected",
        ),
        documents=documents,
        exact_replacements=_integer(
            raw["exact_replacements"],
            f"{path}.exact_replacements",
        ),
    )
    _validate_plan(plan)
    return plan


def _encode_execution_binding(
    binding: ReferencePlanExecutionBinding,
) -> dict[str, Any]:
    if not isinstance(binding, ReferencePlanExecutionBinding):
        raise TypeError("A ReferencePlanExecutionBinding is required.")
    binding.__post_init__()
    return {
        "execution_scope_digest": binding.execution_scope_digest,
        "recorder_id": binding.recorder_id,
        "journal_id": binding.journal_id,
        "provider_bridge_ids": [
            {"provider": provider, "bridge_id": bridge_id}
            for provider, bridge_id in binding.provider_bridge_ids
        ],
        "binding_digest": binding.digest,
    }


def _decode_execution_binding(
    value: Any,
    path: str,
) -> ReferencePlanExecutionBinding:
    raw = _exact_mapping(value, path, _EXECUTION_BINDING_KEYS)
    provider_bridges = _exact_list(
        raw["provider_bridge_ids"],
        f"{path}.provider_bridge_ids",
    )
    pairs: list[tuple[str, str]] = []
    for index, item in enumerate(provider_bridges):
        bridge_path = f"{path}.provider_bridge_ids[{index}]"
        bridge = _exact_mapping(item, bridge_path, _PROVIDER_BRIDGE_KEYS)
        pairs.append(
            (
                _provider(bridge["provider"], f"{bridge_path}.provider"),
                _journal_id(bridge["bridge_id"], f"{bridge_path}.bridge_id"),
            )
        )
    try:
        binding = ReferencePlanExecutionBinding(
            execution_scope_digest=_fingerprint(
                raw["execution_scope_digest"],
                f"{path}.execution_scope_digest",
            ),
            recorder_id=_journal_id(raw["recorder_id"], f"{path}.recorder_id"),
            journal_id=_journal_id(raw["journal_id"], f"{path}.journal_id"),
            provider_bridge_ids=tuple(pairs),
        )
    except (TypeError, ValueError) as err:
        raise _codec_error(path, str(err)) from err
    encoded = _encode_execution_binding(binding)
    if raw != encoded:
        raise _codec_error(path, "is not in canonical form")
    return binding


def _validate_execution_binding_for_plan(
    plan: MigrationPlan,
    binding: ReferencePlanExecutionBinding | None,
    *,
    expected_journal_id: str | None,
    path: str,
) -> None:
    changed = any(document.exact_paths for document in plan.documents)
    if binding is None:
        if changed:
            raise _codec_error(path, "is required for a changed migration plan")
        return
    if not isinstance(binding, ReferencePlanExecutionBinding):
        raise _codec_error(path, "must be a ReferencePlanExecutionBinding")
    binding.__post_init__()
    if expected_journal_id is not None and binding.journal_id != _journal_id(
        expected_journal_id,
        f"{path}.expected_journal_id",
    ):
        raise _codec_error(path, "journal ID does not match the Store journal")
    bound_providers = tuple(
        provider for provider, _bridge_id in binding.provider_bridge_ids
    )
    if bound_providers != plan.providers:
        raise _codec_error(path, "provider bridges do not match the migration plan")


def _encode_active_plan(
    plan: MigrationPlan,
    manifest_digest: str,
    execution_binding: ReferencePlanExecutionBinding | None,
    *,
    expected_journal_id: str | None = None,
) -> dict[str, Any]:
    _validate_execution_binding_for_plan(
        plan,
        execution_binding,
        expected_journal_id=expected_journal_id,
        path="active_plan.execution_binding",
    )
    return {
        "plan": encode_migration_plan(plan),
        "manifest_digest": _fingerprint(
            manifest_digest,
            "active_plan.manifest_digest",
        ),
        "execution_binding": (
            None
            if execution_binding is None
            else _encode_execution_binding(execution_binding)
        ),
    }


def _decode_active_plan(
    value: Any,
    path: str,
    *,
    expected_journal_id: str | None = None,
) -> tuple[MigrationPlan, str, ReferencePlanExecutionBinding | None]:
    raw = _exact_mapping(value, path, _ACTIVE_PLAN_KEYS)
    plan = decode_migration_plan(raw["plan"])
    manifest_digest = _fingerprint(
        raw["manifest_digest"],
        f"{path}.manifest_digest",
    )
    execution_binding = (
        None
        if raw["execution_binding"] is None
        else _decode_execution_binding(
            raw["execution_binding"],
            f"{path}.execution_binding",
        )
    )
    encoded = _encode_active_plan(
        plan,
        manifest_digest,
        execution_binding,
        expected_journal_id=expected_journal_id,
    )
    if raw != encoded:
        raise _codec_error(path, "is not in canonical form")
    return plan, manifest_digest, execution_binding


def _expected_writes_for_plan(
    plan: MigrationPlan,
    *,
    path: str = "migration_plan",
) -> tuple[BridgeExpectedWrite, ...]:
    writes: list[BridgeExpectedWrite] = []
    try:
        for document in plan.documents:
            if not document.exact_paths:
                continue
            writes.append(
                BridgeExpectedWrite(
                    provider=document.provider,
                    object_key=document.object_id,
                    expected_revision=document.revision,
                    pre_fingerprint=document.fingerprint,
                    post_fingerprint=document.post_fingerprint,
                )
            )
    except (TypeError, ValueError) as err:
        raise _codec_error(path, f"cannot produce exact bridge writes: {err}") from err
    return tuple(writes)


def _validate_result(value: MigrationResult) -> None:
    path = "migration_result"
    _plan_id(value.plan_id, f"{path}.plan_id")
    _fingerprint(value.digest, f"{path}.digest")
    if not isinstance(value.state, MigrationState):
        raise _codec_error(f"{path}.state", "must be a MigrationState")
    _integer(value.changed_documents, f"{path}.changed_documents")
    _integer(value.exact_replacements, f"{path}.exact_replacements")
    _boolean(value.idempotent, f"{path}.idempotent")


def encode_migration_result(value: MigrationResult) -> dict[str, Any]:
    """Encode one migration result."""

    if not isinstance(value, MigrationResult):
        raise _codec_error("migration_result", "must be a MigrationResult")
    _validate_result(value)
    return {
        "plan_id": value.plan_id,
        "digest": value.digest,
        "state": value.state.value,
        "changed_documents": value.changed_documents,
        "exact_replacements": value.exact_replacements,
        "idempotent": value.idempotent,
    }


def decode_migration_result(value: Any) -> MigrationResult:
    """Decode one strict migration result."""

    path = "migration_result"
    raw = _exact_mapping(
        value,
        path,
        frozenset(
            {
                "plan_id",
                "digest",
                "state",
                "changed_documents",
                "exact_replacements",
                "idempotent",
            }
        ),
    )
    state_value = _string(raw["state"], f"{path}.state")
    try:
        state = MigrationState(state_value)
    except ValueError as err:
        raise _codec_error(f"{path}.state", "contains an unknown migration state") from err
    result = MigrationResult(
        plan_id=_plan_id(raw["plan_id"], f"{path}.plan_id"),
        digest=_fingerprint(raw["digest"], f"{path}.digest"),
        state=state,
        changed_documents=_integer(
            raw["changed_documents"],
            f"{path}.changed_documents",
        ),
        exact_replacements=_integer(
            raw["exact_replacements"],
            f"{path}.exact_replacements",
        ),
        idempotent=_boolean(raw["idempotent"], f"{path}.idempotent"),
    )
    _validate_result(result)
    return result


def encode_document_snapshot(value: _DocumentSnapshot) -> dict[str, Any]:
    """Encode one private core document snapshot used by completions."""

    if not isinstance(value, _DocumentSnapshot):
        raise _codec_error("document_snapshot", "must be a _DocumentSnapshot")
    return {
        "provider": _provider(value.provider, "document_snapshot.provider"),
        "object_id": _string(value.object_id, "document_snapshot.object_id"),
        "revision": _encode_revision(value.revision, "document_snapshot.revision"),
        "writable": _boolean(value.writable, "document_snapshot.writable"),
        "fingerprint": _fingerprint(
            value.fingerprint,
            "document_snapshot.fingerprint",
        ),
    }


def decode_document_snapshot(value: Any) -> _DocumentSnapshot:
    """Decode one strict private core document snapshot."""

    path = "document_snapshot"
    raw = _exact_mapping(
        value,
        path,
        frozenset({"provider", "object_id", "revision", "writable", "fingerprint"}),
    )
    return _DocumentSnapshot(
        provider=_provider(raw["provider"], f"{path}.provider"),
        object_id=_string(raw["object_id"], f"{path}.object_id"),
        revision=_decode_revision(raw["revision"], f"{path}.revision"),
        writable=_boolean(raw["writable"], f"{path}.writable"),
        fingerprint=_fingerprint(raw["fingerprint"], f"{path}.fingerprint"),
    )


def _validate_completion(value: JournaledCompletion) -> None:
    path = "journaled_completion"
    if not isinstance(value.plan, MigrationPlan):
        raise _codec_error(f"{path}.plan", "must be a MigrationPlan")
    if not isinstance(value.result, MigrationResult):
        raise _codec_error(f"{path}.result", "must be a MigrationResult")
    encode_migration_plan(value.plan)
    encode_migration_result(value.result)
    if type(value.documents) is not tuple:
        raise _codec_error(f"{path}.documents", "must be a tuple")
    for snapshot in value.documents:
        encode_document_snapshot(snapshot)
    snapshot_keys = tuple((item.provider, item.object_id) for item in value.documents)
    if snapshot_keys != tuple(sorted(snapshot_keys)) or len(set(snapshot_keys)) != len(
        snapshot_keys
    ):
        raise _codec_error(
            f"{path}.documents",
            "must be unique and sorted by provider and object ID",
        )
    try:
        _validate_journaled_completion(value, value.plan.plan_id)
    except (MalformedReferenceDocumentError, TypeError, ValueError) as err:
        raise _codec_error(path, str(err)) from err


def encode_journaled_completion(value: JournaledCompletion) -> dict[str, Any]:
    """Encode one fully validated durable completion."""

    if not isinstance(value, JournaledCompletion):
        raise _codec_error("journaled_completion", "must be a JournaledCompletion")
    _validate_completion(value)
    return {
        "plan": encode_migration_plan(value.plan),
        "result": encode_migration_result(value.result),
        "documents": [encode_document_snapshot(item) for item in value.documents],
    }


def decode_journaled_completion(value: Any) -> JournaledCompletion:
    """Decode and cross-validate one strict durable completion."""

    path = "journaled_completion"
    raw = _exact_mapping(
        value,
        path,
        frozenset({"plan", "result", "documents"}),
    )
    completion = JournaledCompletion(
        plan=decode_migration_plan(raw["plan"]),
        result=decode_migration_result(raw["result"]),
        documents=tuple(
            decode_document_snapshot(item)
            for item in _exact_list(raw["documents"], f"{path}.documents")
        ),
    )
    _validate_completion(completion)
    return completion


def _encode_bound_completion(
    completion: JournaledCompletion,
    execution_binding: ReferencePlanExecutionBinding | None,
) -> dict[str, Any]:
    return {
        "execution_binding_digest": (
            None if execution_binding is None else execution_binding.digest
        ),
        "completion": encode_journaled_completion(completion),
    }


def _decode_bound_completion(
    value: Any,
    execution_binding: ReferencePlanExecutionBinding | None,
    path: str,
) -> JournaledCompletion:
    raw = _exact_mapping(value, path, _BOUND_COMPLETION_KEYS)
    completion = decode_journaled_completion(raw["completion"])
    encoded = _encode_bound_completion(completion, execution_binding)
    if raw != encoded:
        raise _codec_error(path, "does not match its exact execution binding")
    return completion


def _original_matches_planned(
    original: JournaledOriginal,
    planned: PlannedDocument,
) -> bool:
    document = original.document
    return (
        document.provider == planned.provider
        and document.object_id == planned.object_id
        and type(document.revision) is type(planned.revision)
        and document.revision == planned.revision
        and document.writable is planned.writable
        and canonical_document_fingerprint(document) == planned.fingerprint
        and original.post_fingerprint == planned.post_fingerprint
    )


def _original_matches_write_intent(
    original: JournaledOriginal,
    intent: BridgeOperationIntent,
) -> bool:
    document = original.document
    return (
        intent.kind is BridgeOperationKind.WRITE
        and document.provider == intent.provider
        and document.object_id == intent.object_key
        and canonical_document_fingerprint(document) == intent.pre_fingerprint
        and original.post_fingerprint == intent.post_fingerprint
    )


def _validate_operation_original_binding(
    originals: Mapping[str, Sequence[JournaledOriginal]],
    journal: InMemoryBridgeOperationJournal,
    operation_id: str,
) -> None:
    record = journal.get_operation(operation_id)
    intent = record.intent
    write_intent = intent
    if intent.kind is BridgeOperationKind.ROLLBACK:
        parent_operation_id = intent.parent_operation_id
        if parent_operation_id is None:
            raise BridgeJournalConflict("Rollback dispatch lacks its parent write.")
        try:
            parent = journal.get_operation(parent_operation_id)
        except KeyError as err:
            raise BridgeJournalConflict(
                "Rollback dispatch parent is not durably journaled."
            ) from err
        parent_applied = (
            parent.intent.kind is BridgeOperationKind.WRITE
            and (
                parent.state is BridgeOperationState.VERIFIED
                or (
                    parent.state is BridgeOperationState.BLOCKED
                    and parent.blocked_from is BridgeOperationState.VERIFIED
                )
            )
            and parent.receipt is not None
            and parent.verification is not None
            and parent.receipt.outcome is BridgeReceiptOutcome.APPLIED
        )
        rollback_matches_parent = (
            intent.plan_id == parent.intent.plan_id
            and intent.plan_digest == parent.intent.plan_digest
            and intent.manifest_digest == parent.intent.manifest_digest
            and intent.attempt == parent.intent.attempt
            and intent.provider == parent.intent.provider
            and intent.object_key == parent.intent.object_key
            and intent.pre_fingerprint == parent.intent.post_fingerprint
            and intent.post_fingerprint == parent.intent.pre_fingerprint
            and parent.receipt is not None
            and type(intent.expected_revision) is type(parent.receipt.result_revision)
            and intent.expected_revision == parent.receipt.result_revision
        )
        if not parent_applied or not rollback_matches_parent:
            raise BridgeJournalConflict(
                "Rollback dispatch lacks its exact verified applied parent write."
            )
        write_intent = parent.intent

    matching = tuple(
        original
        for original in originals.get(intent.plan_id, ())
        if original.document.provider == write_intent.provider
        and original.document.object_id == write_intent.object_key
    )
    if len(matching) != 1 or not _original_matches_write_intent(
        matching[0],
        write_intent,
    ):
        raise BridgeJournalConflict(
            "Object dispatch requires its exact durable JournaledOriginal."
        )


def _journaled_original_values(
    content: Mapping[str, Any],
) -> dict[str, tuple[JournaledOriginal, ...]]:
    return {
        plan_id: tuple(decode_journaled_original(item) for item in encoded)
        for plan_id, encoded in content["originals"].items()
    }


def _encode_state(state: MigrationState, reason: str | None) -> dict[str, Any]:
    if not isinstance(state, MigrationState):
        raise _codec_error("journal state", "must be a MigrationState")
    if reason is not None and type(reason) is not str:
        raise _codec_error("journal state reason", "must be a string or null")
    return {"state": state.value, "reason": reason}


def _decode_state(value: Any, path: str) -> tuple[MigrationState, str | None]:
    raw = _exact_mapping(value, path, _STATE_KEYS)
    state_value = _string(raw["state"], f"{path}.state")
    try:
        state = MigrationState(state_value)
    except ValueError as err:
        raise _codec_error(f"{path}.state", "contains an unknown migration state") from err
    return state, _optional_string(raw["reason"], f"{path}.reason")


def _build_root(
    journal_id: str,
    generation: int,
    content: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": REFERENCE_JOURNAL_SCHEMA,
        "journal_id": _journal_id(journal_id),
        "generation": _integer(generation, "generation"),
        "content": deepcopy(content),
    }
    return {**body, "content_digest": _content_digest(body)}


def empty_reference_journal_data(journal_id: str) -> dict[str, Any]:
    """Return the sole valid generation-zero journal provisioning payload."""

    return _build_root(
        journal_id,
        0,
        {
            "states": {},
            "active_plans": {},
            "originals": {},
            "completions": {},
            "bridge_operations": {},
        },
    )


def decode_reference_journal_data(
    value: Any,
    *,
    expected_journal_id: str | None = None,
) -> dict[str, Any]:
    """Validate and return a canonical copy of one complete journal root."""

    path = "reference_journal"
    raw = _exact_mapping(value, path, _ROOT_KEYS)
    if type(raw["schema"]) is not int or raw["schema"] != REFERENCE_JOURNAL_SCHEMA:
        raise _codec_error(f"{path}.schema", "contains an unsupported schema")
    journal_id = _journal_id(raw["journal_id"], f"{path}.journal_id")
    if expected_journal_id is not None:
        expected = _journal_id(expected_journal_id, "expected_journal_id")
        if journal_id != expected:
            raise _codec_error(f"{path}.journal_id", "does not match the expected journal")
    generation = _integer(raw["generation"], f"{path}.generation")
    digest = _fingerprint(raw["content_digest"], f"{path}.content_digest")
    body = {
        "schema": raw["schema"],
        "journal_id": raw["journal_id"],
        "generation": raw["generation"],
        "content": raw["content"],
    }
    if digest != _content_digest(body):
        raise _codec_error(f"{path}.content_digest", "does not match canonical content")

    content = _exact_mapping(raw["content"], f"{path}.content", _CONTENT_KEYS)
    states_raw = _exact_mapping(content["states"], f"{path}.content.states")
    active_plans_raw = _exact_mapping(
        content["active_plans"],
        f"{path}.content.active_plans",
    )
    originals_raw = _exact_mapping(content["originals"], f"{path}.content.originals")
    completions_raw = _exact_mapping(
        content["completions"],
        f"{path}.content.completions",
    )
    bridge_operations_raw = _exact_mapping(
        content["bridge_operations"],
        f"{path}.content.bridge_operations",
    )

    states: dict[str, dict[str, Any]] = {}
    for raw_plan_id in sorted(states_raw):
        plan_id = _plan_id(raw_plan_id, f"{path}.content.states key")
        state, reason = _decode_state(
            states_raw[raw_plan_id],
            f"{path}.content.states.{plan_id}",
        )
        states[plan_id] = _encode_state(state, reason)

    active_plans: dict[str, dict[str, Any]] = {}
    active_plan_values: dict[
        str,
        tuple[MigrationPlan, str, ReferencePlanExecutionBinding | None],
    ] = {}
    for raw_plan_id in sorted(active_plans_raw):
        plan_id = _plan_id(raw_plan_id, f"{path}.content.active_plans key")
        active_plan, manifest_digest, execution_binding = _decode_active_plan(
            active_plans_raw[raw_plan_id],
            f"{path}.content.active_plans.{plan_id}",
            expected_journal_id=journal_id,
        )
        if active_plan.plan_id != plan_id:
            raise _codec_error(
                f"{path}.content.active_plans.{plan_id}",
                "has a mismatched plan ID",
            )
        active_plans[plan_id] = _encode_active_plan(
            active_plan,
            manifest_digest,
            execution_binding,
            expected_journal_id=journal_id,
        )
        active_plan_values[plan_id] = (
            active_plan,
            manifest_digest,
            execution_binding,
        )

    originals: dict[str, list[dict[str, Any]]] = {}
    original_values: dict[str, tuple[JournaledOriginal, ...]] = {}
    for raw_plan_id in sorted(originals_raw):
        plan_id = _plan_id(raw_plan_id, f"{path}.content.originals key")
        entries = tuple(
            decode_journaled_original(item)
            for item in _exact_list(
                originals_raw[raw_plan_id],
                f"{path}.content.originals.{plan_id}",
            )
        )
        entry_keys = tuple(
            (item.document.provider, item.document.object_id) for item in entries
        )
        if entry_keys != tuple(sorted(entry_keys)) or len(set(entry_keys)) != len(
            entry_keys
        ):
            raise _codec_error(
                f"{path}.content.originals.{plan_id}",
                "must be unique and sorted by provider and object ID",
            )
        originals[plan_id] = [encode_journaled_original(item) for item in entries]
        original_values[plan_id] = entries

    completions: dict[str, dict[str, Any]] = {}
    completion_values: dict[str, JournaledCompletion] = {}
    for raw_plan_id in sorted(completions_raw):
        plan_id = _plan_id(raw_plan_id, f"{path}.content.completions key")
        try:
            _active_plan, _manifest_digest, execution_binding = active_plan_values[
                plan_id
            ]
        except KeyError as err:
            raise _codec_error(
                f"{path}.content.completions.{plan_id}",
                "has no active plan execution binding",
            ) from err
        completion = _decode_bound_completion(
            completions_raw[raw_plan_id],
            execution_binding,
            f"{path}.content.completions.{plan_id}",
        )
        if completion.plan.plan_id != plan_id:
            raise _codec_error(
                f"{path}.content.completions.{plan_id}",
                "has a mismatched plan ID",
            )
        completions[plan_id] = _encode_bound_completion(
            completion,
            execution_binding,
        )
        completion_values[plan_id] = completion

    if not set(active_plans).issubset(states):
        raise _codec_error(
            f"{path}.content.active_plans",
            "contains a plan without state",
        )
    if not set(originals).issubset(active_plans):
        raise _codec_error(
            f"{path}.content.originals",
            "contains a plan without an active plan binding",
        )
    if not set(completions).issubset(active_plans):
        raise _codec_error(
            f"{path}.content.completions",
            "contains a plan without an active plan binding",
        )
    plan_required_states = {
        MigrationState.APPLYING.value,
        MigrationState.BLOCKED.value,
        MigrationState.COMPLETE.value,
    }
    if any(
        record["state"] in plan_required_states and plan_id not in active_plans
        for plan_id, record in states.items()
    ):
        raise _codec_error(
            f"{path}.content.states",
            "contains an active migration without its exact plan binding",
        )
    for plan_id, encoded_originals in originals.items():
        plan, _manifest_digest, _execution_binding = active_plan_values[plan_id]
        planned_changes = {
            (item.provider, item.object_id): item
            for item in plan.documents
            if item.exact_paths
        }
        for encoded_original in encoded_originals:
            original = decode_journaled_original(encoded_original)
            key = (original.document.provider, original.document.object_id)
            planned = planned_changes.get(key)
            if planned is None or not _original_matches_planned(original, planned):
                raise _codec_error(
                    f"{path}.content.originals.{plan_id}",
                    "contains an original outside the exact active plan",
                )
    completed_states = {
        plan_id
        for plan_id, record in states.items()
        if record["state"] == MigrationState.COMPLETE.value
    }
    if not completed_states.issubset(completions):
        raise _codec_error(
            f"{path}.content.states",
            "contains a complete plan without a durable completion",
        )
    for plan_id, completion in completion_values.items():
        active_plan, _manifest_digest, _execution_binding = active_plan_values[plan_id]
        if completion.plan != active_plan:
            raise _codec_error(
                f"{path}.content.completions.{plan_id}",
                "does not match the exact active plan",
            )
        expected_originals = {
            (document.provider, document.object_id): document
            for document in completion.plan.documents
            if document.exact_paths
        }
        actual_originals = {
            (item.document.provider, item.document.object_id): item
            for item in (
                decode_journaled_original(value)
                for value in originals.get(plan_id, ())
            )
        }
        if set(actual_originals) != set(expected_originals):
            raise _codec_error(
                f"{path}.content.originals.{plan_id}",
                "does not cover every changed completion document exactly",
            )
        for key, planned in expected_originals.items():
            original = actual_originals[key]
            if not _original_matches_planned(original, planned):
                raise _codec_error(
                    f"{path}.content.originals.{plan_id}",
                    "does not match the completed plan preimage and postimage",
                )

    bridge_operations = _decode_bridge_operation_content(
        bridge_operations_raw,
        states,
        active_plan_values,
        original_values,
        f"{path}.content.bridge_operations",
    )

    for plan_id, completion in completion_values.items():
        plan, manifest_digest, execution_binding = active_plan_values[plan_id]
        try:
            _validate_completion_transaction_coverage(
                plan,
                manifest_digest,
                execution_binding,
                bridge_operations.get(plan_id, ()),
            )
        except (BridgeJournalConflict, TypeError, ValueError) as err:
            raise _codec_error(
                f"{path}.content.completions.{plan_id}",
                "does not have exact committed transaction coverage",
            ) from err

    normalized_content = {
        "states": states,
        "active_plans": active_plans,
        "originals": originals,
        "completions": completions,
        "bridge_operations": bridge_operations,
    }
    if content != normalized_content:
        raise _codec_error(f"{path}.content", "is not in canonical form")
    return _build_root(journal_id, generation, normalized_content)


def _encode_bound_attempt(
    attempt: BridgeOperationAttempt,
    execution_binding: ReferencePlanExecutionBinding,
) -> dict[str, Any]:
    if not isinstance(execution_binding, ReferencePlanExecutionBinding):
        raise TypeError("A bridge attempt requires an execution binding.")
    return {
        "execution_binding_digest": execution_binding.digest,
        "attempt": encode_bridge_operation_attempt(attempt),
    }


def _decode_bound_attempt(
    value: Any,
    execution_binding: ReferencePlanExecutionBinding | None,
    path: str,
) -> BridgeOperationAttempt:
    raw = _exact_mapping(value, path, _BOUND_ATTEMPT_KEYS)
    if execution_binding is None:
        raise _codec_error(path, "has no active execution binding")
    attempt = decode_bridge_operation_attempt(raw["attempt"])
    encoded = _encode_bound_attempt(attempt, execution_binding)
    if raw != encoded:
        raise _codec_error(path, "does not match its exact execution binding")
    return attempt


def _validate_attempt_plan_binding(
    attempt: BridgeOperationAttempt,
    plan: MigrationPlan,
    manifest_digest: str,
    execution_binding: ReferencePlanExecutionBinding | None,
) -> None:
    expected_writes = _expected_writes_for_plan(plan)
    bound_providers = (
        set()
        if execution_binding is None
        else {
            provider for provider, _bridge_id in execution_binding.provider_bridge_ids
        }
    )
    attempt_providers = {
        item.provider for item in attempt.expected_writes
    } | {
        item.intent.provider for item in attempt.acquisitions
    } | {
        item.intent.provider for item in attempt.operations
    } | {
        item.intent.provider for item in attempt.releases
    }
    if (
        attempt.plan_id != plan.plan_id
        or attempt.plan_digest != plan.digest
        or attempt.manifest_digest != manifest_digest
        or execution_binding is None
        or not attempt_providers.issubset(bound_providers)
        or len(attempt.expected_writes) != len(expected_writes)
        or any(
            actual.provider != expected.provider
            or actual.object_key != expected.object_key
            or actual.pre_fingerprint != expected.pre_fingerprint
            or actual.post_fingerprint != expected.post_fingerprint
            or (
                attempt.attempt == 1
                and (
                    type(actual.expected_revision)
                    is not type(expected.expected_revision)
                    or actual.expected_revision != expected.expected_revision
                )
            )
            for actual, expected in zip(
                attempt.expected_writes,
                expected_writes,
                strict=True,
            )
        )
    ):
        raise BridgeJournalConflict(
            "Bridge attempt does not match its exact plan, manifest, and execution binding."
        )


def _validate_completion_transaction_coverage(
    plan: MigrationPlan,
    manifest_digest: str,
    execution_binding: ReferencePlanExecutionBinding | None,
    encoded_attempts: Sequence[dict[str, Any]],
) -> None:
    expected_writes = _expected_writes_for_plan(plan)
    if not expected_writes:
        if encoded_attempts:
            raise BridgeJournalConflict(
                "An unchanged plan cannot contain bridge write attempts."
            )
        return
    if not encoded_attempts:
        raise BridgeJournalConflict(
            "A changed plan requires a committed bridge write attempt."
        )
    attempts = tuple(
        _decode_bound_attempt(
            item,
            execution_binding,
            f"bridge_operations[{index}]",
        )
        for index, item in enumerate(encoded_attempts)
    )
    for attempt in attempts:
        _validate_attempt_plan_binding(
            attempt,
            plan,
            manifest_digest,
            execution_binding,
        )
    if attempts[-1].state is not BridgeAttemptState.COMMITTED:
        raise BridgeJournalConflict(
            "A changed plan requires a committed final bridge attempt."
        )


def _decode_bridge_operation_content(
    value: dict[str, Any],
    states: dict[str, dict[str, Any]],
    active_plans: dict[
        str,
        tuple[MigrationPlan, str, ReferencePlanExecutionBinding | None],
    ],
    originals: Mapping[str, Sequence[JournaledOriginal]],
    path: str,
) -> dict[str, list[dict[str, Any]]]:
    journal = InMemoryBridgeOperationJournal()
    normalized: dict[str, list[dict[str, Any]]] = {}
    for raw_plan_id in sorted(value):
        plan_id = _plan_id(raw_plan_id, f"{path} key")
        if plan_id not in states:
            raise _codec_error(path, "contains operations without a plan state")
        if plan_id not in active_plans:
            raise _codec_error(path, "contains operations without an active plan")
        active_plan, manifest_digest, execution_binding = active_plans[plan_id]
        if execution_binding is None:
            raise _codec_error(path, "contains operations without execution binding")
        raw_attempts = _exact_list(value[raw_plan_id], f"{path}.{plan_id}")
        if not raw_attempts:
            raise _codec_error(f"{path}.{plan_id}", "must contain an attempt")
        attempts: list[BridgeOperationAttempt] = []
        try:
            for expected_number, raw_attempt in enumerate(raw_attempts, start=1):
                attempt = _decode_bound_attempt(
                    raw_attempt,
                    execution_binding,
                    f"{path}.{plan_id}[{expected_number - 1}]",
                )
                if attempt.plan_id != plan_id or attempt.attempt != expected_number:
                    raise ValueError(
                        "Bridge attempts do not match their plan key and position."
                    )
                _validate_attempt_plan_binding(
                    attempt,
                    active_plan,
                    manifest_digest,
                    execution_binding,
                )
                journal.append_attempt(attempt)
                attempts.append(attempt)
            for attempt in attempts:
                for record in attempt.operations:
                    if record.authorization is not None:
                        _validate_operation_original_binding(
                            originals,
                            journal,
                            record.intent.operation_id,
                        )
        except (BridgeJournalConflict, TypeError, ValueError) as err:
            raise _codec_error(
                f"{path}.{plan_id}",
                "contains invalid bridge operation history",
            ) from err

        migration_state = MigrationState(states[plan_id]["state"])
        attempt_state = attempts[-1].state
        allowed_migration_states = {
            BridgeAttemptState.OPEN: {MigrationState.APPLYING},
            BridgeAttemptState.COMMITTED: {
                MigrationState.APPLYING,
                MigrationState.COMPLETE,
            },
            BridgeAttemptState.RESTORED: {
                MigrationState.PLANNED,
                MigrationState.APPLYING,
                MigrationState.FAILED,
                MigrationState.BLOCKED,
            },
            BridgeAttemptState.BLOCKED: {
                MigrationState.APPLYING,
                MigrationState.BLOCKED,
            },
        }
        if migration_state not in allowed_migration_states[attempt_state]:
            raise _codec_error(
                f"{path}.{plan_id}",
                "is incompatible with the migration plan state",
            )
        if (
            migration_state is MigrationState.COMPLETE
            and attempt_state is not BridgeAttemptState.COMMITTED
        ):
            raise _codec_error(
                f"{path}.{plan_id}",
                "does not contain a committed final attempt",
            )
        if (
            migration_state is MigrationState.FAILED
            and attempt_state is not BridgeAttemptState.RESTORED
        ):
            raise _codec_error(
                f"{path}.{plan_id}",
                "failed without a fully restored final attempt",
            )
        normalized[plan_id] = [
            _encode_bound_attempt(attempt, execution_binding)
            for attempt in attempts
        ]
    return normalized


def _bridge_journal_from_content(
    content: dict[str, Any],
) -> tuple[
    InMemoryBridgeOperationJournal,
    set[str],
    dict[str, ReferencePlanExecutionBinding],
]:
    journal = InMemoryBridgeOperationJournal()
    plan_ids = set(content["bridge_operations"])
    execution_bindings: dict[str, ReferencePlanExecutionBinding] = {}
    for plan_id in sorted(plan_ids):
        plan, manifest_digest, execution_binding = _decode_active_plan(
            content["active_plans"][plan_id],
            f"active_plans.{plan_id}",
        )
        if execution_binding is None:
            raise BridgeJournalConflict(
                "Bridge operation history lacks an execution binding."
            )
        execution_bindings[plan_id] = execution_binding
        for index, raw_attempt in enumerate(content["bridge_operations"][plan_id]):
            attempt = _decode_bound_attempt(
                raw_attempt,
                execution_binding,
                f"bridge_operations.{plan_id}[{index}]",
            )
            _validate_attempt_plan_binding(
                attempt,
                plan,
                manifest_digest,
                execution_binding,
            )
            journal.append_attempt(attempt)
    return journal, plan_ids, execution_bindings


def _encode_bridge_journal(
    journal: InMemoryBridgeOperationJournal,
    plan_ids: set[str],
    execution_bindings: Mapping[str, ReferencePlanExecutionBinding],
) -> dict[str, list[dict[str, Any]]]:
    return {
        plan_id: [
            _encode_bound_attempt(attempt, execution_bindings[plan_id])
            for attempt in journal.attempts_for(plan_id)
        ]
        for plan_id in sorted(plan_ids)
        if journal.attempts_for(plan_id)
    }


async def _new_store(
    hass: HomeAssistant,
    journal_id: str,
) -> ReferenceJournalOwnedStore:
    """Open the discovered companion App as the sole production backend."""

    endpoint = get_reference_journal_endpoint(hass)
    if endpoint is None:
        raise ReferenceJournalIOError(
            "The True Family journal App is not currently discovered."
        )
    try:
        return await reference_journal_remote.RemoteReferenceJournalStore.async_open(
            hass,
            journal_id=journal_id,
            endpoint=endpoint,
        )
    except reference_journal_remote.RemoteJournalError as err:
        normalized = _normalized_backend_error(err)
        if normalized is None:
            raise ReferenceJournalDurabilityError(
                "The remote reference journal failed closed."
            ) from err
        raise normalized from err


def _select_durability_barrier(
    store: ReferenceJournalStore,
    barrier: ReferenceJournalDurabilityBarrier | None,
    *,
    owns_store: bool = False,
    allow_test: bool = False,
) -> ReferenceJournalDurabilityBarrier:
    if not isinstance(store, ReferenceJournalStore):
        raise TypeError("A reference journal store is required.")
    if owns_store:
        if not isinstance(store, ReferenceJournalOwnedStore):
            raise ReferenceJournalDurabilityError(
                "The owned reference journal does not provide its full lifecycle."
            )
        if barrier is not None and barrier is not store:
            raise ReferenceJournalDurabilityError(
                "The owned reference journal store must be its own exact barrier."
            )
        selected: ReferenceJournalDurabilityBarrier = store
    else:
        if barrier is None:
            raise ReferenceJournalDurabilityError(
                "An injected journal store requires an explicit strong test barrier."
            )
        selected = barrier
    if not callable(getattr(selected, "async_barrier", None)):
        raise TypeError("A reference journal durability barrier is required.")
    proof = _require_strong_durability_barrier(
        selected,
        allow_test=allow_test,
    )
    if type(proof) is ReferenceJournalDurabilityProof and selected is not store:
        raise ReferenceJournalDurabilityError(
            "A production durability proof must belong to the exact Store object."
        )
    return selected


def _normalized_backend_error(
    err: BaseException,
    *,
    mutation: bool = False,
) -> ReferenceJournalCodecError | ReferenceJournalDurabilityError | None:
    """Translate backend failures without exposing endpoints or journal data."""

    if isinstance(err, (ReferenceJournalCodecError, ReferenceJournalDurabilityError)):
        return err

    if isinstance(
        err,
        (
            reference_journal_remote.RemoteJournalAmbiguousMutationError,
            reference_journal_remote.RemoteJournalPoisonedError,
            reference_journal_remote.RemoteJournalClosedError,
        ),
    ):
        return ReferenceJournalDurabilityError(
            "The remote reference journal has an ambiguous durability state."
        )
    if isinstance(err, reference_journal_remote.RemoteJournalConflictError):
        return ReferenceJournalConflictError(
            "The reference journal changed concurrently."
        )
    if isinstance(err, reference_journal_remote.RemoteJournalAuthenticationError):
        return ReferenceJournalIOError(
            "The remote reference journal App generation is temporarily unavailable."
        )
    if isinstance(err, reference_journal_remote.RemoteJournalCorruptionError):
        return ReferenceJournalCorruptionError(
            "The remote reference journal returned corrupt or noncanonical data."
        )
    if isinstance(err, reference_journal_remote.RemoteJournalProtocolError):
        return ReferenceJournalCodecError(
            "The remote reference journal violated its signed protocol."
        )
    if isinstance(err, reference_journal_remote.RemoteJournalUnavailableError):
        if mutation:
            return ReferenceJournalDurabilityError(
                "The remote reference journal mutation has an ambiguous outcome."
            )
        return ReferenceJournalIOError(
            "The remote reference journal is temporarily unavailable."
        )
    if isinstance(err, reference_journal_remote.RemoteJournalError):
        return ReferenceJournalDurabilityError(
            "The remote reference journal failed closed."
        )

    if isinstance(err, reference_journal_file.ReferenceJournalSecurityError):
        return ReferenceJournalSecurityError(
            "Reference journal data failed its trusted-file security checks."
        )
    if isinstance(err, reference_journal_file.ReferenceJournalCorruptionError):
        return ReferenceJournalCorruptionError(
            "Reference journal data is corrupt or noncanonical."
        )
    if isinstance(err, reference_journal_file.ReferenceJournalBusyError):
        return ReferenceJournalBusyError("Reference journal storage is busy.")
    if isinstance(err, reference_journal_file.ReferenceJournalConflictError):
        return ReferenceJournalConflictError(
            "The reference journal changed concurrently."
        )
    if isinstance(
        err,
        (
            reference_journal_file.ReferenceJournalAmbiguousDurabilityError,
            reference_journal_file.ReferenceJournalPoisonedError,
            reference_journal_file.ReferenceJournalClosedError,
        ),
    ):
        return ReferenceJournalDurabilityError(
            "The reference journal has an ambiguous durability state."
        )
    if isinstance(err, reference_journal_file.ReferenceJournalProtocolError):
        return ReferenceJournalCodecError(
            "The reference journal backend violated its operation protocol."
        )
    if isinstance(err, reference_journal_file.ReferenceJournalCertificationError):
        return ReferenceJournalCertificationError(
            "External reference journal durability certification is unavailable."
        )
    if isinstance(
        err,
        reference_journal_file.ReferenceJournalUnsupportedFilesystemError,
    ):
        return ReferenceJournalUnsupportedFilesystemError(
            "Crash-durable reference journal storage is unavailable."
        )
    if isinstance(err, reference_journal_file.ReferenceJournalFileError):
        return ReferenceJournalIOError(
            "Reference journal storage could not complete a safe I/O operation."
        )
    return None


def _raise_normalized_backend_error(
    err: BaseException,
    fallback: ReferenceJournalCodecError | ReferenceJournalDurabilityError,
    *,
    mutation: bool = False,
) -> NoReturn:
    normalized = _normalized_backend_error(err, mutation=mutation)
    if normalized is None:
        raise fallback from err
    if normalized is err:
        raise err
    raise normalized from err


def _require_strong_durability_barrier(
    barrier: ReferenceJournalDurabilityBarrier,
    *,
    allow_test: bool,
) -> ReferenceJournalDurabilityProof:
    try:
        proof = barrier.durability_proof
    except (AttributeError, TypeError, ValueError) as err:
        raise ReferenceJournalDurabilityError(
            "The durability barrier has no valid nominal proof identity."
        ) from err
    if type(proof) is ReferenceJournalDurabilityProof:
        try:
            _validate_durability_proof_fields(
                proof.provider_id,
                proof.guarantee,
                proof.scope,
                proof.identity_digest,
                test_only=False,
            )
        except (TypeError, ValueError) as err:
            raise ReferenceJournalDurabilityError(
                "The durability barrier has an invalid production proof."
            ) from err
        if proof._backend is not barrier or type(barrier) not in {
            reference_journal_remote.RemoteReferenceJournalStore,
            reference_journal_file.CrashDurableReferenceJournalStore,
        }:
            raise ReferenceJournalDurabilityError(
                "The production durability proof is not bound to its exact known backend."
            )
        return proof
    if type(proof) is ReferenceJournalTestDurabilityProof and allow_test:
        try:
            _validate_durability_proof_fields(
                proof.provider_id,
                proof.guarantee,
                proof.scope,
                proof.identity_digest,
                test_only=True,
            )
        except (TypeError, ValueError) as err:
            raise ReferenceJournalDurabilityError(
                "The injected durability barrier has an invalid test proof."
            ) from err
        if proof._backend is not None and proof._backend is not barrier:
            raise ReferenceJournalDurabilityError(
                "The test durability proof belongs to a different backend."
            )
        return proof
    if isinstance(proof, ReferenceJournalDurabilityProof):
        raise ReferenceJournalDurabilityError(
            "The durability proof has an unsupported grade or subclass."
        )
    raise ReferenceJournalDurabilityError(
        "The durability barrier cannot prove a supported crash-durability guarantee."
    )


def _journal_runtime(hass: HomeAssistant) -> dict[str, Any]:
    runtime = hass.data.get(REFERENCE_JOURNAL_RUNTIME_DATA)
    if runtime is None:
        runtime = {
            "lock": asyncio.Lock(),
            "owner": None,
        }
        hass.data[REFERENCE_JOURNAL_RUNTIME_DATA] = runtime
    return runtime


def _test_durability_injection_enabled(hass: HomeAssistant) -> bool:
    """Recognize only the existing explicitly branded test policy seam."""

    policy = hass.data.get(REFERENCE_JOURNAL_FILESYSTEM_POLICY_DATA)
    return (
        type(policy) is reference_journal_file.DurableFilesystemPolicy
        and policy.test_only
    )


def _require_hass_loop(hass: HomeAssistant) -> asyncio.AbstractEventLoop:
    loop = asyncio.get_running_loop()
    if loop is not hass.loop:
        raise ReferenceJournalThreadError(
            "The reference journal async factory must run on Home Assistant's event loop."
        )
    return loop


async def _await_shielded_completion(
    future: asyncio.Future[_T],
) -> tuple[_T, asyncio.CancelledError | None]:
    """Drain one owned future despite any number of caller cancellations."""

    cancelled: asyncio.CancelledError | None = None
    while True:
        try:
            result = await asyncio.shield(future)
            return result, cancelled
        except asyncio.CancelledError as err:
            if future.cancelled():
                raise
            if cancelled is None:
                cancelled = err


async def _async_close_owned_backend(
    store: ReferenceJournalOwnedStore,
) -> asyncio.CancelledError | None:
    """Close one internally opened backend despite repeated caller cancellation."""

    close_task = asyncio.create_task(store.async_close())
    _result, cancelled = await _await_shielded_completion(close_task)
    return cancelled


class HomeAssistantMigrationAuthority:
    """Worker-thread-only resolver for trusted migration subjects.

    Construction must happen on Home Assistant's event loop after the True
    Family config entry is loaded.  The captured runtime object is part of the
    authority identity, so an adapter cannot survive an unload or reload.  Each
    resolution is marshalled back to the event loop and uses only read APIs.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        policy: HomeAssistantMigrationTargetPolicy,
    ) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as err:
            raise MigrationAuthorityThreadError(
                "Migration authority must be constructed on Home Assistant's event loop."
            ) from err
        if loop is not hass.loop:
            raise MigrationAuthorityThreadError(
                "Migration authority must be constructed on Home Assistant's event loop."
            )
        if not isinstance(policy, HomeAssistantMigrationTargetPolicy):
            raise MigrationAuthorityPolicyError(
                "A complete immutable migration target policy is required."
            )
        if getattr(entry, "domain", None) != DOMAIN:
            raise MigrationAuthorityError("The authority config entry is not True Family.")

        self._hass = hass
        self._entry = entry
        self._policy = policy
        self._room_policies = MappingProxyType(
            {room.room_id: room for room in policy.rooms}
        )
        self._loop = loop
        self._loop_thread_id = threading.get_ident()
        self._runtime = self._require_registered_runtime()

    @classmethod
    async def async_create(
        cls,
        hass: HomeAssistant,
        entry: ConfigEntry,
        policy: HomeAssistantMigrationTargetPolicy,
    ) -> HomeAssistantMigrationAuthority:
        """Capture the loaded runtime identity on Home Assistant's event loop."""

        return cls(hass, entry, policy)

    def resolve_subject(self, room_id: str) -> MigrationSubject:
        """Resolve one fresh subject from trusted state on the HA event loop."""

        self._require_worker_thread()
        if type(room_id) is not str or room_id not in self._room_policies:
            raise MigrationAuthorityError("The migration room is not in policy.")

        async def resolve() -> MigrationSubject:
            return self._resolve_subject_on_loop(room_id)

        return self._wait(resolve)

    def _require_worker_thread(self) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise MigrationAuthorityThreadError(
                "MigrationAuthority methods must run in a worker thread, not an event loop."
            )
        if threading.get_ident() == self._loop_thread_id:
            raise MigrationAuthorityThreadError(
                "MigrationAuthority methods cannot block Home Assistant's event-loop thread."
            )
        if self._loop.is_closed() or not self._loop.is_running():
            raise MigrationAuthorityThreadError(
                "Home Assistant's event loop is not available for authority resolution."
            )

    def _wait(self, operation: Callable[[], Coroutine[Any, Any, _T]]) -> _T:
        coroutine = operation()
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        except BaseException:
            coroutine.close()
            raise
        return future.result()

    def _require_registered_runtime(self) -> Any:
        entries = self._hass.config_entries.async_entries(DOMAIN)
        registered = self._hass.config_entries.async_get_entry(self._entry.entry_id)
        if len(entries) != 1 or entries[0] is not self._entry or registered is not self._entry:
            raise MigrationAuthorityError(
                "The authority requires the registered singleton True Family entry."
            )
        if self._entry.state is not ConfigEntryState.LOADED:
            raise MigrationAuthorityError(
                "The True Family config entry must be loaded for migration authority."
            )
        try:
            runtime = self._entry.runtime_data
        except AttributeError as err:
            raise MigrationAuthorityError(
                "The loaded True Family config entry has no runtime identity."
            ) from err
        domain_data = self._hass.data.get(DOMAIN)
        if (
            not isinstance(domain_data, Mapping)
            or domain_data.get(self._entry.entry_id) is not runtime
            or getattr(runtime, "hass", None) is not self._hass
            or getattr(runtime, "entry", None) is not self._entry
        ):
            raise MigrationAuthorityError(
                "The loaded True Family runtime identity cannot be proven."
            )
        return runtime

    def _resolve_subject_on_loop(self, room_id: str) -> MigrationSubject:
        if asyncio.get_running_loop() is not self._loop:
            raise MigrationAuthorityThreadError(
                "Authority registry resolution left Home Assistant's event loop."
            )
        runtime = self._require_registered_runtime()
        if runtime is not self._runtime:
            raise MigrationAuthorityError(
                "The True Family runtime changed after authority construction."
            )

        rooms, bootstrap = self._validated_rooms(runtime)
        room = rooms[room_id]
        if room.binding is None or room.bootstrap_binding is None:
            raise MigrationAuthorityError(
                "The migration room needs a bound valve and immutable bootstrap anchor."
            )
        evidence = next(item for item in bootstrap.rooms if item.room_id == room_id)
        bootstrap_device_id = (
            evidence.device_id if room.binding == room.bootstrap_binding else None
        )

        entity_registry = er.async_get(self._hass)
        device_registry = dr.async_get(self._hass)
        source_entry = self._resolve_physical_binding(
            room.binding,
            entity_registry,
            device_registry,
            bootstrap_device_id=bootstrap_device_id,
        )
        old_entity_id = source_entry.entity_id
        logical_unique_id = f"logical_valve_{room_id}"
        logical_entry = self._resolve_logical_target(
            logical_unique_id,
            entity_registry,
        )

        policy = self._room_policies[room_id]
        facade_entries: dict[FacadeRegistryIdentity, Any] = {}
        provider_targets: list[tuple[str, str]] = []
        for target_policy in policy.provider_targets:
            if target_policy.role is MigrationTargetRole.LOGICAL_VALVE:
                target_entry = logical_entry
            else:
                facade = target_policy.facade
                if facade is None:
                    raise MigrationAuthorityPolicyError(
                        "A facade provider target lost its identity contract."
                    )
                target_entry = facade_entries.get(facade)
                if target_entry is None:
                    target_entry = self._resolve_facade_target(
                        facade,
                        entity_registry,
                    )
                    facade_entries[facade] = target_entry
            if target_entry.id == source_entry.id:
                raise MigrationAuthorityError(
                    "A migration target resolves to the physical source registry entry."
                )
            provider_targets.append(
                (target_policy.provider, target_entry.entity_id)
            )

        targets = tuple(provider_targets)
        if tuple(provider for provider, _target in targets) != tuple(
            sorted(TRUE_FAMILY_PROVIDER_MANIFEST)
        ):
            raise MigrationAuthorityError(
                "The authoritative subject does not cover every provider exactly."
            )
        for _provider, target_entity_id in targets:
            if target_entity_id == old_entity_id:
                raise MigrationAuthorityError(
                    "The physical source and migration targets must differ safely."
                )

        return MigrationSubject(
            room_id=room.room_id,
            room_revision=room.revision,
            old_entity_id=old_entity_id,
            logical_unique_id=logical_unique_id,
            provider_targets=targets,
        )

    def _validated_rooms(
        self,
        runtime: Any,
    ) -> tuple[dict[str, RoomSlot], BootstrapRecord]:
        try:
            raw_rooms = self._entry.data[CONF_ROOMS]
            raw_bootstrap = self._entry.data[CONF_BOOTSTRAP]
            persisted_rooms = rooms_from_dict(raw_rooms)
            bootstrap = BootstrapRecord.from_dict(raw_bootstrap)
            validate_bootstrap_rooms(bootstrap, persisted_rooms)

            runtime_rooms = getattr(runtime, "rooms")
            if type(runtime_rooms) is not dict:
                raise ValueError("Runtime rooms must be a built-in mapping.")
            normalized_runtime_rooms = rooms_from_dict(rooms_as_dict(runtime_rooms))
        except (AttributeError, BootstrapError, KeyError, TypeError, ValueError) as err:
            raise MigrationAuthorityError(
                "Persisted True Family rooms and bootstrap data are invalid."
            ) from err
        if normalized_runtime_rooms != persisted_rooms:
            raise MigrationAuthorityError(
                "Persisted rooms do not match the captured loaded runtime."
            )
        return persisted_rooms, bootstrap

    def _resolve_physical_binding(
        self,
        binding: RoomBinding,
        entity_registry: Any,
        device_registry: Any,
        *,
        bootstrap_device_id: str | None,
    ) -> Any:
        source = entity_registry.async_get(binding.registry_entry_id)
        if (
            source is None
            or source.domain != "climate"
            or source.platform != "mqtt"
            or source.disabled_by is not None
            or source.unique_id != binding.mqtt_unique_id
            or source.device_id is None
            or source.config_entry_id is None
            or source.entity_id.startswith(f"climate.{DOMAIN}_")
            or not _CLIMATE_ENTITY_PATTERN.fullmatch(source.entity_id)
        ):
            raise MigrationAuthorityError(
                "The physical MQTT climate registry binding is invalid."
            )
        mqtt_entry = self._hass.config_entries.async_get_entry(source.config_entry_id)
        if (
            mqtt_entry is None
            or mqtt_entry.domain != "mqtt"
            or mqtt_entry.state is not ConfigEntryState.LOADED
        ):
            raise MigrationAuthorityError(
                "The physical climate is not owned by a loaded MQTT config entry."
            )
        device = device_registry.async_get(source.device_id)
        mqtt_identifiers = (
            sorted(value for domain, value in device.identifiers if domain == "mqtt")
            if device is not None
            else []
        )
        if (
            device is None
            or (bootstrap_device_id is not None and device.id != bootstrap_device_id)
            or mqtt_identifiers != [binding.device_identifier]
            or device.model_id != binding.model
            or device.manufacturer != binding.manufacturer
            or device.name != binding.z2m_friendly_name
        ):
            raise MigrationAuthorityError(
                "The physical valve device identity no longer matches its binding."
            )
        enabled_mqtt_climates = tuple(
            entry.id
            for entry in er.async_entries_for_device(entity_registry, device.id)
            if entry.domain == "climate"
            and entry.platform == "mqtt"
            and entry.disabled_by is None
        )
        if enabled_mqtt_climates != (binding.registry_entry_id,):
            raise MigrationAuthorityError(
                "The physical valve does not have one exact enabled climate source."
            )
        return source

    def _resolve_logical_target(
        self,
        logical_unique_id: str,
        entity_registry: Any,
    ) -> Any:
        entity_id = entity_registry.async_get_entity_id(
            "climate",
            DOMAIN,
            logical_unique_id,
        )
        logical = entity_registry.async_get(entity_id) if entity_id is not None else None
        if (
            logical is None
            or logical.domain != "climate"
            or logical.platform != DOMAIN
            or logical.unique_id != logical_unique_id
            or logical.config_entry_id != self._entry.entry_id
            or logical.disabled_by is not None
            or not _CLIMATE_ENTITY_PATTERN.fullmatch(logical.entity_id)
        ):
            raise MigrationAuthorityError(
                "The room's enabled logical valve registry identity is invalid."
            )
        return logical

    @staticmethod
    def _resolve_facade_target(
        facade: FacadeRegistryIdentity,
        entity_registry: Any,
    ) -> Any:
        target = entity_registry.async_get(facade.registry_entry_id)
        if (
            target is None
            or target.domain != "climate"
            or target.platform != facade.platform
            or target.unique_id != facade.unique_id
            or target.disabled_by is not None
            or not _CLIMATE_ENTITY_PATTERN.fullmatch(target.entity_id)
        ):
            raise MigrationAuthorityError(
                "An enabled facade climate no longer matches its allowlisted identity."
            )
        return target


async def async_provision_reference_journal(
    hass: HomeAssistant,
    *,
    journal_id: str,
    store: ReferenceJournalStore | None = None,
    durability_barrier: ReferenceJournalDurabilityBarrier | None = None,
) -> None:
    """Create an empty journal through a strong barrier and exact read-back.

    Provisioning is deliberately separate from the loading factory.  Existing
    malformed or nonempty data is never replaced by this function. Repeating
    provisioning for the same exact empty generation-zero journal is idempotent.
    """

    loop = _require_hass_loop(hass)
    expected_journal_id = _journal_id(journal_id)
    owned_store: ReferenceJournalOwnedStore | None = None
    if store is None:
        try:
            owned_store = await _new_store(
                hass,
                expected_journal_id,
            )
            selected_store: ReferenceJournalStore = owned_store
        except Exception as err:
            _raise_normalized_backend_error(
                err,
                ReferenceJournalDurabilityError(
                    "The reference journal backend could not be opened."
                ),
            )
    else:
        selected_store = store

    async def provision(
        selected_barrier: ReferenceJournalDurabilityBarrier,
    ) -> None:
        ownership = _journal_runtime(hass)
        async with ownership["lock"]:
            if ownership["owner"] is not None:
                raise ReferenceJournalOwnershipError(
                    "The reference migration journal already has a process owner."
                )
            try:
                existing = await selected_store.async_load()
            except Exception as err:
                _raise_normalized_backend_error(
                    err,
                    ReferenceJournalIOError(
                        "Reference journal storage could not be read safely."
                    ),
                )

            initial = empty_reference_journal_data(expected_journal_id)
            if existing is not None:
                try:
                    verified_existing = decode_reference_journal_data(
                        existing,
                        expected_journal_id=expected_journal_id,
                    )
                except ReferenceJournalCodecError as err:
                    raise ReferenceJournalCorruptionError(
                        "Existing reference journal data is malformed or inconsistent."
                    ) from err
                if verified_existing == initial:
                    return
                raise ReferenceJournalAlreadyProvisionedError(
                    "The reference migration journal already contains data."
                )

            if hass.state is CoreState.stopping:
                raise ReferenceJournalDurabilityError(
                    "Reference journal provisioning is blocked while Home Assistant is stopping."
                )
            try:
                await selected_store.async_save(deepcopy(initial))
                await selected_barrier.async_barrier()
                loaded = await selected_store.async_load()
            except Exception as err:
                _raise_normalized_backend_error(
                    err,
                    ReferenceJournalDurabilityError(
                        "Reference journal provisioning could not be verified."
                    ),
                    mutation=True,
                )
            if loaded is None:
                raise ReferenceJournalDurabilityError(
                    "Reference journal provisioning was not visible on read-back."
                )
            try:
                verified = decode_reference_journal_data(
                    loaded,
                    expected_journal_id=expected_journal_id,
                )
            except ReferenceJournalCodecError as err:
                raise ReferenceJournalDurabilityError(
                    "Reference journal provisioning read-back was malformed."
                ) from err
            if verified != initial:
                raise ReferenceJournalDurabilityError(
                    "Reference journal provisioning read-back did not match exactly."
                )

    failure: BaseException | None = None
    caller_cancelled: asyncio.CancelledError | None = None
    try:
        selected_barrier = _select_durability_barrier(
            selected_store,
            durability_barrier,
            owns_store=owned_store is not None,
            allow_test=(
                store is not None or _test_durability_injection_enabled(hass)
            ),
        )
        operation = loop.create_task(provision(selected_barrier))
        while True:
            try:
                await asyncio.shield(operation)
                break
            except asyncio.CancelledError as err:
                if operation.cancelled():
                    failure = err
                    break
                if caller_cancelled is None:
                    caller_cancelled = err
            except BaseException as err:
                failure = err
                break
    except BaseException as err:
        failure = err

    close_cancelled: asyncio.CancelledError | None = None
    if owned_store is not None:
        try:
            close_cancelled = await _async_close_owned_backend(owned_store)
        except BaseException as err:
            if failure is None:
                failure = err

    if caller_cancelled is not None:
        raise caller_cancelled
    if close_cancelled is not None:
        raise close_cancelled
    if failure is not None:
        normalized_failure = _normalized_backend_error(failure)
        if normalized_failure is None or normalized_failure is failure:
            raise failure
        raise normalized_failure from failure


class HomeAssistantReferenceJournal:
    """Synchronous, worker-thread-only ``ReferenceJournal`` Store adapter.

    Construct this class with ``await async_create(...)`` on the Home Assistant
    event loop.  Invoke every journal protocol method from an executor or other
    non-event-loop worker thread.  Each mutating call verifies the current
    generation before writing and verifies the full next root after writing.
    Once durability becomes uncertain, the instance remains fail-closed.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        store: ReferenceJournalStore,
        owns_store: bool,
        root: dict[str, Any],
        loop: asyncio.AbstractEventLoop,
        ownership: dict[str, Any],
        owner_token: str,
        durability_barrier: ReferenceJournalDurabilityBarrier,
        allow_test_durability_proof: bool,
        durability_scope: ReferenceJournalDurabilityScope,
    ) -> None:
        self._hass = hass
        self._store = store
        self._owns_store = owns_store
        self._root = root
        self._loop = loop
        self._loop_thread_id = threading.get_ident()
        self._ownership = ownership
        self._owner_token = owner_token
        self._durability_barrier = durability_barrier
        self._allow_test_durability_proof = allow_test_durability_proof
        self._durability_scope = durability_scope
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="true-family-reference-migration",
        )
        self._worker_thread_id: int | None = None
        self._closing = False
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None
        self._durability_failure: str | None = None
        self._active_operations = 0

    @classmethod
    async def async_create(
        cls,
        hass: HomeAssistant,
        *,
        journal_id: str,
        store: ReferenceJournalStore | None = None,
        durability_barrier: ReferenceJournalDurabilityBarrier | None = None,
    ) -> HomeAssistantReferenceJournal:
        """Load and validate an existing, explicitly provisioned Store."""

        loop = _require_hass_loop(hass)
        expected_journal_id = _journal_id(journal_id)
        owned_store: ReferenceJournalOwnedStore | None = None
        if store is None:
            try:
                owned_store = await _new_store(hass, expected_journal_id)
                selected_store: ReferenceJournalStore = owned_store
            except Exception as err:
                _raise_normalized_backend_error(
                    err,
                    ReferenceJournalDurabilityError(
                        "The reference journal backend could not be opened."
                    ),
                )
        else:
            selected_store = store

        try:
            allow_test_durability_proof = (
                store is not None or _test_durability_injection_enabled(hass)
            )
            selected_barrier = _select_durability_barrier(
                selected_store,
                durability_barrier,
                owns_store=owned_store is not None,
                allow_test=allow_test_durability_proof,
            )
            selected_proof = _require_strong_durability_barrier(
                selected_barrier,
                allow_test=allow_test_durability_proof,
            )
            ownership = _journal_runtime(hass)
            async with ownership["lock"]:
                if ownership["owner"] is not None:
                    raise ReferenceJournalOwnershipError(
                        "The reference migration journal already has a process owner."
                    )
                try:
                    loaded = await selected_store.async_load()
                except Exception as err:
                    _raise_normalized_backend_error(
                        err,
                        ReferenceJournalIOError(
                            "Reference journal storage could not be read safely."
                        ),
                    )
                if loaded is None:
                    raise ReferenceJournalNotProvisionedError(
                        "The reference migration journal has not been provisioned."
                    )
                try:
                    root = decode_reference_journal_data(
                        loaded,
                        expected_journal_id=expected_journal_id,
                    )
                except ReferenceJournalCodecError as err:
                    raise ReferenceJournalCorruptionError(
                        "Reference journal data is malformed or inconsistent."
                    ) from err
                owner_token = secrets.token_urlsafe(32)
                ownership["owner"] = owner_token
                return cls(
                    hass,
                    selected_store,
                    owned_store is not None,
                    root,
                    loop,
                    ownership,
                    owner_token,
                    selected_barrier,
                    allow_test_durability_proof,
                    selected_proof.scope,
                )
        except BaseException as failure:
            close_cancelled: asyncio.CancelledError | None = None
            close_failure: BaseException | None = None
            if owned_store is not None:
                try:
                    close_cancelled = await _async_close_owned_backend(owned_store)
                except BaseException as err:
                    close_failure = err
            if isinstance(failure, asyncio.CancelledError):
                raise failure
            if close_cancelled is not None:
                raise close_cancelled
            normalized_failure = _normalized_backend_error(failure)
            if normalized_failure is not None:
                if normalized_failure is failure:
                    raise failure
                raise normalized_failure from failure
            if close_failure is not None:
                _raise_normalized_backend_error(
                    close_failure,
                    ReferenceJournalDurabilityError(
                        "The owned reference journal could not close safely."
                    ),
                )
            raise

    @classmethod
    async def async_load(
        cls,
        hass: HomeAssistant,
        *,
        journal_id: str,
        store: ReferenceJournalStore | None = None,
        durability_barrier: ReferenceJournalDurabilityBarrier | None = None,
    ) -> HomeAssistantReferenceJournal:
        """Alias for ``async_create`` emphasizing preprovisioned loading."""

        return await cls.async_create(
            hass,
            journal_id=journal_id,
            store=store,
            durability_barrier=durability_barrier,
        )

    def _require_worker_thread(self) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise ReferenceJournalThreadError(
                "ReferenceJournal methods must run in a worker thread, not an event loop."
            )
        if threading.get_ident() == self._loop_thread_id:
            raise ReferenceJournalThreadError(
                "ReferenceJournal methods cannot block Home Assistant's event-loop thread."
            )
        if self._closed or self._ownership["owner"] != self._owner_token:
            raise ReferenceJournalOwnershipError(
                "The reference migration journal adapter no longer owns the journal."
            )
        if threading.get_ident() != self._worker_thread_id:
            raise ReferenceJournalThreadError(
                "ReferenceJournal methods must use the adapter's dedicated worker."
            )
        if self._loop.is_closed() or not self._loop.is_running():
            raise ReferenceJournalThreadError(
                "Home Assistant's event loop is not available for journal persistence."
            )

    def _wait(self, operation: Callable[[], Coroutine[Any, Any, _T]]) -> _T:
        coroutine = operation()
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        except BaseException:
            coroutine.close()
            raise
        return future.result()

    def _raise_if_failed(self) -> None:
        if self._durability_failure is not None:
            raise ReferenceJournalDurabilityError(self._durability_failure)

    @property
    def migration_operation_in_progress(self) -> bool:
        """Return whether reload would interrupt accepted migration work."""

        return self._active_operations > 0 or self._closing

    @property
    def durability_scope(self) -> ReferenceJournalDurabilityScope:
        """Return the immutable capability scope accepted at adapter creation."""

        return self._durability_scope

    @property
    def host_mutation_authorized(self) -> bool:
        """Return whether this adapter may journal paths leading to host writes."""

        return self._durability_scope in {
            ReferenceJournalDurabilityScope.POWER_LOSS_HOST_MUTATION,
            ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION,
        } and (
            self._durability_scope
            is not ReferenceJournalDurabilityScope.TEST_ONLY_HOST_MUTATION
            or self._allow_test_durability_proof
        )

    def _require_host_mutation_authorization(self) -> None:
        self._require_worker_thread()
        if not self.host_mutation_authorized:
            raise ReferenceJournalDurabilityError(
                "The reference journal durability scope does not authorize host mutation."
            )

    async def async_run(self, function: Callable[..., _T], *args: Any) -> _T:
        """Run one complete coordinator operation on the dedicated worker."""

        if self._closing or self._closed or self._ownership["owner"] != self._owner_token:
            raise ReferenceJournalOwnershipError(
                "The reference migration journal adapter no longer owns the journal."
            )

        self._active_operations += 1
        try:
            def invoke() -> _T:
                self._worker_thread_id = threading.get_ident()
                return function(*args)

            future = self._loop.run_in_executor(self._executor, invoke)
            result, cancelled = await _await_shielded_completion(future)
            if cancelled is not None:
                raise cancelled
            return result
        finally:
            self._active_operations -= 1
            if self._active_operations == 0:
                async_schedule_pending_reference_journal_reload(self._hass, self)

    async def async_close(self) -> None:
        """Release process ownership and reject every stale adapter reference."""

        if self._closed:
            return
        if self._close_task is None:
            self._closing = True
            async_schedule_pending_reference_journal_reload(self._hass, self)
            self._close_task = self._loop.create_task(self._async_finish_close())
        _result, cancelled = await _await_shielded_completion(self._close_task)
        if cancelled is not None:
            raise cancelled

    async def _async_finish_close(self) -> None:
        """Drain work, close the owned backend, then relinquish ownership."""

        failure: BaseException | None = None
        cancelled: asyncio.CancelledError | None = None
        shutdown = self._loop.run_in_executor(None, self._executor.shutdown, True)
        try:
            _result, cancelled = await _await_shielded_completion(shutdown)
        except BaseException as err:
            failure = err

        if self._owns_store:
            if (
                not isinstance(self._store, ReferenceJournalOwnedStore)
                or self._durability_barrier is not self._store
            ):
                if failure is None:
                    failure = ReferenceJournalDurabilityError(
                        "The owned reference journal backend identity was lost."
                    )
            else:
                try:
                    backend_cancelled = await _async_close_owned_backend(self._store)
                    if cancelled is None:
                        cancelled = backend_cancelled
                except BaseException as err:
                    if failure is None:
                        failure = err

        async with self._ownership["lock"]:
            if self._ownership["owner"] == self._owner_token:
                self._ownership["owner"] = None
            self._closed = True
        async_schedule_pending_reference_journal_reload(self._hass, self)
        if cancelled is not None:
            raise cancelled
        if failure is not None:
            _raise_normalized_backend_error(
                failure,
                ReferenceJournalDurabilityError(
                    "The owned reference journal could not close safely."
                ),
            )

    def _fail_durability(self, message: str) -> ReferenceJournalDurabilityError:
        self._durability_failure = message
        return ReferenceJournalDurabilityError(message)

    def _fail_backend(
        self,
        err: BaseException,
        message: str,
        *,
        mutation: bool = False,
    ) -> ReferenceJournalCodecError | ReferenceJournalDurabilityError:
        self._durability_failure = message
        normalized = _normalized_backend_error(err, mutation=mutation)
        return (
            ReferenceJournalDurabilityError(message)
            if normalized is None
            else normalized
        )

    async def _async_verified_current_root(self) -> None:
        self._raise_if_failed()
        if self._closed or self._ownership["owner"] != self._owner_token:
            raise self._fail_durability(
                "The reference journal process ownership was lost."
            )
        try:
            loaded = await self._store.async_load()
        except Exception as err:
            failure = self._fail_backend(
                err,
                "The current reference journal could not be loaded before mutation."
            )
            if failure is err:
                raise
            raise failure from err
        if loaded is None:
            raise self._fail_durability(
                "The current reference journal disappeared before mutation."
            )
        try:
            verified = decode_reference_journal_data(
                loaded,
                expected_journal_id=self._root["journal_id"],
            )
        except ReferenceJournalCodecError as err:
            raise self._fail_durability(
                "The current reference journal became malformed before mutation."
            ) from err
        if verified != self._root:
            raise self._fail_durability(
                "The reference journal generation changed outside this adapter."
            )

    async def _async_change(
        self,
        mutate: Callable[[dict[str, Any]], bool],
        *,
        requires_host_mutation_durability: bool = False,
    ) -> None:
        async with self._ownership["lock"]:
            try:
                proof = _require_strong_durability_barrier(
                    self._durability_barrier,
                    allow_test=self._allow_test_durability_proof,
                )
            except ReferenceJournalDurabilityError as err:
                raise self._fail_durability(str(err)) from err
            if proof.scope is not self._durability_scope:
                raise ReferenceJournalDurabilityError(
                    "The reference journal durability scope changed after opening."
                )
            if requires_host_mutation_durability and not self.host_mutation_authorized:
                raise ReferenceJournalDurabilityError(
                    "The reference journal durability scope does not authorize host mutation."
                )
            await self._async_verified_current_root()
            content = deepcopy(self._root["content"])
            if not mutate(content):
                return
            candidate = _build_root(
                self._root["journal_id"],
                self._root["generation"] + 1,
                content,
            )
            try:
                candidate = decode_reference_journal_data(
                    candidate,
                    expected_journal_id=self._root["journal_id"],
                )
            except ReferenceJournalCodecError as err:
                raise self._fail_durability(
                    "The reference journal mutation was invalid before persistence."
                ) from err
            if self._hass.state is CoreState.stopping:
                raise self._fail_durability(
                    "Reference journal writes are blocked while Home Assistant is stopping."
                )
            try:
                await self._store.async_save(deepcopy(candidate))
                await self._durability_barrier.async_barrier()
                loaded = await self._store.async_load()
            except asyncio.CancelledError as err:
                raise self._fail_durability(
                    "The reference journal write was cancelled and is ambiguous."
                ) from err
            except Exception as err:
                failure = self._fail_backend(
                    err,
                    "The reference journal write could not be verified.",
                    mutation=True,
                )
                if failure is err:
                    raise
                raise failure from err
            if loaded is None:
                raise self._fail_durability(
                    "The reference journal write was absent on read-back."
                )
            try:
                verified = decode_reference_journal_data(
                    loaded,
                    expected_journal_id=self._root["journal_id"],
                )
            except ReferenceJournalCodecError as err:
                raise self._fail_durability(
                    "The reference journal write produced malformed read-back data."
                ) from err
            if verified != candidate:
                raise self._fail_durability(
                    "The reference journal write did not match exact read-back data."
                )
            self._root = verified

    async def _async_read(self, read: Callable[[dict[str, Any]], _T]) -> _T:
        async with self._ownership["lock"]:
            self._raise_if_failed()
            if self._closed or self._ownership["owner"] != self._owner_token:
                raise ReferenceJournalOwnershipError(
                    "The reference migration journal adapter no longer owns the journal."
                )
            return read(self._root["content"])

    def _change_bridge_journal(
        self,
        change: Callable[[InMemoryBridgeOperationJournal], _T],
        *,
        allow_blocked_recovery: bool = False,
        validate_before_change: Callable[
            [dict[str, Any], InMemoryBridgeOperationJournal],
            None,
        ]
        | None = None,
    ) -> _T:
        self._require_worker_thread()
        self._require_host_mutation_authorization()
        result: list[_T] = []

        def mutate(content: dict[str, Any]) -> bool:
            journal, plan_ids, execution_bindings = _bridge_journal_from_content(
                content
            )
            before = deepcopy(content["bridge_operations"])
            if validate_before_change is not None:
                validate_before_change(content, journal)
            changed = change(journal)
            if isinstance(changed, BridgeOperationAttempt):
                plan_id = changed.plan_id
            elif isinstance(changed, BridgeOperationRecord):
                plan_id = changed.intent.plan_id
            elif isinstance(
                changed,
                (FenceAcquisitionRecord, FenceReleaseRecord),
            ):
                plan_id = changed.intent.plan_id
            else:
                raise TypeError("A bridge journal mutation returned invalid data.")
            plan_ids.add(plan_id)
            if plan_id not in execution_bindings:
                _plan, _manifest, execution_binding = _decode_active_plan(
                    content["active_plans"][plan_id],
                    f"active_plans.{plan_id}",
                    expected_journal_id=self._root["journal_id"],
                )
                if execution_binding is None:
                    raise ValueError(
                        "Bridge operation mutation requires an execution binding."
                    )
                execution_bindings[plan_id] = execution_binding
            after = _encode_bridge_journal(
                journal,
                plan_ids,
                execution_bindings,
            )
            result.append(changed)
            if after == before:
                return False
            state_record = content["states"].get(plan_id)
            migration_state = (
                None
                if state_record is None
                else MigrationState(state_record["state"])
            )
            if migration_state is MigrationState.BLOCKED and allow_blocked_recovery:
                final_attempt = journal.attempts_for(plan_id)[-1]
                if final_attempt.state not in {
                    BridgeAttemptState.BLOCKED,
                    BridgeAttemptState.RESTORED,
                }:
                    raise ValueError(
                        "Blocked recovery cannot open or commit a normal bridge attempt."
                    )
            elif migration_state is not MigrationState.APPLYING:
                raise ValueError(
                    "Bridge operation mutations require applying state or exact blocked recovery."
                )
            content["bridge_operations"] = after
            return True

        self._wait(
            lambda: self._async_change(
                mutate,
                requires_host_mutation_durability=True,
            )
        )
        return result[0]

    def _read_bridge_journal(
        self,
        read: Callable[[InMemoryBridgeOperationJournal], _T],
    ) -> _T:
        self._require_worker_thread()

        def read_content(content: dict[str, Any]) -> _T:
            journal, _plan_ids, _execution_bindings = _bridge_journal_from_content(
                content
            )
            return read(journal)

        return self._wait(lambda: self._async_read(read_content))

    def record_plan(
        self,
        plan: MigrationPlan,
        manifest_digest: str,
        execution_binding: ReferencePlanExecutionBinding | None = None,
    ) -> MigrationPlan:
        """Persist one immutable plan, manifest, and execution identity."""

        self._require_worker_thread()
        encoded = _encode_active_plan(
            plan,
            manifest_digest,
            execution_binding,
            expected_journal_id=self._root["journal_id"],
        )
        plan_id = plan.plan_id

        async def change() -> None:
            def mutate(content: dict[str, Any]) -> bool:
                existing = content["active_plans"].get(plan_id)
                if existing is not None:
                    if existing == encoded:
                        return False
                    raise ValueError("An active migration plan binding is immutable.")
                state = content["states"].get(plan_id)
                if state is None:
                    content["states"][plan_id] = _encode_state(
                        MigrationState.PLANNED,
                        None,
                    )
                elif state["state"] != MigrationState.PLANNED.value:
                    raise ValueError(
                        "A new active plan can only be bound while planned."
                    )
                content["active_plans"][plan_id] = deepcopy(encoded)
                return True

            await self._async_change(mutate)

        self._wait(change)
        return plan

    def _active_plan_binding(
        self,
        plan_id: str,
    ) -> tuple[MigrationPlan, str, ReferencePlanExecutionBinding | None]:
        self._require_worker_thread()
        canonical_plan_id = _plan_id(plan_id, "plan_id")

        def read_content(
            content: dict[str, Any],
        ) -> tuple[MigrationPlan, str, ReferencePlanExecutionBinding | None]:
            try:
                encoded = content["active_plans"][canonical_plan_id]
            except KeyError as err:
                raise KeyError(f"Unknown active migration: {canonical_plan_id}.") from err
            return _decode_active_plan(
                encoded,
                f"active_plans.{canonical_plan_id}",
                expected_journal_id=self._root["journal_id"],
            )

        return self._wait(lambda: self._async_read(read_content))

    def plan_for(self, plan_id: str) -> MigrationPlan:
        """Return the detached exact plan bound to one migration ID."""

        return self._active_plan_binding(plan_id)[0]

    def manifest_digest_for(self, plan_id: str) -> str:
        """Return the exact provider-manifest digest bound to one plan."""

        return self._active_plan_binding(plan_id)[1]

    def execution_binding_for(
        self,
        plan_id: str,
    ) -> ReferencePlanExecutionBinding | None:
        """Return the exact persisted execution identity for one active plan."""

        return self._active_plan_binding(plan_id)[2]

    def expected_writes_for(
        self,
        plan_id: str,
    ) -> tuple[BridgeExpectedWrite, ...]:
        """Derive bridge write coverage solely from the persisted active plan."""

        return _expected_writes_for_plan(self._active_plan_binding(plan_id)[0])

    def append_attempt(
        self,
        attempt: BridgeOperationAttempt,
    ) -> BridgeOperationAttempt:
        """Durably append one empty open bridge attempt."""

        self._require_host_mutation_authorization()
        if not isinstance(attempt, BridgeOperationAttempt):
            raise TypeError("A BridgeOperationAttempt is required.")
        attempt.__post_init__()
        if (
            attempt.state is not BridgeAttemptState.OPEN
            or attempt.acquisitions
            or attempt.operations
            or attempt.releases
            or attempt.reason_code is not None
        ):
            raise ValueError("A new bridge attempt must be empty and open.")
        plan, manifest_digest, execution_binding = self._active_plan_binding(
            attempt.plan_id
        )
        _validate_attempt_plan_binding(
            attempt,
            plan,
            manifest_digest,
            execution_binding,
        )
        return self._change_bridge_journal(lambda journal: journal.append_attempt(attempt))

    def attempts_for(self, plan_id: str) -> tuple[BridgeOperationAttempt, ...]:
        """Return every durable bridge attempt for one migration plan."""

        canonical_plan_id = _plan_id(plan_id, "plan_id")
        return self._read_bridge_journal(
            lambda journal: journal.attempts_for(canonical_plan_id)
        )

    def provider_epoch_high_water(self, provider: str) -> int | None:
        """Return the reconstructed global epoch high-water mark."""

        canonical_provider = _provider(provider, "provider")
        return self._read_bridge_journal(
            lambda journal: journal.provider_epoch_high_water(canonical_provider)
        )

    def get_attempt(self, plan_id: str, attempt: int) -> BridgeOperationAttempt:
        """Return one durable bridge attempt."""

        canonical_plan_id = _plan_id(plan_id, "plan_id")
        canonical_attempt = _integer(attempt, "attempt", minimum=1)
        return self._read_bridge_journal(
            lambda journal: journal.get_attempt(
                canonical_plan_id,
                canonical_attempt,
            )
        )

    def get_operation(self, operation_id: str) -> BridgeOperationRecord:
        """Return one durable bridge operation record."""

        return self._read_bridge_journal(
            lambda journal: journal.get_operation(operation_id)
        )

    def get_acquisition(self, operation_id: str) -> FenceAcquisitionRecord:
        """Return one durable fence acquisition record."""

        return self._read_bridge_journal(
            lambda journal: journal.get_acquisition(operation_id)
        )

    def get_release(self, operation_id: str) -> FenceReleaseRecord:
        """Return one durable fence release record."""

        return self._read_bridge_journal(
            lambda journal: journal.get_release(operation_id)
        )

    def record_acquisition_intent(
        self,
        intent: FenceAcquisitionIntent,
    ) -> FenceAcquisitionRecord:
        """Persist a deterministic fence request before host acquisition."""

        return self._change_bridge_journal(
            lambda journal: journal.record_acquisition_intent(intent),
            allow_blocked_recovery=True,
        )

    def arm_acquisition(self, operation_id: str) -> FenceAcquisitionRecord:
        """Persist acquisition dispatch ambiguity before the host call."""

        return self._change_bridge_journal(
            lambda journal: journal.arm_acquisition(operation_id),
            allow_blocked_recovery=True,
        )

    def block_acquisition(
        self,
        operation_id: str,
        reason_code: BridgeBlockReason,
    ) -> FenceAcquisitionRecord:
        """Persist one fixed acquisition failure reason."""

        return self._change_bridge_journal(
            lambda journal: journal.block_acquisition(operation_id, reason_code),
            allow_blocked_recovery=True,
        )

    def record_acquisition_receipt(
        self,
        receipt: FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt,
    ) -> FenceAcquisitionRecord:
        """Persist a host-ledger fence acquisition receipt."""

        return self._change_bridge_journal(
            lambda journal: journal.record_acquisition_receipt(receipt),
            allow_blocked_recovery=True,
        )

    def record_release_intent(
        self,
        intent: FenceReleaseIntent,
    ) -> FenceReleaseRecord:
        """Persist a deterministic fence release before the host call."""

        return self._change_bridge_journal(
            lambda journal: journal.record_release_intent(intent),
            allow_blocked_recovery=True,
        )

    def arm_release(self, operation_id: str) -> FenceReleaseRecord:
        """Persist release dispatch ambiguity before the host call."""

        return self._change_bridge_journal(
            lambda journal: journal.arm_release(operation_id),
            allow_blocked_recovery=True,
        )

    def record_release_receipt(
        self,
        receipt: FenceReleaseReceipt | FenceReleaseNoEffectReceipt,
    ) -> FenceReleaseRecord:
        """Persist a host-ledger fence release receipt."""

        return self._change_bridge_journal(
            lambda journal: journal.record_release_receipt(receipt),
            allow_blocked_recovery=True,
        )

    def record_intent(
        self,
        intent: BridgeOperationIntent,
    ) -> BridgeOperationRecord:
        """Persist one intent before any bridge dispatch."""

        return self._change_bridge_journal(
            lambda journal: journal.record_intent(intent),
            allow_blocked_recovery=True,
        )

    def arm_operation(
        self,
        operation_id: str,
        authorization: BridgeDispatchAuthorization,
    ) -> BridgeOperationRecord:
        """Persist the dispatch-armed checkpoint before the external call."""

        return self._change_bridge_journal(
            lambda journal: journal.arm_operation(operation_id, authorization),
            allow_blocked_recovery=True,
            validate_before_change=lambda content, journal: (
                _validate_operation_original_binding(
                    _journaled_original_values(content),
                    journal,
                    operation_id,
                )
            ),
        )

    def record_receipt(
        self,
        receipt: BridgeOperationReceipt,
    ) -> BridgeOperationRecord:
        """Persist one exact durable host receipt."""

        return self._change_bridge_journal(
            lambda journal: journal.record_receipt(receipt),
            allow_blocked_recovery=True,
        )

    def record_verification(
        self,
        verification: BridgeOperationVerification,
    ) -> BridgeOperationRecord:
        """Persist fresh read-back verification for one receipt."""

        return self._change_bridge_journal(
            lambda journal: journal.record_verification(verification),
            allow_blocked_recovery=True,
        )

    def block_operation(
        self,
        operation_id: str,
        reason_code: BridgeBlockReason,
    ) -> BridgeOperationRecord:
        """Persist a fixed fail-closed operation reason."""

        return self._change_bridge_journal(
            lambda journal: journal.block_operation(operation_id, reason_code),
            allow_blocked_recovery=True,
        )

    def set_attempt_state(
        self,
        plan_id: str,
        attempt: int,
        state: BridgeAttemptState,
        reason_code: BridgeBlockReason | None = None,
        terminal_at: datetime | None = None,
    ) -> BridgeOperationAttempt:
        """Terminalize an attempt only after its operation invariants pass."""

        canonical_plan_id = _plan_id(plan_id, "plan_id")
        canonical_attempt = _integer(attempt, "attempt", minimum=1)
        return self._change_bridge_journal(
            lambda journal: journal.set_attempt_state(
                canonical_plan_id,
                canonical_attempt,
                state,
                reason_code=reason_code,
                terminal_at=terminal_at,
            ),
            allow_blocked_recovery=True,
        )

    def record_original(
        self,
        plan_id: str,
        document: ReferenceDocument,
        post_fingerprint: str,
    ) -> None:
        """Persist one immutable original before its provider is written."""

        self._require_host_mutation_authorization()
        canonical_plan_id = _plan_id(plan_id, "plan_id")
        original = JournaledOriginal(document, post_fingerprint)
        encoded = encode_journaled_original(original)

        async def change() -> None:
            def mutate(content: dict[str, Any]) -> bool:
                state = content["states"].get(canonical_plan_id)
                if state is None:
                    raise ValueError("A journal original requires an existing plan state.")
                if state["state"] != MigrationState.APPLYING.value:
                    raise ValueError("A journal original can only be recorded while applying.")
                try:
                    active_plan, _manifest_digest, _execution_binding = (
                        _decode_active_plan(
                            content["active_plans"][canonical_plan_id],
                            f"active_plans.{canonical_plan_id}",
                            expected_journal_id=self._root["journal_id"],
                        )
                    )
                except KeyError as err:
                    raise ValueError(
                        "A journal original requires an exact active plan."
                    ) from err
                planned = next(
                    (
                        item
                        for item in active_plan.documents
                        if item.provider == document.provider
                        and item.object_id == document.object_id
                        and item.exact_paths
                    ),
                    None,
                )
                if planned is None or not _original_matches_planned(original, planned):
                    raise ValueError(
                        "A journal original must match one changed active-plan document."
                    )
                entries = content["originals"].setdefault(canonical_plan_id, [])
                key = (
                    encoded["document"]["provider"],
                    encoded["document"]["object_id"],
                )
                for existing in entries:
                    existing_key = (
                        existing["document"]["provider"],
                        existing["document"]["object_id"],
                    )
                    if existing_key != key:
                        continue
                    if existing == encoded:
                        return False
                    raise ValueError(
                        "A journal original changed across migration attempts."
                    )
                entries.append(deepcopy(encoded))
                entries.sort(
                    key=lambda item: (
                        item["document"]["provider"],
                        item["document"]["object_id"],
                    )
                )
                return True

            await self._async_change(
                mutate,
                requires_host_mutation_durability=True,
            )

        self._wait(change)

    def set_state(
        self,
        plan_id: str,
        state: MigrationState,
        reason: str | None = None,
    ) -> None:
        """Persist a migration state and wait for exact durable read-back."""

        self._require_worker_thread()
        if state in {MigrationState.APPLYING, MigrationState.COMPLETE}:
            self._require_host_mutation_authorization()
        canonical_plan_id = _plan_id(plan_id, "plan_id")
        encoded = _encode_state(state, reason)

        async def change() -> None:
            def mutate(content: dict[str, Any]) -> bool:
                existing_state = content["states"].get(canonical_plan_id)
                active_binding = content["active_plans"].get(canonical_plan_id)
                if state in {
                    MigrationState.APPLYING,
                    MigrationState.BLOCKED,
                    MigrationState.COMPLETE,
                } and active_binding is None:
                    raise ValueError(
                        "An active migration state requires its exact plan binding."
                    )
                if (
                    state is MigrationState.COMPLETE
                    and canonical_plan_id not in content["completions"]
                ):
                    raise ValueError(
                        "A complete state requires a durable completion record."
                    )
                if state is MigrationState.COMPLETE and active_binding is not None:
                    plan, manifest_digest, execution_binding = _decode_active_plan(
                        active_binding,
                        f"active_plans.{canonical_plan_id}",
                        expected_journal_id=self._root["journal_id"],
                    )
                    _validate_completion_transaction_coverage(
                        plan,
                        manifest_digest,
                        execution_binding,
                        content["bridge_operations"].get(canonical_plan_id, ()),
                    )
                if existing_state == encoded:
                    return False
                current = (
                    None
                    if existing_state is None
                    else MigrationState(existing_state["state"])
                )
                allowed = {
                    None: {MigrationState.PLANNED},
                    MigrationState.PLANNED: {
                        MigrationState.APPLYING,
                        MigrationState.FAILED,
                    },
                    MigrationState.APPLYING: {
                        MigrationState.BLOCKED,
                        MigrationState.COMPLETE,
                        MigrationState.FAILED,
                    },
                    MigrationState.BLOCKED: {MigrationState.FAILED},
                    MigrationState.FAILED: {
                        MigrationState.APPLYING,
                        MigrationState.PLANNED,
                    },
                    MigrationState.COMPLETE: set(),
                }
                if state not in allowed[current]:
                    raise ValueError("The reference journal state transition is invalid.")
                if current is MigrationState.BLOCKED and state is MigrationState.FAILED:
                    attempts = content["bridge_operations"].get(canonical_plan_id, ())
                    if attempts:
                        if active_binding is None:
                            raise ValueError(
                                "Blocked bridge recovery lost its active plan."
                            )
                        _plan, _manifest, execution_binding = _decode_active_plan(
                            active_binding,
                            f"active_plans.{canonical_plan_id}",
                            expected_journal_id=self._root["journal_id"],
                        )
                        if _decode_bound_attempt(
                            attempts[-1],
                            execution_binding,
                            f"bridge_operations.{canonical_plan_id}[-1]",
                        ).state is not BridgeAttemptState.RESTORED:
                            raise ValueError(
                                "A blocked migration with bridge effects must be fully restored before failure."
                            )
                content["states"][canonical_plan_id] = deepcopy(encoded)
                return True

            await self._async_change(
                mutate,
                requires_host_mutation_durability=state
                in {
                    MigrationState.APPLYING,
                    MigrationState.COMPLETE,
                },
            )

        self._wait(change)

    def incomplete_plan_ids(self) -> tuple[str, ...]:
        """Return applying or blocked plans from the verified journal image."""

        self._require_worker_thread()

        async def read() -> tuple[str, ...]:
            return await self._async_read(
                lambda content: tuple(
                    sorted(
                        plan_id
                        for plan_id, record in content["states"].items()
                        if record["state"]
                        in {
                            MigrationState.APPLYING.value,
                            MigrationState.BLOCKED.value,
                        }
                    )
                )
            )

        return self._wait(read)

    def originals_for(self, plan_id: str) -> tuple[JournaledOriginal, ...]:
        """Return detached original documents for one plan."""

        self._require_worker_thread()
        canonical_plan_id = _plan_id(plan_id, "plan_id")

        async def read() -> tuple[JournaledOriginal, ...]:
            return await self._async_read(
                lambda content: tuple(
                    decode_journaled_original(item)
                    for item in content["originals"].get(canonical_plan_id, ())
                )
            )

        return self._wait(read)

    def record_completion(self, completion: JournaledCompletion) -> None:
        """Persist one validated completion before marking its plan complete."""

        self._require_host_mutation_authorization()
        _ = encode_journaled_completion(completion)
        plan_id = completion.plan.plan_id

        async def change() -> None:
            def mutate(content: dict[str, Any]) -> bool:
                state = content["states"].get(plan_id)
                if state is None or state["state"] != MigrationState.APPLYING.value:
                    raise ValueError(
                        "A completion can only be recorded for an applying plan."
                    )
                try:
                    active_plan, manifest_digest, execution_binding = (
                        _decode_active_plan(
                            content["active_plans"][plan_id],
                            f"active_plans.{plan_id}",
                            expected_journal_id=self._root["journal_id"],
                        )
                    )
                except KeyError as err:
                    raise ValueError(
                        "A completion requires an exact active plan binding."
                    ) from err
                if completion.plan != active_plan:
                    raise ValueError(
                        "A completion does not match the exact active plan."
                    )
                _validate_completion_transaction_coverage(
                    active_plan,
                    manifest_digest,
                    execution_binding,
                    content["bridge_operations"].get(plan_id, ()),
                )
                encoded = _encode_bound_completion(completion, execution_binding)
                expected_originals = {
                    (item.provider, item.object_id): item
                    for item in active_plan.documents
                    if item.exact_paths
                }
                actual_originals = {
                    (item.document.provider, item.document.object_id): item
                    for item in (
                        decode_journaled_original(value)
                        for value in content["originals"].get(plan_id, ())
                    )
                }
                if set(actual_originals) != set(expected_originals) or any(
                    not _original_matches_planned(
                        actual_originals[key],
                        planned,
                    )
                    for key, planned in expected_originals.items()
                ):
                    raise ValueError(
                        "A completion requires every exact changed original."
                    )
                existing = content["completions"].get(plan_id)
                if existing is not None:
                    if existing == encoded:
                        return False
                    raise ValueError("A journal completion changed across writes.")
                content["completions"][plan_id] = deepcopy(encoded)
                return True

            await self._async_change(
                mutate,
                requires_host_mutation_durability=True,
            )

        self._wait(change)

    def completed_plan_ids(self) -> tuple[str, ...]:
        """Return plans with both complete state and completion data."""

        self._require_worker_thread()

        async def read() -> tuple[str, ...]:
            return await self._async_read(
                lambda content: tuple(
                    sorted(
                        plan_id
                        for plan_id, record in content["states"].items()
                        if record["state"] == MigrationState.COMPLETE.value
                        and plan_id in content["completions"]
                    )
                )
            )

        return self._wait(read)

    def completion_for(self, plan_id: str) -> JournaledCompletion:
        """Return a detached, fully revalidated completion record."""

        self._require_worker_thread()
        canonical_plan_id = _plan_id(plan_id, "plan_id")

        async def read() -> JournaledCompletion:
            def get_completion(content: dict[str, Any]) -> JournaledCompletion:
                try:
                    encoded = content["completions"][canonical_plan_id]
                except KeyError as err:
                    raise KeyError(
                        f"Unknown completed migration: {canonical_plan_id}."
                    ) from err
                try:
                    _plan, _manifest, execution_binding = _decode_active_plan(
                        content["active_plans"][canonical_plan_id],
                        f"active_plans.{canonical_plan_id}",
                        expected_journal_id=self._root["journal_id"],
                    )
                except KeyError as err:
                    raise ReferenceJournalCodecError(
                        "A completion lost its active execution binding."
                    ) from err
                return _decode_bound_completion(
                    encoded,
                    execution_binding,
                    f"completions.{canonical_plan_id}",
                )

            return await self._async_read(get_completion)

        return self._wait(read)

    def state(
        self,
        plan_id: str,
    ) -> tuple[MigrationState, str | None] | None:
        """Return one verified state for diagnostics and adapter tests."""

        self._require_worker_thread()
        canonical_plan_id = _plan_id(plan_id, "plan_id")

        async def read() -> tuple[MigrationState, str | None] | None:
            def get_state(
                content: dict[str, Any],
            ) -> tuple[MigrationState, str | None] | None:
                encoded = content["states"].get(canonical_plan_id)
                return (
                    None
                    if encoded is None
                    else _decode_state(encoded, f"states.{canonical_plan_id}")
                )

            return await self._async_read(get_state)

        return self._wait(read)


async def async_load_reference_journal(
    hass: HomeAssistant,
    *,
    journal_id: str,
    store: ReferenceJournalStore | None = None,
    durability_barrier: ReferenceJournalDurabilityBarrier | None = None,
) -> HomeAssistantReferenceJournal:
    """Load the worker-thread adapter from an existing Store."""

    return await HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=journal_id,
        store=store,
        durability_barrier=durability_barrier,
    )
