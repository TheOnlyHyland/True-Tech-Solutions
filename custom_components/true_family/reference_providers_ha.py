"""Read-only Home Assistant inventory and fail-closed provider readiness."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import json
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .reference_migration import (
    ReferenceDocument,
    Revision,
    TRUE_FAMILY_PROVIDER_MANIFEST,
)
from .reference_projection import scan_semantic_references
from .reference_transaction import (
    BridgeDispatchAuthorization,
    BridgeObjectObservation,
    BridgeOperationIntent,
    BridgeOperationReceipt,
    FenceAcquisitionIntent,
    FenceAcquisitionNoEffectReceipt,
    FenceAcquisitionReceipt,
    FenceBinding,
    FenceReleaseIntent,
    FenceReleaseNoEffectReceipt,
    FenceReleaseReceipt,
    FenceTokenDigest,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant


PROVIDER_NAMES: tuple[str, ...] = (
    "active_yaml",
    "config_entry",
    "external_writers",
    "lovelace",
    "scheduler",
)

if frozenset(PROVIDER_NAMES) != TRUE_FAMILY_PROVIDER_MANIFEST:
    raise RuntimeError("The Home Assistant provider contract does not match the core manifest.")

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SCHEDULER_SERVICES = ("add", "edit", "remove")
_SCHEDULER_ATTRIBUTES = ("actions", "entities", "timeslots", "weekdays")
_HOST_AUTHORITATIVE_PROVIDERS = frozenset({"active_yaml", "lovelace"})
_CONFIG_ENTRY_REFERENCE_VERSIONS = {
    "generic_thermostat": (1, 3),
    "template": (1, 2),
}
_CONFIG_ENTRY_REFERENCE_ENTITY_PATTERN = re.compile(
    r"(?<![a-z0-9_])(?P<entity>[a-z0-9_]+\.[a-z0-9_]+)(?![a-z0-9_])"
)
_CONFIG_ENTRY_REFERENCE_VALIDATION_ENTITY = (
    "sensor.true_family_reference_validation_sentinel"
)
_CONFIG_ENTRY_REFERENCE_TEMPLATE_MAX_BYTES = 16_384
_CONFIG_ENTRY_REFERENCE_TEMPLATE_MAX_ENTITIES = 64
_GENERIC_THERMOSTAT_OPTION_FIELDS = frozenset(
    {
        "ac_mode",
        "activity_temp",
        "away_temp",
        "cold_tolerance",
        "comfort_temp",
        "cycle_cooldown",
        "eco_temp",
        "heater",
        "home_temp",
        "hot_tolerance",
        "keep_alive",
        "max_cycle_duration",
        "max_temp",
        "min_cycle_duration",
        "min_temp",
        "name",
        "sleep_temp",
        "target_sensor",
    }
)
_TEMPLATE_OPTION_FIELDS = frozenset(
    {
        "advanced_options",
        "device_class",
        "device_id",
        "name",
        "state",
        "state_class",
        "template_type",
        "unit_of_measurement",
    }
)
_TEMPLATE_REFERENCE_TYPE = "sensor"


class InventoryStatus(StrEnum):
    """Internal availability of one read-only inventory surface."""

    READABLE = "readable"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class PublicProviderStatus(StrEnum):
    """Fixed, non-sensitive status values exposed to callers."""

    READY = "ready"
    READ_ONLY = "read_only"
    COUNT_MISMATCH = "count_mismatch"
    MANIFEST_MISMATCH = "manifest_mismatch"
    UNAVAILABLE = "unavailable"


class BridgeRecoveryCapability(StrEnum):
    """Fine-grained bridge capabilities selected by journal recovery."""

    ACQUISITION_LEDGER = "acquisition_ledger"
    OBJECT_LEDGER = "object_ledger"
    RELEASE_LEDGER = "release_ledger"
    OBJECT_OBSERVATION = "object_observation"
    FENCE_STATE = "fence_state"
    EPOCH_RESERVATION = "epoch_reservation"
    FENCE_ACQUISITION = "fence_acquisition"
    CONDITIONAL_WRITE = "conditional_write"
    ROLLBACK = "rollback"
    FENCE_RELEASE = "fence_release"


class ExternalAttestationError(ValueError):
    """Raised when external-writer evidence cannot be trusted."""


class ConfigEntryReferenceSnapshotError(ValueError):
    """Raised when an exact config-entry reference snapshot cannot be trusted."""


@dataclass(frozen=True, slots=True)
class ConfigEntryReferenceObjectPolicy:
    """Server-owned identity for one supported config-entry reference object."""

    entry_id: str
    domain: str

    def __post_init__(self) -> None:
        if (
            type(self.entry_id) is not str
            or not self.entry_id
            or self.entry_id != self.entry_id.strip()
            or "\x00" in self.entry_id
        ):
            raise ConfigEntryReferenceSnapshotError(
                "Config-entry reference policy contains an invalid identity."
            )
        if (
            type(self.domain) is not str
            or self.domain not in _CONFIG_ENTRY_REFERENCE_VERSIONS
        ):
            raise ConfigEntryReferenceSnapshotError(
                "Config-entry reference policy contains an unsupported domain."
            )


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    """Capabilities a host bridge must explicitly prove."""

    readable: bool
    schema_aware: bool
    conditional_write: bool
    durable_ack: bool
    rollback: bool
    fenced_writer: bool

    def __post_init__(self) -> None:
        for name in (
            "readable",
            "schema_aware",
            "conditional_write",
            "durable_ack",
            "rollback",
            "fenced_writer",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"Provider capability {name} must be a boolean.")

    @property
    def production_ready(self) -> bool:
        """Return whether every production capability is proven."""

        return all(
            (
                self.readable,
                self.schema_aware,
                self.conditional_write,
                self.durable_ack,
                self.rollback,
                self.fenced_writer,
            )
        )

    @classmethod
    def unavailable(cls) -> ProviderCapabilities:
        """Return an explicit no-capability claim."""

        return cls(False, False, False, False, False, False)


@dataclass(frozen=True, slots=True)
class ExpectedProviderObjects:
    """Canonical expected object keys for one provider."""

    provider: str
    object_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        _validate_object_keys(self.object_keys)

    @property
    def count(self) -> int:
        """Return the exact expected object count."""

        return len(self.object_keys)

    @property
    def digest(self) -> str:
        """Return a stable digest binding the provider to all expected keys."""

        return _digest_json(
            {
                "provider": self.provider,
                "objects": list(self.object_keys),
            }
        )


@dataclass(frozen=True, slots=True)
class ExpectedObjectManifest:
    """Exactly one expected-object set for every production provider."""

    revision: str
    providers: tuple[ExpectedProviderObjects, ...]

    def __post_init__(self) -> None:
        _validate_nonempty_string(self.revision, "Expected manifest revision")
        if type(self.providers) is not tuple:
            raise TypeError("Expected manifest providers must be a tuple.")
        names = tuple(item.provider for item in self.providers)
        if names != PROVIDER_NAMES:
            raise ValueError(
                "Expected manifest providers must contain the five canonical names "
                "once and in canonical order."
            )

    @classmethod
    def from_mapping(
        cls,
        revision: str,
        objects: Mapping[str, Iterable[str]],
    ) -> ExpectedObjectManifest:
        """Build a canonical manifest from an exact five-provider mapping."""

        if not isinstance(objects, Mapping):
            raise TypeError("Expected objects must be a mapping.")
        if set(objects) != set(PROVIDER_NAMES):
            raise ValueError("Expected objects must cover the five providers exactly.")
        providers: list[ExpectedProviderObjects] = []
        for provider in PROVIDER_NAMES:
            values = objects[provider]
            if isinstance(values, (str, bytes)):
                raise TypeError("Expected object keys must be an iterable of strings.")
            providers.append(
                ExpectedProviderObjects(provider, tuple(sorted(values)))
            )
        return cls(revision, tuple(providers))

    def for_provider(self, provider: str) -> ExpectedProviderObjects:
        """Return one provider's expected objects."""

        _validate_provider(provider)
        return self.providers[PROVIDER_NAMES.index(provider)]

    @property
    def digest(self) -> str:
        """Return a stable digest of the complete expected manifest."""

        return _digest_json(
            {
                "revision": self.revision,
                "providers": [
                    {
                        "provider": item.provider,
                        "objects": list(item.object_keys),
                    }
                    for item in self.providers
                ],
            }
        )


@dataclass(frozen=True, slots=True)
class SourceAnnotation:
    """A YAML source annotation retained without the referenced payload."""

    source: str
    line: int | str

    def __post_init__(self) -> None:
        _validate_nonempty_string(self.source, "Source annotation")
        if isinstance(self.line, bool) or not isinstance(self.line, (int, str)):
            raise TypeError("Source annotation line must be an integer or string.")
        if isinstance(self.line, int) and self.line < 0:
            raise ValueError("Source annotation line cannot be negative.")
        if isinstance(self.line, str):
            _validate_nonempty_string(self.line, "Source annotation line")


@dataclass(frozen=True, slots=True)
class InventoryObject:
    """One payload-free object observation from a supported read surface."""

    object_key: str
    revision: Revision | None = None
    annotation: SourceAnnotation | None = None

    def __post_init__(self) -> None:
        _validate_nonempty_string(self.object_key, "Inventory object key")
        if self.revision is not None:
            _validate_revision(self.revision, "Inventory object revision")
        if self.annotation is not None and not isinstance(
            self.annotation, SourceAnnotation
        ):
            raise TypeError("Inventory object annotation is malformed.")


@dataclass(frozen=True, slots=True)
class ProviderDocumentSnapshot:
    """Immutable projected provider document with its payload hidden from repr."""

    provider: str
    object_id: str = field(repr=False)
    revision: str = field(repr=False)
    payload: Mapping[str, Any] = field(repr=False)
    writable: bool = field(default=False, init=False)
    fingerprint: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        _validate_nonempty_string(self.object_id, "Provider document object ID")
        _validate_digest(self.revision, "Provider document revision")
        canonical_payload = _copy_projected_payload(self.payload)
        try:
            fingerprint = _digest_json(canonical_payload)
        except (TypeError, ValueError):
            raise ConfigEntryReferenceSnapshotError(
                "Projected provider document payload is not canonical."
            ) from None
        object.__setattr__(
            self,
            "payload",
            _freeze_projected_payload(canonical_payload),
        )
        object.__setattr__(self, "fingerprint", fingerprint)

    def as_public_summary(self) -> dict[str, str | bool]:
        """Return payload-free metadata suitable for a public status surface."""

        return {
            "provider": self.provider,
            "writable": self.writable,
        }

    def as_reference_document(self) -> ReferenceDocument:
        """Return a canonical mutable copy for the existing planner boundary."""

        return ReferenceDocument(
            provider=self.provider,
            object_id=self.object_id,
            revision=self.revision,
            payload=_copy_projected_payload(self.payload),
            writable=False,
        )


@dataclass(frozen=True, slots=True)
class ProviderInventory:
    """Internal payload-free inventory for one provider."""

    provider: str
    status: InventoryStatus
    objects: tuple[InventoryObject, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        if not isinstance(self.status, InventoryStatus):
            raise TypeError("Provider inventory status is malformed.")
        if type(self.objects) is not tuple or any(
            not isinstance(item, InventoryObject) for item in self.objects
        ):
            raise TypeError("Provider inventory objects must be a tuple of observations.")
        keys = tuple(item.object_key for item in self.objects)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("Provider inventory object keys must be unique and sorted.")
        if self.status is not InventoryStatus.READABLE and self.objects:
            raise ValueError("An unreadable inventory cannot contain observations.")

    @classmethod
    def readable(
        cls,
        provider: str,
        objects: Iterable[InventoryObject] = (),
    ) -> ProviderInventory:
        """Build a sorted readable inventory."""

        return cls(
            provider,
            InventoryStatus.READABLE,
            tuple(sorted(objects, key=lambda item: item.object_key)),
        )

    @classmethod
    def unavailable(cls, provider: str) -> ProviderInventory:
        """Build an unavailable inventory without sensitive error detail."""

        return cls(provider, InventoryStatus.UNAVAILABLE, ())

    @classmethod
    def error(cls, provider: str) -> ProviderInventory:
        """Build a failed inventory without sensitive error detail."""

        return cls(provider, InventoryStatus.ERROR, ())

    @property
    def object_keys(self) -> tuple[str, ...]:
        """Return internal keys for exact manifest comparison."""

        return tuple(item.object_key for item in self.objects)

    @property
    def count(self) -> int:
        """Return the observed object count."""

        return len(self.objects)

    @property
    def revision_digest(self) -> str:
        """Bind all observed object revisions into one canonical snapshot."""

        return _digest_json(
            {
                "provider": self.provider,
                "objects": [
                    {
                        "object_key": item.object_key,
                        "revision": (
                            None
                            if item.revision is None
                            else _canonical_revision(item.revision)
                        ),
                    }
                    for item in self.objects
                ],
            }
        )


@dataclass(frozen=True, slots=True)
class WriterFenceMetadata:
    """Non-secret host lease evidence bound to a provider inventory scope."""

    provider: str
    writer_id: str
    fence_token_digest: FenceTokenDigest
    fence_epoch: int
    fence_revision: Revision
    scope_digest: str
    acquired_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        _validate_nonempty_string(self.writer_id, "Writer ID")
        if not isinstance(self.fence_token_digest, FenceTokenDigest):
            raise TypeError("Writer fence token digest is not runtime-branded.")
        if type(self.fence_epoch) is not int or self.fence_epoch < 0:
            raise ValueError("Writer fence epoch must be a non-negative integer.")
        _validate_revision(self.fence_revision, "Writer fence revision")
        _validate_digest(self.scope_digest, "Writer fence scope digest")
        _validate_utc_datetime(self.acquired_at, "Writer fence acquisition")
        _validate_utc_datetime(self.expires_at, "Writer fence expiry")
        if self.acquired_at >= self.expires_at:
            raise ValueError("Writer fence expiry must follow acquisition.")


@dataclass(frozen=True, slots=True)
class SignedExternalWriterAttestation:
    """Signed external inventory metadata tied to an active writer fence."""

    provider: str
    issuer: str
    key_id: str
    attestation_id: str
    writer_id: str
    expected_manifest_digest: str
    object_keys: tuple[str, ...]
    inventory_revision: Revision
    issued_at: datetime
    expires_at: datetime
    fence: WriterFenceMetadata
    signature: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if self.provider != "external_writers":
            raise ValueError("External attestation has the wrong provider.")
        for value, label in (
            (self.issuer, "Attestation issuer"),
            (self.key_id, "Attestation key ID"),
            (self.attestation_id, "Attestation ID"),
            (self.writer_id, "Attested writer ID"),
        ):
            _validate_nonempty_string(value, label)
        _validate_digest(
            self.expected_manifest_digest,
            "Attestation expected manifest digest",
        )
        _validate_object_keys(self.object_keys)
        _validate_revision(self.inventory_revision, "Attested inventory revision")
        _validate_utc_datetime(self.issued_at, "Attestation issue time")
        _validate_utc_datetime(self.expires_at, "Attestation expiry")
        if self.issued_at >= self.expires_at:
            raise ValueError("Attestation expiry must follow issue time.")
        if not isinstance(self.fence, WriterFenceMetadata):
            raise TypeError("External attestation fence is malformed.")
        if self.fence.provider != self.provider:
            raise ValueError("External attestation fence has the wrong provider.")
        if self.fence.writer_id != self.writer_id:
            raise ValueError("External attestation writer and fence do not match.")
        if type(self.signature) is not bytes or not self.signature:
            raise ValueError("External attestation needs a non-empty byte signature.")

    def canonical_payload(self) -> bytes:
        """Return deterministic unsigned metadata for an injected verifier."""

        return _canonical_json(
            {
                "provider": self.provider,
                "issuer": self.issuer,
                "key_id": self.key_id,
                "attestation_id": self.attestation_id,
                "writer_id": self.writer_id,
                "expected_manifest_digest": self.expected_manifest_digest,
                "object_keys": list(self.object_keys),
                "inventory_revision": _canonical_revision(self.inventory_revision),
                "issued_at": self.issued_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
                "fence": {
                    "provider": self.fence.provider,
                    "writer_id": self.fence.writer_id,
                    "fence_token_digest": str(self.fence.fence_token_digest),
                    "fence_epoch": self.fence.fence_epoch,
                    "fence_revision": _canonical_revision(
                        self.fence.fence_revision
                    ),
                    "scope_digest": self.fence.scope_digest,
                    "acquired_at": self.fence.acquired_at.isoformat(),
                    "expires_at": self.fence.expires_at.isoformat(),
                },
            }
        )


@runtime_checkable
class ExternalAttestationVerifier(Protocol):
    """Injected cryptographic verifier for external-writer attestations."""

    def verify(
        self,
        attestation: SignedExternalWriterAttestation,
        canonical_payload: bytes,
        /,
    ) -> bool:
        """Return true only for a trusted signature over the supplied payload."""

        ...


@dataclass(frozen=True, slots=True)
class BridgeReadiness:
    """Non-mutating readiness proof returned by an explicit host bridge."""

    provider: str
    available: bool
    capabilities: ProviderCapabilities
    object_count: int
    expected_manifest_digest: str | None
    object_manifest_digest: str | None
    inventory_revision: Revision | None
    bridge_id: str | None
    readiness_revision: Revision | None

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        if type(self.available) is not bool:
            raise TypeError("Bridge availability must be a boolean.")
        if not isinstance(self.capabilities, ProviderCapabilities):
            raise TypeError("Bridge capabilities are malformed.")
        if isinstance(self.object_count, bool) or not isinstance(self.object_count, int):
            raise TypeError("Bridge object count must be an integer.")
        if self.object_count < 0:
            raise ValueError("Bridge object count cannot be negative.")
        if self.available:
            if self.expected_manifest_digest is None:
                raise ValueError("Available bridge needs an expected manifest digest.")
            if self.object_manifest_digest is None:
                raise ValueError("Available bridge needs an object manifest digest.")
            if self.inventory_revision is None:
                raise ValueError("Available bridge needs an inventory revision.")
            if self.bridge_id is None:
                raise ValueError("Available bridge needs an opaque bridge ID.")
            if self.readiness_revision is None:
                raise ValueError("Available bridge needs a readiness revision.")
            _validate_digest(
                self.expected_manifest_digest,
                "Bridge expected manifest digest",
            )
            _validate_digest(
                self.object_manifest_digest,
                "Bridge object manifest digest",
            )
            _validate_revision(self.inventory_revision, "Bridge inventory revision")
            _validate_nonempty_string(self.bridge_id, "Bridge ID")
            _validate_revision(self.readiness_revision, "Bridge readiness revision")
        elif (
            self.capabilities != ProviderCapabilities.unavailable()
            or self.object_count != 0
            or self.expected_manifest_digest is not None
            or self.object_manifest_digest is not None
            or self.inventory_revision is not None
            or self.bridge_id is not None
            or self.readiness_revision is not None
        ):
            raise ValueError("Unavailable bridge readiness must not claim proof data.")

    @classmethod
    def unavailable(cls, provider: str) -> BridgeReadiness:
        """Build a canonical unavailable bridge result."""

        return cls(
            provider,
            False,
            ProviderCapabilities.unavailable(),
            0,
            None,
            None,
            None,
            None,
            None,
        )


@dataclass(frozen=True, slots=True)
class BridgeFenceAuthoritySnapshot:
    """Fresh payload-free host fence state; bearer material stays bridge-private."""

    provider: str
    bridge_id: str
    current_binding: FenceBinding | None = field(repr=False)
    host_epoch_high_water: int
    observed_at: datetime

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        _validate_nonempty_string(self.bridge_id, "Bridge ID")
        if (
            type(self.host_epoch_high_water) is not int
            or self.host_epoch_high_water < -1
        ):
            raise ValueError("Host epoch high-water must be an integer of at least -1.")
        _validate_utc_datetime(self.observed_at, "Fence-state observation")
        if self.current_binding is not None:
            if not isinstance(self.current_binding, FenceBinding):
                raise TypeError("Current fence binding is malformed.")
            if self.current_binding.provider != self.provider:
                raise ValueError("Current fence binding has the wrong provider.")
            if self.current_binding.epoch > self.host_epoch_high_water:
                raise ValueError("Current fence epoch exceeds the host high-water mark.")


@dataclass(frozen=True, slots=True)
class BridgeEpochReservation:
    """Opaque result of atomically reserving one strictly newer host epoch."""

    provider: str
    bridge_id: str
    reservation_id: str
    requested_after_epoch: int
    previous_high_water: int
    epoch: int
    reserved_at: datetime

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        _validate_nonempty_string(self.bridge_id, "Bridge ID")
        _validate_nonempty_string(self.reservation_id, "Epoch reservation ID")
        if type(self.requested_after_epoch) is not int or self.requested_after_epoch < -1:
            raise ValueError("Requested prior epoch must be at least -1.")
        if type(self.previous_high_water) is not int or self.previous_high_water < -1:
            raise ValueError("Previous epoch high-water must be at least -1.")
        if type(self.epoch) is not int or self.epoch < 0:
            raise ValueError("Reserved epoch must be a non-negative integer.")
        if self.epoch <= max(self.requested_after_epoch, self.previous_high_water):
            raise ValueError("Reserved epoch must advance caller and host high-water.")
        _validate_utc_datetime(self.reserved_at, "Epoch reservation time")


@runtime_checkable
class ProviderHostBridge(Protocol):
    """Write-capable host contract; this module never invokes mutation methods."""

    @property
    def name(self) -> str:
        """Return one canonical provider name."""

        ...

    @property
    def bridge_id(self) -> str:
        """Return an opaque non-secret identity persisted with journal scope."""

        ...

    async def async_readiness(
        self,
        expected_manifest: ExpectedObjectManifest,
    ) -> BridgeReadiness:
        """Return a payload-free, non-mutating bridge readiness proof."""

        ...

    async def async_acquire_writer_fence(
        self,
        operation: FenceAcquisitionIntent,
        *,
        reservation: BridgeEpochReservation,
    ) -> FenceAcquisitionReceipt:
        """Idempotently acquire one operation-ledger writer fence."""

        ...

    async def async_compare_and_swap(
        self,
        operation: BridgeOperationIntent,
        authorization: BridgeDispatchAuthorization,
        *,
        payload: Any,
    ) -> BridgeOperationReceipt:
        """Execute one intent using its exact persisted dispatch authorization."""

        ...

    async def async_rollback(
        self,
        operation: BridgeOperationIntent,
        authorization: BridgeDispatchAuthorization,
        *,
        payload: Any,
        write_receipt: BridgeOperationReceipt,
    ) -> BridgeOperationReceipt:
        """Compensate one receipt using its persisted rollback authorization."""

        ...

    async def async_reconcile_operation(
        self,
        operation: BridgeOperationIntent,
        authorization: BridgeDispatchAuthorization,
    ) -> BridgeOperationReceipt:
        """Reconcile an intent and its exact persisted dispatch authorization."""

        ...

    async def async_reconcile_fence_acquisition(
        self,
        operation: FenceAcquisitionIntent,
    ) -> FenceAcquisitionReceipt | FenceAcquisitionNoEffectReceipt:
        """Reconcile a complete acquisition intent against the host ledger."""

        ...

    async def async_reconcile_fence_release(
        self,
        operation: FenceReleaseIntent,
    ) -> FenceReleaseReceipt | FenceReleaseNoEffectReceipt:
        """Reconcile a complete release intent against the host ledger."""

        ...

    async def async_release_writer_fence(
        self,
        operation: FenceReleaseIntent,
    ) -> FenceReleaseReceipt:
        """Idempotently release one acquisition-bound writer fence."""

        ...

    async def async_observe_object(
        self,
        operation: BridgeOperationIntent,
    ) -> BridgeObjectObservation:
        """Return a fresh payload-free observation bound to a complete intent."""

        ...

    async def async_fence_authority_snapshot(
        self,
    ) -> BridgeFenceAuthoritySnapshot:
        """Atomically read current binding and durable host epoch high-water."""

        ...

    async def async_reserve_next_fence_epoch(
        self,
        *,
        after_epoch: int,
    ) -> BridgeEpochReservation:
        """Atomically allocate and reserve an epoch newer than all known epochs."""

        ...


@dataclass(frozen=True, slots=True)
class HomeAssistantInventoryScope:
    """Explicit scope for the public Home Assistant read surfaces."""

    expected_manifest_digest: str | None = None
    active_yaml_domains: tuple[str, ...] | None = None
    config_entry_domains: tuple[str, ...] | None = None
    lovelace_dashboards: tuple[str | None, ...] | None = None
    scheduler_entity_prefix: str = "switch.schedule_"
    scheduler_entity_ids: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if self.expected_manifest_digest is not None:
            _validate_digest(
                self.expected_manifest_digest,
                "Inventory scope expected manifest digest",
            )
        _validate_optional_string_tuple(
            self.active_yaml_domains,
            "Active YAML domains",
        )
        _validate_optional_string_tuple(
            self.config_entry_domains,
            "Config-entry domains",
        )
        if self.lovelace_dashboards is not None:
            if type(self.lovelace_dashboards) is not tuple:
                raise TypeError("Lovelace dashboard scope must be a tuple or None.")
            seen: set[str | None] = set()
            for value in self.lovelace_dashboards:
                if value is not None:
                    _validate_nonempty_string(value, "Lovelace dashboard path")
                if value in seen:
                    raise ValueError("Lovelace dashboard scope contains duplicates.")
                seen.add(value)
        _validate_nonempty_string(
            self.scheduler_entity_prefix,
            "Scheduler entity prefix",
        )
        if not self.scheduler_entity_prefix.startswith("switch."):
            raise ValueError("Scheduler inventory must use the switch state surface.")
        _validate_optional_string_tuple(
            self.scheduler_entity_ids,
            "Scheduler entity IDs",
        )
        if self.scheduler_entity_ids is not None and any(
            not entity_id.startswith("switch.")
            for entity_id in self.scheduler_entity_ids
        ):
            raise ValueError("Scheduler inventory IDs must use the switch domain.")


@dataclass(frozen=True, slots=True)
class ProviderPublicSummary:
    """Public provider result containing only a name, status, and counts."""

    provider: str
    status: PublicProviderStatus
    expected_count: int
    observed_count: int

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        if not isinstance(self.status, PublicProviderStatus):
            raise TypeError("Public provider status is malformed.")
        for value, label in (
            (self.expected_count, "Expected object count"),
            (self.observed_count, "Observed object count"),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer.")
            if value < 0:
                raise ValueError(f"{label} cannot be negative.")

    def as_dict(self) -> dict[str, str | int]:
        """Return the fixed safe public shape."""

        return {
            "provider": self.provider,
            "status": self.status.value,
            "expected_count": self.expected_count,
            "observed_count": self.observed_count,
        }


@dataclass(frozen=True, slots=True)
class ProductionReadiness:
    """Sanitized readiness result for all five providers."""

    ready: bool
    providers: tuple[ProviderPublicSummary, ...]

    def __post_init__(self) -> None:
        if type(self.ready) is not bool:
            raise TypeError("Production readiness must be a boolean.")
        if type(self.providers) is not tuple or tuple(
            item.provider for item in self.providers
        ) != PROVIDER_NAMES:
            raise ValueError("Production readiness must summarize all five providers.")
        if any(not isinstance(item, ProviderPublicSummary) for item in self.providers):
            raise TypeError("Production readiness provider summary is malformed.")
        all_ready = all(
            item.status is PublicProviderStatus.READY for item in self.providers
        )
        if self.ready != all_ready:
            raise ValueError("Production readiness conflicts with provider statuses.")

    def as_dict(self) -> dict[str, object]:
        """Return a public result with no provider object identifiers or paths."""

        return {
            "ready": self.ready,
            "providers": [item.as_dict() for item in self.providers],
        }


def validate_external_writer_attestation(
    attestation: SignedExternalWriterAttestation,
    expected_manifest: ExpectedObjectManifest,
    verifier: ExternalAttestationVerifier,
    *,
    now: datetime | None = None,
) -> None:
    """Validate metadata, fence binding, freshness, and an injected signature."""

    if not isinstance(attestation, SignedExternalWriterAttestation):
        raise ExternalAttestationError("External-writer attestation is missing.")
    if not isinstance(expected_manifest, ExpectedObjectManifest):
        raise TypeError("Expected object manifest is malformed.")
    verify = getattr(verifier, "verify", None)
    if not callable(verify):
        raise ExternalAttestationError(
            "An injected external-attestation verifier is required."
        )
    checked_at = now or datetime.now(UTC)
    _validate_utc_datetime(checked_at, "Attestation validation time")
    expected = expected_manifest.for_provider("external_writers")
    if attestation.expected_manifest_digest != expected_manifest.digest:
        raise ExternalAttestationError("External attestation manifest does not match.")
    if attestation.object_keys != expected.object_keys:
        raise ExternalAttestationError("External attestation objects do not match.")
    if attestation.fence.scope_digest != expected.digest:
        raise ExternalAttestationError("External attestation fence scope does not match.")
    if not (attestation.issued_at <= checked_at < attestation.expires_at):
        raise ExternalAttestationError("External attestation is not currently valid.")
    if attestation.fence.acquired_at > attestation.issued_at:
        raise ExternalAttestationError("External attestation predates its writer fence.")
    if checked_at >= attestation.fence.expires_at:
        raise ExternalAttestationError("External writer fence has expired.")
    if attestation.expires_at > attestation.fence.expires_at:
        raise ExternalAttestationError("External attestation outlives its writer fence.")
    try:
        verified = verify(attestation, attestation.canonical_payload())
    except Exception as err:
        raise ExternalAttestationError(
            "External attestation signature verification failed."
        ) from err
    if type(verified) is not bool or not verified:
        raise ExternalAttestationError(
            "External attestation signature verification failed."
        )


async def async_probe_active_yaml(
    hass: HomeAssistant,
    *,
    domains: tuple[str, ...] | None = None,
) -> ProviderInventory:
    """Inventory YAML object presence and annotations without retaining payloads."""

    provider = "active_yaml"
    _validate_optional_string_tuple(domains, "Active YAML domains")
    if domains == ():
        return ProviderInventory.readable(provider)
    # Core's complete YAML loader can import integrations and resolve
    # requirements. Nonempty inventory therefore requires the fenced host bridge.
    return ProviderInventory.unavailable(provider)


async def async_read_config_entry_reference_snapshot(
    hass: HomeAssistant,
    policy: tuple[ConfigEntryReferenceObjectPolicy, ...],
) -> tuple[ProviderDocumentSnapshot, ...]:
    """Read an exact, projected config-entry snapshot without host mutations."""

    _validate_config_entry_reference_policy(policy)
    try:
        expected_ids = tuple(item.entry_id for item in policy)
        expected_id_set = frozenset(expected_ids)
        selected_entries = tuple(
            entry
            for domain in sorted({item.domain for item in policy})
            for entry in hass.config_entries.async_entries(domain)
            if getattr(entry, "entry_id", None) in expected_id_set
        )
        entries_by_id: dict[str, Any] = {}
        for entry in selected_entries:
            entry_id = getattr(entry, "entry_id", None)
            domain = getattr(entry, "domain", None)
            if type(entry_id) is not str or type(domain) is not str:
                raise ConfigEntryReferenceSnapshotError(
                    "Selected config-entry reference object has an invalid shape."
                )
            if entry_id in entries_by_id:
                raise ConfigEntryReferenceSnapshotError(
                    "Selected config-entry references do not match the exact policy."
                )
            entries_by_id[entry_id] = entry

        if tuple(sorted(entries_by_id)) != expected_ids:
            raise ConfigEntryReferenceSnapshotError(
                "Selected config-entry references do not match the exact policy."
            )

        snapshots: list[ProviderDocumentSnapshot] = []
        for item in policy:
            entry = entries_by_id[item.entry_id]
            if entry.domain != item.domain:
                raise ConfigEntryReferenceSnapshotError(
                    "Selected config-entry references do not match the exact policy."
                )
            expected_version = _CONFIG_ENTRY_REFERENCE_VERSIONS[item.domain]
            version = getattr(entry, "version", None)
            minor_version = getattr(entry, "minor_version", None)
            if (
                type(version) is not int
                or type(minor_version) is not int
                or (version, minor_version) != expected_version
            ):
                raise ConfigEntryReferenceSnapshotError(
                    "Selected config-entry reference schema version is unsupported."
                )
            modified_at = getattr(entry, "modified_at", None)
            if (
                not isinstance(modified_at, datetime)
                or modified_at.utcoffset() != timedelta(0)
            ):
                raise ConfigEntryReferenceSnapshotError(
                    "Selected config-entry reference object has an invalid shape."
                )

            projected = _project_config_entry_reference(entry, item.domain)
            fingerprint = _digest_json(projected)
            revision = _digest_json(
                {
                    "modified_at": modified_at.isoformat(),
                    "version": version,
                    "minor_version": minor_version,
                    "projected_fingerprint": fingerprint,
                }
            )
            snapshots.append(
                ProviderDocumentSnapshot(
                    provider="config_entry",
                    object_id=item.entry_id,
                    revision=revision,
                    payload=projected,
                )
            )
        return tuple(snapshots)
    except ConfigEntryReferenceSnapshotError:
        raise
    except Exception:
        raise ConfigEntryReferenceSnapshotError(
            "Config-entry reference snapshot could not be read safely."
        ) from None


async def async_probe_config_entries(
    hass: HomeAssistant,
    *,
    domains: tuple[str, ...] | None = None,
) -> ProviderInventory:
    """Inventory config entries through the public manager without retaining data."""

    provider = "config_entry"
    _validate_optional_string_tuple(domains, "Config-entry domains")
    if domains == ():
        return ProviderInventory.readable(provider)
    selected = set(domains) if domains is not None else None
    try:
        observations: list[InventoryObject] = []
        for entry in hass.config_entries.async_entries():
            domain = entry.domain
            entry_id = entry.entry_id
            _validate_nonempty_string(domain, "Config-entry domain")
            _validate_nonempty_string(entry_id, "Config-entry ID")
            if selected is not None and domain not in selected:
                continue
            modified_at = getattr(entry, "modified_at", None)
            if isinstance(modified_at, datetime):
                revision: Revision = modified_at.isoformat()
            else:
                revision = f"{entry.version}.{entry.minor_version}"
            observations.append(
                InventoryObject(
                    _config_entry_key(domain, entry_id),
                    revision=revision,
                )
            )
        return ProviderInventory.readable(provider, observations)
    except Exception:
        return ProviderInventory.error(provider)


async def async_probe_lovelace(
    hass: HomeAssistant,
    *,
    dashboards: tuple[str | None, ...] | None = None,
) -> ProviderInventory:
    """Inventory views by loading only Home Assistant's dashboard objects."""

    provider = "lovelace"
    if dashboards == ():
        return ProviderInventory.readable(provider)
    if dashboards is not None:
        HomeAssistantInventoryScope(lovelace_dashboards=dashboards)
    # Loading dashboard objects can hydrate caches and emit update events.
    # Nonempty inventory therefore requires the fenced host bridge.
    return ProviderInventory.unavailable(provider)


async def async_probe_scheduler(
    hass: HomeAssistant,
    *,
    entity_prefix: str = "switch.schedule_",
    entity_ids: tuple[str, ...] | None = None,
) -> ProviderInventory:
    """Inventory Scheduler profiles from state and service surfaces only."""

    provider = "scheduler"
    HomeAssistantInventoryScope(
        scheduler_entity_prefix=entity_prefix,
        scheduler_entity_ids=entity_ids,
    )
    if entity_ids == ():
        return ProviderInventory.readable(provider)
    try:
        if any(
            not hass.services.has_service("scheduler", service)
            for service in _SCHEDULER_SERVICES
        ):
            return ProviderInventory.unavailable(provider)
        observations: list[InventoryObject] = []
        states = (
            tuple(
                state
                for entity_id in entity_ids
                if (state := hass.states.get(entity_id)) is not None
            )
            if entity_ids is not None
            else tuple(
                state
                for state in hass.states.async_all("switch")
                if state.entity_id.startswith(entity_prefix)
            )
        )
        for state in states:
            attributes = state.attributes
            if any(
                name not in attributes
                or not isinstance(attributes[name], (list, tuple))
                for name in _SCHEDULER_ATTRIBUTES
            ):
                return ProviderInventory.error(provider)
            observations.append(
                InventoryObject(
                    state.entity_id,
                    revision=state.last_updated.isoformat(),
                )
            )
        return ProviderInventory.readable(provider, observations)
    except Exception:
        return ProviderInventory.error(provider)


def probe_external_writers(
    expected_manifest: ExpectedObjectManifest,
    *,
    attestation: SignedExternalWriterAttestation | None = None,
    verifier: ExternalAttestationVerifier | None = None,
    now: datetime | None = None,
) -> ProviderInventory:
    """Use verified attestation metadata or report external writers unavailable."""

    provider = "external_writers"
    if attestation is None or verifier is None:
        return ProviderInventory.unavailable(provider)
    try:
        validate_external_writer_attestation(
            attestation,
            expected_manifest,
            verifier,
            now=now,
        )
    except (ExternalAttestationError, TypeError, ValueError):
        return ProviderInventory.unavailable(provider)
    return ProviderInventory.readable(
        provider,
        (
            InventoryObject(key, revision=attestation.inventory_revision)
            for key in attestation.object_keys
        ),
    )


async def async_probe_home_assistant_inventory(
    hass: HomeAssistant,
    expected_manifest: ExpectedObjectManifest,
    *,
    scope: HomeAssistantInventoryScope | None = None,
    external_attestation: SignedExternalWriterAttestation | None = None,
    external_verifier: ExternalAttestationVerifier | None = None,
    now: datetime | None = None,
) -> tuple[ProviderInventory, ...]:
    """Collect all five inventories without mutating Home Assistant state."""

    if not isinstance(expected_manifest, ExpectedObjectManifest):
        raise TypeError("Expected object manifest is malformed.")
    selected_scope = scope or HomeAssistantInventoryScope()
    if not isinstance(selected_scope, HomeAssistantInventoryScope):
        raise TypeError("Home Assistant inventory scope is malformed.")
    if selected_scope.expected_manifest_digest != expected_manifest.digest:
        return tuple(
            ProviderInventory.unavailable(provider)
            for provider in PROVIDER_NAMES
        )
    inventories = {
        "active_yaml": await async_probe_active_yaml(
            hass,
            domains=selected_scope.active_yaml_domains,
        ),
        "config_entry": await async_probe_config_entries(
            hass,
            domains=selected_scope.config_entry_domains,
        ),
        "external_writers": probe_external_writers(
            expected_manifest,
            attestation=external_attestation,
            verifier=external_verifier,
            now=now,
        ),
        "lovelace": await async_probe_lovelace(
            hass,
            dashboards=selected_scope.lovelace_dashboards,
        ),
        "scheduler": await async_probe_scheduler(
            hass,
            entity_prefix=selected_scope.scheduler_entity_prefix,
            entity_ids=selected_scope.scheduler_entity_ids,
        ),
    }
    return tuple(inventories[provider] for provider in PROVIDER_NAMES)


def assess_production_readiness(
    expected_manifest: ExpectedObjectManifest,
    inventories: Iterable[ProviderInventory],
    bridges: Iterable[BridgeReadiness],
    *,
    external_attestation: SignedExternalWriterAttestation | None = None,
    external_verifier: ExternalAttestationVerifier | None = None,
    now: datetime | None = None,
) -> ProductionReadiness:
    """Fail closed unless exact inventory and bridge proofs cover all providers."""

    if not isinstance(expected_manifest, ExpectedObjectManifest):
        raise TypeError("Expected object manifest is malformed.")
    inventory_map, duplicate_inventories = _index_provider_items(
        inventories,
        ProviderInventory,
    )
    bridge_map, duplicate_bridges = _index_provider_items(bridges, BridgeReadiness)
    external_valid = False
    if external_attestation is not None and external_verifier is not None:
        try:
            validate_external_writer_attestation(
                external_attestation,
                expected_manifest,
                external_verifier,
                now=now,
            )
            external_valid = True
        except (ExternalAttestationError, TypeError, ValueError):
            pass

    summaries: list[ProviderPublicSummary] = []
    for provider in PROVIDER_NAMES:
        expected = expected_manifest.for_provider(provider)
        inventory = inventory_map.get(provider)
        bridge = bridge_map.get(provider)
        bridge_exact = (
            provider not in duplicate_bridges
            and bridge is not None
            and bridge.available
            and bridge.capabilities.production_ready
            and bridge.object_count == expected.count
            and bridge.expected_manifest_digest == expected_manifest.digest
            and bridge.object_manifest_digest == expected.digest
        )
        observed_count = inventory.count if inventory is not None else 0
        if inventory is None and bridge_exact and bridge is not None:
            observed_count = bridge.object_count
        if (
            provider in duplicate_inventories
            or inventory is None
            or inventory.status is not InventoryStatus.READABLE
        ):
            status = (
                PublicProviderStatus.READY
                if provider in _HOST_AUTHORITATIVE_PROVIDERS and bridge_exact
                else PublicProviderStatus.UNAVAILABLE
            )
        elif inventory.count != expected.count:
            status = PublicProviderStatus.COUNT_MISMATCH
        elif inventory.object_keys != expected.object_keys:
            status = PublicProviderStatus.MANIFEST_MISMATCH
        elif provider == "external_writers" and not external_valid:
            status = PublicProviderStatus.UNAVAILABLE
        else:
            if (
                provider in duplicate_bridges
                or bridge is None
                or not bridge.available
                or not bridge.capabilities.production_ready
            ):
                status = PublicProviderStatus.READ_ONLY
            elif bridge.object_count != expected.count:
                status = PublicProviderStatus.COUNT_MISMATCH
            elif (
                bridge.expected_manifest_digest != expected_manifest.digest
                or bridge.object_manifest_digest != expected.digest
                or bridge.inventory_revision != inventory.revision_digest
            ):
                status = PublicProviderStatus.MANIFEST_MISMATCH
            else:
                status = PublicProviderStatus.READY
        summaries.append(
            ProviderPublicSummary(
                provider,
                status,
                expected.count,
                observed_count,
            )
        )
    providers = tuple(summaries)
    return ProductionReadiness(
        all(item.status is PublicProviderStatus.READY for item in providers),
        providers,
    )


def _index_provider_items(
    items: Iterable[Any],
    expected_type: type,
) -> tuple[dict[str, Any], set[str]]:
    if isinstance(items, (str, bytes)):
        raise TypeError("Provider results must be an iterable of typed objects.")
    indexed: dict[str, Any] = {}
    duplicates: set[str] = set()
    for item in items:
        if not isinstance(item, expected_type):
            raise TypeError("Provider result has the wrong type.")
        if item.provider in indexed:
            duplicates.add(item.provider)
        else:
            indexed[item.provider] = item
    return indexed, duplicates


def _validate_config_entry_reference_policy(
    policy: tuple[ConfigEntryReferenceObjectPolicy, ...],
) -> None:
    if type(policy) is not tuple:
        raise ConfigEntryReferenceSnapshotError(
            "Config-entry reference policy must be an immutable tuple."
        )
    if any(not isinstance(item, ConfigEntryReferenceObjectPolicy) for item in policy):
        raise ConfigEntryReferenceSnapshotError(
            "Config-entry reference policy is malformed."
        )
    entry_ids = tuple(item.entry_id for item in policy)
    if entry_ids != tuple(sorted(entry_ids)) or len(entry_ids) != len(set(entry_ids)):
        raise ConfigEntryReferenceSnapshotError(
            "Config-entry reference policy must contain unique entry IDs in sorted order."
        )


def _project_config_entry_reference(
    entry: Any,
    domain: str,
) -> dict[str, Any]:
    data = getattr(entry, "data", None)
    options = getattr(entry, "options", None)
    subentries = getattr(entry, "subentries", None)
    if (
        not isinstance(data, Mapping)
        or data
        or not isinstance(options, Mapping)
        or not isinstance(subentries, Mapping)
        or subentries
    ):
        raise ConfigEntryReferenceSnapshotError(
            "Selected config-entry reference object has an invalid shape."
        )
    option_fields = tuple(options)
    if any(type(name) is not str for name in option_fields):
        raise ConfigEntryReferenceSnapshotError(
            "Selected config-entry reference object has an invalid shape."
        )

    projected: dict[str, Any]
    if domain == "generic_thermostat":
        if (
            not set(option_fields) <= _GENERIC_THERMOSTAT_OPTION_FIELDS
            or "heater" not in options
            or "target_sensor" not in options
            or not _is_projected_entity_id(options["heater"], {"fan", "switch"})
            or not _is_projected_entity_id(options["target_sensor"], {"sensor"})
        ):
            raise ConfigEntryReferenceSnapshotError(
                "Selected config-entry reference object has an invalid shape."
            )
        projected = {
            "heater": options["heater"],
            "target_sensor": options["target_sensor"],
        }
    elif domain == "template":
        if (
            not set(option_fields) <= _TEMPLATE_OPTION_FIELDS
            or "state" not in options
        ):
            raise ConfigEntryReferenceSnapshotError(
                "Selected config-entry reference object has an invalid shape."
            )
        if options.get("template_type") != _TEMPLATE_REFERENCE_TYPE:
            raise ConfigEntryReferenceSnapshotError(
                "Selected config-entry reference object has an invalid shape."
            )
        state = _validate_config_entry_reference_template(options["state"])
        projected = {"state": state}
        if "advanced_options" in options:
            advanced_options = options["advanced_options"]
            if not isinstance(advanced_options, Mapping) or any(
                type(name) is not str for name in advanced_options
            ):
                raise ConfigEntryReferenceSnapshotError(
                    "Selected config-entry reference object has an invalid shape."
                )
            if set(advanced_options) - {"availability"}:
                raise ConfigEntryReferenceSnapshotError(
                    "Selected config-entry reference object has an invalid shape."
                )
            if "availability" in advanced_options:
                projected["availability_template"] = (
                    _validate_config_entry_reference_template(
                        advanced_options["availability"],
                        field="availability_template",
                    )
                )
    else:
        raise ConfigEntryReferenceSnapshotError(
            "Selected config-entry reference object has an unsupported domain."
        )
    _validate_projected_config_entry_reference(domain, projected)
    return projected


def _validate_projected_config_entry_reference(
    domain: str,
    projected: Mapping[str, Any],
) -> None:
    fields = set(projected)
    if domain == "generic_thermostat":
        valid = fields == {"heater", "target_sensor"}
    else:
        valid = fields in ({"state"}, {"availability_template", "state"})
    if not valid:
        raise ConfigEntryReferenceSnapshotError(
            "Projected config-entry reference schema contains unexpected fields."
        )


def _validate_config_entry_reference_template(
    value: Any,
    *,
    field: str = "state",
) -> str:
    if (
        field not in {"availability_template", "state"}
        or type(value) is not str
        or not value
        or "\x00" in value
        or len(value) > _CONFIG_ENTRY_REFERENCE_TEMPLATE_MAX_BYTES
        or len(value.encode("utf-8")) > _CONFIG_ENTRY_REFERENCE_TEMPLATE_MAX_BYTES
    ):
        raise ConfigEntryReferenceSnapshotError(
            "Selected config-entry reference object has an invalid shape."
        )
    entity_ids = {
        match.group("entity")
        for match in _CONFIG_ENTRY_REFERENCE_ENTITY_PATTERN.finditer(value)
    }
    if len(entity_ids) > _CONFIG_ENTRY_REFERENCE_TEMPLATE_MAX_ENTITIES:
        raise ConfigEntryReferenceSnapshotError(
            "Config-entry reference template is too complex."
        )
    entity_ids.add(_CONFIG_ENTRY_REFERENCE_VALIDATION_ENTITY)
    for entity_id in sorted(entity_ids):
        scan = scan_semantic_references(
            {field: value},
            entity_id,
            provider="config_entry",
        )
        if scan.blocked:
            raise ConfigEntryReferenceSnapshotError(
                "Config-entry reference template is dynamic or ambiguous."
            )
    return value


def _is_projected_entity_id(value: Any, domains: set[str]) -> bool:
    return bool(
        type(value) is str
        and _CONFIG_ENTRY_REFERENCE_ENTITY_PATTERN.fullmatch(value) is not None
        and value.split(".", 1)[0] in domains
    )


def _copy_projected_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ConfigEntryReferenceSnapshotError(
            "Projected provider document payload must be a mapping."
        )

    def copy_value(value: Any) -> Any:
        if isinstance(value, Mapping):
            if any(type(key) is not str for key in value):
                raise ConfigEntryReferenceSnapshotError(
                    "Projected provider document payload is not canonical."
                )
            return {key: copy_value(value[key]) for key in sorted(value)}
        if type(value) in (list, tuple):
            return [copy_value(item) for item in value]
        if value is None or type(value) in (bool, int, float, str):
            return value
        raise ConfigEntryReferenceSnapshotError(
            "Projected provider document payload is not canonical."
        )

    return copy_value(payload)


def _freeze_projected_payload(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType(
            {key: _freeze_projected_payload(item) for key, item in value.items()}
        )
    if type(value) is list:
        return tuple(_freeze_projected_payload(item) for item in value)
    return value


def _config_entry_key(domain: str, entry_id: str) -> str:
    return json.dumps([domain, entry_id], ensure_ascii=True, separators=(",", ":"))


def _validate_provider(provider: str) -> None:
    if type(provider) is not str or provider not in TRUE_FAMILY_PROVIDER_MANIFEST:
        raise ValueError("Provider name is not in the True Family manifest.")


def _validate_nonempty_string(value: str, label: str) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be a non-empty canonical string.")


def _validate_object_keys(object_keys: tuple[str, ...]) -> None:
    if type(object_keys) is not tuple:
        raise TypeError("Provider object keys must be a tuple.")
    for key in object_keys:
        _validate_nonempty_string(key, "Provider object key")
    if object_keys != tuple(sorted(object_keys)) or len(object_keys) != len(
        set(object_keys)
    ):
        raise ValueError("Provider object keys must be unique and sorted.")


def _validate_revision(revision: Revision, label: str) -> None:
    if isinstance(revision, bool) or not isinstance(revision, (str, int)):
        raise TypeError(f"{label} must be a string or integer.")
    if isinstance(revision, str):
        _validate_nonempty_string(revision, label)
    elif revision < 0:
        raise ValueError(f"{label} cannot be negative.")


def _validate_digest(digest: str, label: str) -> None:
    if type(digest) is not str or _DIGEST_PATTERN.fullmatch(digest) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest.")


def _validate_utc_datetime(value: datetime, label: str) -> None:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be a timezone-aware UTC datetime.")


def _validate_optional_string_tuple(
    values: tuple[str, ...] | None,
    label: str,
) -> None:
    if values is None:
        return
    if type(values) is not tuple:
        raise TypeError(f"{label} must be a tuple or None.")
    for value in values:
        _validate_nonempty_string(value, label)
    if len(values) != len(set(values)):
        raise ValueError(f"{label} contains duplicates.")


def _canonical_revision(revision: Revision) -> dict[str, str | int]:
    if isinstance(revision, int):
        return {"kind": "integer", "value": revision}
    return {"kind": "string", "value": revision}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()
