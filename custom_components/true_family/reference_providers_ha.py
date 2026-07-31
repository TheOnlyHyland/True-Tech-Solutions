"""Read-only Home Assistant inventory and fail-closed provider readiness."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

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
_EXACT_REFERENCE_INVENTORY_TIMEOUT_SECONDS = 30.0
_CANCELLATION_CLEANUP_TIMEOUT_SECONDS = 0.25
_REFERENCE_SNAPSHOT_MAX_DOCUMENTS_PER_PROVIDER = 512
_REFERENCE_SNAPSHOT_MAX_DOCUMENTS = 1_024
_REFERENCE_SNAPSHOT_MAX_OBJECT_KEY_BYTES = 512
_REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES = 1_048_576
_REFERENCE_SNAPSHOT_MAX_AGGREGATE_BYTES = 16_777_216
_REFERENCE_SNAPSHOT_MAX_INVENTORY_DIGEST_BYTES = 17_825_792
_REFERENCE_SNAPSHOT_MAX_PAYLOAD_DEPTH = 100
_REFERENCE_SNAPSHOT_MAX_PAYLOAD_NODES = 100_000
_REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES = 100_000
_REFERENCE_SNAPSHOT_MAX_INTEGER_BITS = 13_500
_REFERENCE_SNAPSHOT_JSON_CHUNK_BYTES = 4_096
_CONFIG_ENTRY_OPAQUE_KEY_PREFIX = "tf-reference-object-sha256-v1:"
_PREPARED_PAYLOAD_FAILED = object()
_RECOMPUTED_DOCUMENT_FAILED = object()
_RAW_CONFIG_ENTRY_SNAPSHOT_FAILED = object()
_CONFIG_ENTRY_SOURCE_FAILED = object()
_SOURCE_STREAM_FAILED = object()
_SOURCE_STREAM_END = object()
_CLEANUP_MISSING = object()
_COLLECTION_FAILED = object()
_COLLECTION_TIMED_OUT = object()
_EXACT_REFERENCE_INVENTORY_TOKEN = object()
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


class ExactReferenceInventorySnapshotError(ValueError):
    """Raised when an exact five-provider snapshot cannot be trusted."""


class _SnapshotDeadlineExceeded(TimeoutError):
    """Internal marker for synchronous metadata returning after the deadline."""


@dataclass(frozen=True, slots=True)
class ConfigEntryReferenceObjectPolicy:
    """Server-owned identity for one supported config-entry reference object."""

    entry_id: str = field(repr=False)
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
    object_keys: tuple[str, ...] = field(repr=False)

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
    providers: tuple[ExpectedProviderObjects, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.revision) is not str
            or len(self.revision) > _REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES
        ):
            raise ValueError("Expected manifest revision is malformed.")
        _validate_nonempty_string(self.revision, "Expected manifest revision")
        providers = self._typed_providers()
        names = tuple(item.provider for item in providers)
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
        return self._typed_providers()[PROVIDER_NAMES.index(provider)]

    @property
    def digest(self) -> str:
        """Return a stable digest of the complete expected manifest."""

        providers = self._typed_providers()
        return _digest_json(
            {
                "revision": self.revision,
                "providers": [
                    {
                        "provider": item.provider,
                        "objects": list(item.object_keys),
                    }
                    for item in providers
                ],
            }
        )

    def _typed_providers(self) -> tuple[ExpectedProviderObjects, ...]:
        providers = self.providers
        if type(providers) is not tuple or any(
            type(item) is not ExpectedProviderObjects for item in providers
        ):
            raise TypeError(
                "Expected manifest providers must be exact typed records."
            )
        for item in providers:
            _validate_provider(item.provider)
            _validate_object_keys(item.object_keys)
        return providers


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
class _PreparedProviderDocument:
    payload: Any = field(repr=False)
    fingerprint: str = field(repr=False)
    payload_size: int
    document_size: int
    node_count: int


@dataclass(frozen=True, slots=True, init=False)
class ProviderDocumentSnapshot:
    """Immutable projected provider document with its payload hidden from repr."""

    provider: str
    object_id: str = field(repr=False)
    revision: Revision = field(repr=False)
    payload: Any = field(repr=False)
    writable: bool = field(default=False, init=False)
    fingerprint: str = field(init=False, repr=False)
    _canonical_payload_size: int = field(init=False, repr=False, compare=False)
    _canonical_document_size: int = field(init=False, repr=False, compare=False)
    _canonical_node_count: int = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        provider: str,
        object_id: str,
        revision: Revision,
        payload: Any,
    ) -> None:
        prepared = _prepare_provider_document_snapshot(
            provider,
            object_id,
            revision,
            payload,
        )
        if type(prepared) is not _PreparedProviderDocument:
            object.__setattr__(self, "provider", "active_yaml")
            object.__setattr__(self, "object_id", "")
            object.__setattr__(self, "revision", 0)
            object.__setattr__(self, "payload", MappingProxyType({}))
            object.__setattr__(self, "writable", False)
            del object_id, payload, provider, revision
            raise ConfigEntryReferenceSnapshotError(
                "Projected provider document is not canonical."
            )
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "object_id", object_id)
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "payload", prepared.payload)
        object.__setattr__(self, "writable", False)
        object.__setattr__(self, "fingerprint", prepared.fingerprint)
        object.__setattr__(
            self,
            "_canonical_payload_size",
            prepared.payload_size,
        )
        object.__setattr__(
            self,
            "_canonical_document_size",
            prepared.document_size,
        )
        object.__setattr__(
            self,
            "_canonical_node_count",
            prepared.node_count,
        )

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


@runtime_checkable
class ReadOnlyProviderSnapshotSource(Protocol):
    """Read-only source for one exact provider document set."""

    @property
    def name(self) -> str:
        """Return one canonical provider name."""

        ...

    @property
    def expected_objects(self) -> ExpectedProviderObjects:
        """Return the source-owned exact opaque object set."""

        ...

    def async_read_snapshot(
        self,
        hass: HomeAssistant,
    ) -> AsyncIterator[ProviderDocumentSnapshot]:
        """Stream immutable read-only documents in canonical key order."""

        ...


@dataclass(frozen=True, slots=True)
class _SnapshotSourceRegistration:
    name: str
    expected_objects: ExpectedProviderObjects = field(repr=False)
    reader: Callable[
        [HomeAssistant],
        AsyncIterator[ProviderDocumentSnapshot],
    ] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _CollectedProviderStream:
    inventory: ProviderDocumentInventory
    document_count: int
    canonical_size: int
    node_count: int


@dataclass(frozen=True, slots=True, init=False)
class ConfigEntryReferenceSnapshotSource:
    """Opaque read-only wrapper around the exact config-entry projector."""

    _policy: tuple[ConfigEntryReferenceObjectPolicy, ...] = field(repr=False)
    name: str = field(default="config_entry", init=False)
    expected_objects: ExpectedProviderObjects = field(init=False, repr=False)

    def __init__(
        self,
        policy: tuple[ConfigEntryReferenceObjectPolicy, ...],
    ) -> None:
        if not _config_entry_reference_policy_is_valid(policy):
            object.__setattr__(self, "_policy", ())
            object.__setattr__(self, "name", "config_entry")
            object.__setattr__(
                self,
                "expected_objects",
                ExpectedProviderObjects("config_entry", ()),
            )
            del policy
            raise ConfigEntryReferenceSnapshotError(
                "Config-entry reference policy is malformed."
            )
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "name", "config_entry")
        object.__setattr__(
            self,
            "expected_objects",
            ExpectedProviderObjects(
                "config_entry",
                tuple(
                    sorted(
                        _config_entry_reference_opaque_key(item.domain, item.entry_id)
                        for item in policy
                    )
                ),
            ),
        )

    def async_read_snapshot(
        self,
        hass: HomeAssistant,
    ) -> AsyncIterator[ProviderDocumentSnapshot]:
        """Stream raw entry projections under deterministic opaque object keys."""

        return _async_iter_opaque_config_entry_snapshot(
            hass,
            self._policy,
        )


@dataclass(frozen=True, slots=True)
class ProviderDocumentInventory:
    """Exact immutable documents and digest for one canonical provider."""

    provider: str
    documents: tuple[ProviderDocumentSnapshot, ...] = field(repr=False)
    digest: str = field(init=False, repr=False)
    _canonical_size: int = field(init=False, repr=False, compare=False)
    _canonical_node_count: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_provider(self.provider)
        if type(self.documents) is not tuple or any(
            type(item) is not ProviderDocumentSnapshot for item in self.documents
        ):
            raise ExactReferenceInventorySnapshotError(
                "Provider snapshot documents must be an immutable typed tuple."
            )
        if len(self.documents) > _REFERENCE_SNAPSHOT_MAX_DOCUMENTS_PER_PROVIDER:
            raise ExactReferenceInventorySnapshotError(
                "Provider snapshot exceeds its document limit."
            )
        object_keys = tuple(item.object_id for item in self.documents)
        if object_keys != tuple(sorted(object_keys)) or len(object_keys) != len(
            set(object_keys)
        ):
            raise ExactReferenceInventorySnapshotError(
                "Provider snapshot object keys must be unique and sorted."
            )

        canonical_size = 0
        canonical_node_count = 0
        digest_documents: list[dict[str, Any]] = []
        for document in self.documents:
            if document.provider != self.provider:
                raise ExactReferenceInventorySnapshotError(
                    "Provider snapshot contains a document for another provider."
                )
            if document.writable is not False:
                raise ExactReferenceInventorySnapshotError(
                    "Provider snapshot contains a writable document."
                )
            estimated_node_count = document._canonical_node_count
            if (
                type(estimated_node_count) is not int
                or estimated_node_count <= 0
                or canonical_node_count + estimated_node_count
                > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES
            ):
                raise ExactReferenceInventorySnapshotError(
                    "Provider snapshot exceeds the aggregate node limit."
                )
            fingerprint, document_size, node_count = _validate_snapshot_document(
                document
            )
            canonical_size += document_size
            if canonical_size > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_BYTES:
                raise ExactReferenceInventorySnapshotError(
                    "Provider snapshot exceeds the aggregate size limit."
                )
            canonical_node_count += node_count
            if (
                canonical_node_count
                > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES
            ):
                raise ExactReferenceInventorySnapshotError(
                    "Provider snapshot exceeds the aggregate node limit."
                )
            digest_documents.append(
                {
                    "object_key": document.object_id,
                    "revision": _canonical_revision(document.revision),
                    "payload_fingerprint": fingerprint,
                }
            )

        object.__setattr__(self, "_canonical_size", canonical_size)
        object.__setattr__(
            self,
            "_canonical_node_count",
            canonical_node_count,
        )
        digest, _digest_size = _stream_canonical_json_digest(
            {
                "domain": "true-family-provider-document-inventory-v1",
                "provider": self.provider,
                "documents": digest_documents,
            },
            _REFERENCE_SNAPSHOT_MAX_INVENTORY_DIGEST_BYTES,
        )
        object.__setattr__(self, "digest", digest)

    @property
    def count(self) -> int:
        """Return the exact document count."""

        return len(self.documents)

    @property
    def object_keys(self) -> tuple[str, ...]:
        """Return the exact opaque object keys for internal comparison."""

        return tuple(item.object_id for item in self.documents)


@dataclass(frozen=True, slots=True, init=False)
class ExactReferenceInventorySnapshot:
    """Manifest-bound read-only inventory of all five provider snapshots."""

    expected_manifest_digest: str = field(repr=False)
    providers: tuple[ProviderDocumentInventory, ...] = field(repr=False)
    read_only: bool = field(default=True, init=False)
    digest: str = field(init=False, repr=False)

    def __init__(
        self,
        expected_manifest_digest: str,
        providers: tuple[ProviderDocumentInventory, ...],
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not _EXACT_REFERENCE_INVENTORY_TOKEN:
            raise TypeError(
                "Exact reference inventory snapshots are collector-owned."
            )
        object.__setattr__(self, "expected_manifest_digest", expected_manifest_digest)
        object.__setattr__(self, "providers", providers)
        object.__setattr__(self, "read_only", True)
        _validate_digest(
            self.expected_manifest_digest,
            "Exact inventory expected manifest digest",
        )
        if type(self.providers) is not tuple or any(
            type(item) is not ProviderDocumentInventory for item in self.providers
        ):
            raise ExactReferenceInventorySnapshotError(
                "Exact inventory providers must be an immutable typed tuple."
            )
        if tuple(item.provider for item in self.providers) != PROVIDER_NAMES:
            raise ExactReferenceInventorySnapshotError(
                "Exact inventory must contain all five providers in canonical order."
            )
        if sum(item.count for item in self.providers) > _REFERENCE_SNAPSHOT_MAX_DOCUMENTS:
            raise ExactReferenceInventorySnapshotError(
                "Exact inventory exceeds its aggregate document limit."
            )
        if (
            sum(item._canonical_size for item in self.providers)
            > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_BYTES
        ):
            raise ExactReferenceInventorySnapshotError(
                "Exact inventory exceeds its aggregate size limit."
            )
        node_counts = tuple(
            item._canonical_node_count for item in self.providers
        )
        if any(type(count) is not int or count < 0 for count in node_counts) or (
            sum(node_counts) > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES
        ):
            raise ExactReferenceInventorySnapshotError(
                "Exact inventory exceeds its aggregate node limit."
            )
        object.__setattr__(
            self,
            "digest",
            _digest_json(
                {
                    "domain": "true-family-exact-reference-inventory-v1",
                    "expected_manifest_digest": self.expected_manifest_digest,
                    "providers": [
                        {
                            "provider": item.provider,
                            "inventory_digest": item.digest,
                        }
                        for item in self.providers
                    ],
                }
            ),
        )

    def as_public_summary(self) -> dict[str, object]:
        """Return only read-only state, canonical names, and document counts."""

        return {
            "read_only": self.read_only,
            "providers": [
                {"provider": item.provider, "count": item.count}
                for item in self.providers
            ],
        }


async def async_read_exact_reference_inventory_snapshot(
    hass: HomeAssistant,
    expected: ExpectedObjectManifest,
    sources: tuple[ReadOnlyProviderSnapshotSource, ...],
) -> ExactReferenceInventorySnapshot:
    """Read five exact sources sequentially under one overall timeout."""

    outcome = await _async_collect_exact_reference_inventory_snapshot(
        hass,
        expected,
        sources,
    )
    del hass, expected, sources
    if outcome is _COLLECTION_TIMED_OUT:
        raise TimeoutError("Exact reference inventory snapshot timed out.")
    if type(outcome) is not ExactReferenceInventorySnapshot:
        raise ExactReferenceInventorySnapshotError(
            "Exact reference inventory snapshot could not be read safely."
        )
    return outcome


async def _async_collect_exact_reference_inventory_snapshot(
    hass: HomeAssistant,
    expected: ExpectedObjectManifest,
    sources: tuple[ReadOnlyProviderSnapshotSource, ...],
) -> ExactReferenceInventorySnapshot | object:
    # Sources are internal and directly awaited to preserve the no-task contract.
    # Synchronous descriptor/reader/cleanup code cannot be preempted while it
    # owns the event-loop thread; monotonic checks fail closed when control returns.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _EXACT_REFERENCE_INVENTORY_TIMEOUT_SECONDS
    try:
        async with asyncio.timeout_at(deadline):
            try:
                registrations = _prevalidate_snapshot_sources(
                    expected,
                    sources,
                    deadline=deadline,
                )
            except _SnapshotDeadlineExceeded:
                return _COLLECTION_TIMED_OUT
            except Exception:
                return _collection_failure_outcome(loop, deadline)
            if loop.time() >= deadline:
                return _COLLECTION_TIMED_OUT

            inventories: list[ProviderDocumentInventory] = []
            aggregate_size = 0
            aggregate_node_count = 0
            document_count = 0
            for registration in registrations:
                expected_objects = registration.expected_objects
                collected = await _async_collect_provider_stream(
                    registration,
                    expected_objects,
                    hass,
                    global_document_count=document_count,
                    aggregate_size=aggregate_size,
                    aggregate_node_count=aggregate_node_count,
                    deadline=deadline,
                )
                if type(collected) is not _CollectedProviderStream:
                    if collected is _COLLECTION_TIMED_OUT:
                        return _COLLECTION_TIMED_OUT
                    return _collection_failure_outcome(loop, deadline)
                document_count += collected.document_count
                aggregate_size += collected.canonical_size
                aggregate_node_count += collected.node_count
                inventories.append(collected.inventory)
                if loop.time() >= deadline:
                    return _COLLECTION_TIMED_OUT

            try:
                snapshot = _new_exact_reference_inventory_snapshot(
                    expected.digest,
                    tuple(inventories),
                )
            except Exception:
                return _collection_failure_outcome(loop, deadline)
            if loop.time() >= deadline:
                return _COLLECTION_TIMED_OUT
            return snapshot
    except TimeoutError:
        return _COLLECTION_TIMED_OUT


def _collection_failure_outcome(
    loop: asyncio.AbstractEventLoop,
    deadline: float,
) -> object:
    if loop.time() >= deadline:
        return _COLLECTION_TIMED_OUT
    return _COLLECTION_FAILED


async def _async_collect_provider_stream(
    registration: _SnapshotSourceRegistration,
    expected: ExpectedProviderObjects,
    hass: HomeAssistant,
    *,
    global_document_count: int,
    aggregate_size: int,
    aggregate_node_count: int,
    deadline: float,
) -> _CollectedProviderStream | object:
    loop = asyncio.get_running_loop()
    stream = await _async_open_registered_snapshot_stream(registration.reader, hass)
    if stream is _SOURCE_STREAM_FAILED:
        return _collection_failure_outcome(loop, deadline)
    stream = cast(AsyncIterator[ProviderDocumentSnapshot], stream)
    if loop.time() >= deadline:
        await _async_close_registered_snapshot_stream(stream)
        return _COLLECTION_TIMED_OUT

    documents: list[ProviderDocumentSnapshot] = []
    provider_size = 0
    provider_node_count = 0
    outcome: object | None = None
    cleanup_succeeded = True
    try:
        while True:
            document = await _async_next_registered_snapshot(stream)
            current_task = asyncio.current_task()
            if current_task is not None and current_task.cancelling():
                raise asyncio.CancelledError
            if loop.time() >= deadline:
                outcome = _COLLECTION_TIMED_OUT
                break
            if document is _SOURCE_STREAM_END:
                if len(documents) != expected.count:
                    outcome = _collection_failure_outcome(loop, deadline)
                break
            if document is _SOURCE_STREAM_FAILED:
                outcome = _collection_failure_outcome(loop, deadline)
                break

            index = len(documents)
            if (
                index >= expected.count
                or index >= _REFERENCE_SNAPSHOT_MAX_DOCUMENTS_PER_PROVIDER
                or global_document_count + index
                >= _REFERENCE_SNAPSHOT_MAX_DOCUMENTS
            ):
                outcome = _collection_failure_outcome(loop, deadline)
                break
            if type(document) is not ProviderDocumentSnapshot:
                outcome = _collection_failure_outcome(loop, deadline)
                break
            if (
                document.provider != registration.name
                or document.object_id != expected.object_keys[index]
                or document.writable is not False
            ):
                outcome = _collection_failure_outcome(loop, deadline)
                break

            estimated_size = document._canonical_document_size
            estimated_node_count = document._canonical_node_count
            if (
                type(estimated_size) is not int
                or estimated_size < 0
                or aggregate_size + provider_size + estimated_size
                > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_BYTES
            ):
                outcome = _collection_failure_outcome(loop, deadline)
                break
            if (
                type(estimated_node_count) is not int
                or estimated_node_count <= 0
                or aggregate_node_count
                + provider_node_count
                + estimated_node_count
                > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES
            ):
                outcome = _collection_failure_outcome(loop, deadline)
                break
            try:
                _fingerprint, document_size, node_count = (
                    _validate_snapshot_document(document)
                )
            except Exception:
                outcome = _collection_failure_outcome(loop, deadline)
                break
            if loop.time() >= deadline:
                outcome = _COLLECTION_TIMED_OUT
                break
            if (
                aggregate_size + provider_size + document_size
                > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_BYTES
            ):
                outcome = _collection_failure_outcome(loop, deadline)
                break
            if (
                aggregate_node_count + provider_node_count + node_count
                > _REFERENCE_SNAPSHOT_MAX_AGGREGATE_NODES
            ):
                outcome = _collection_failure_outcome(loop, deadline)
                break
            provider_size += document_size
            provider_node_count += node_count
            documents.append(document)
    finally:
        if _collector_task_is_cancelling():
            await _async_cleanup_registered_stream_during_cancellation(stream)
        else:
            cleanup_succeeded = await _async_close_registered_snapshot_stream(stream)

    if loop.time() >= deadline:
        return _COLLECTION_TIMED_OUT
    if not cleanup_succeeded:
        return _collection_failure_outcome(loop, deadline)
    if outcome is not None:
        return outcome
    try:
        inventory = ProviderDocumentInventory(
            registration.name,
            tuple(documents),
        )
    except Exception:
        return _collection_failure_outcome(loop, deadline)
    if loop.time() >= deadline:
        return _COLLECTION_TIMED_OUT
    if (
        inventory.object_keys != expected.object_keys
        or inventory._canonical_size != provider_size
        or inventory._canonical_node_count != provider_node_count
    ):
        return _collection_failure_outcome(loop, deadline)
    return _CollectedProviderStream(
        inventory,
        len(documents),
        provider_size,
        provider_node_count,
    )


async def _async_open_registered_snapshot_stream(
    reader: Callable[[HomeAssistant], AsyncIterator[ProviderDocumentSnapshot]],
    hass: HomeAssistant,
) -> AsyncIterator[ProviderDocumentSnapshot] | object:
    stream: Any = _CLEANUP_MISSING
    try:
        stream = reader(hass)
    except asyncio.CancelledError:
        if _collector_task_is_cancelling():
            raise
        return _SOURCE_STREAM_FAILED
    except BaseException:
        return _SOURCE_STREAM_FAILED

    try:
        iterator = aiter(stream)
    except asyncio.CancelledError:
        if _collector_task_is_cancelling():
            await _async_cleanup_registered_stream_during_cancellation(stream)
            raise
        await _async_close_registered_snapshot_stream(stream)
        return _SOURCE_STREAM_FAILED
    except BaseException:
        await _async_close_registered_snapshot_stream(stream)
        return _SOURCE_STREAM_FAILED
    if iterator is not stream:
        await _async_close_registered_snapshot_stream(iterator)
        await _async_close_registered_snapshot_stream(stream)
        return _SOURCE_STREAM_FAILED
    return iterator


async def _async_next_registered_snapshot(
    stream: AsyncIterator[ProviderDocumentSnapshot],
) -> ProviderDocumentSnapshot | object:
    try:
        return await anext(stream)
    except StopAsyncIteration:
        return _SOURCE_STREAM_END
    except asyncio.CancelledError:
        if _collector_task_is_cancelling():
            raise
        return _SOURCE_STREAM_FAILED
    except BaseException:
        return _SOURCE_STREAM_FAILED


async def _async_close_registered_snapshot_stream(
    stream: Any,
) -> bool:
    failed = False
    try:
        async_close = getattr(stream, "aclose", _CLEANUP_MISSING)
    except asyncio.CancelledError:
        if _collector_task_is_cancelling():
            raise
        async_close = _CLEANUP_MISSING
        failed = True
    except BaseException:
        async_close = _CLEANUP_MISSING
        failed = True

    if async_close is not _CLEANUP_MISSING:
        if not callable(async_close):
            failed = True
        else:
            try:
                await cast(Awaitable[Any], async_close())
            except asyncio.CancelledError:
                if _collector_task_is_cancelling():
                    raise
                failed = True
            except BaseException:
                failed = True
            else:
                return not failed

    try:
        close = getattr(stream, "close", _CLEANUP_MISSING)
    except asyncio.CancelledError:
        if _collector_task_is_cancelling():
            raise
        close = _CLEANUP_MISSING
        failed = True
    except BaseException:
        close = _CLEANUP_MISSING
        failed = True

    if close is _CLEANUP_MISSING:
        return not failed
    if not callable(close):
        return False
    try:
        close_result = close()
        if close_result is not None:
            await cast(Awaitable[Any], close_result)
    except asyncio.CancelledError:
        if _collector_task_is_cancelling():
            raise
        return False
    except BaseException:
        return False
    return not failed


async def _async_cleanup_registered_stream_during_cancellation(
    stream: AsyncIterator[ProviderDocumentSnapshot],
) -> None:
    try:
        async with asyncio.timeout(_CANCELLATION_CLEANUP_TIMEOUT_SECONDS):
            await _async_close_registered_snapshot_stream(stream)
    except BaseException:
        return


def _collector_task_is_cancelling() -> bool:
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


def _new_exact_reference_inventory_snapshot(
    expected_manifest_digest: str,
    inventories: tuple[ProviderDocumentInventory, ...],
) -> ExactReferenceInventorySnapshot:
    return ExactReferenceInventorySnapshot(
        expected_manifest_digest,
        inventories,
        _token=_EXACT_REFERENCE_INVENTORY_TOKEN,
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

    result = await _async_read_config_entry_reference_snapshot_safely(hass, policy)
    if type(result) is tuple:
        return result
    del hass, policy
    raise ConfigEntryReferenceSnapshotError(
        "Config-entry reference snapshot could not be read safely."
    )


async def _async_read_config_entry_reference_snapshot_safely(
    hass: HomeAssistant,
    policy: tuple[ConfigEntryReferenceObjectPolicy, ...],
) -> tuple[ProviderDocumentSnapshot, ...] | object:
    try:
        return await _async_read_config_entry_reference_snapshot_impl(hass, policy)
    except asyncio.CancelledError:
        raise
    except Exception:
        return _RAW_CONFIG_ENTRY_SNAPSHOT_FAILED


async def _async_read_config_entry_reference_snapshot_impl(
    hass: HomeAssistant,
    policy: tuple[ConfigEntryReferenceObjectPolicy, ...],
) -> tuple[ProviderDocumentSnapshot, ...]:
    if not _config_entry_reference_policy_is_valid(policy):
        del hass, policy
        raise ConfigEntryReferenceSnapshotError(
            "Config-entry reference policy is malformed."
        )
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


async def _async_iter_opaque_config_entry_snapshot(
    hass: HomeAssistant,
    policy: tuple[ConfigEntryReferenceObjectPolicy, ...],
) -> AsyncIterator[ProviderDocumentSnapshot]:
    prepared = await _async_prepare_opaque_config_entry_stream(hass, policy)
    if type(prepared) is not tuple:
        del hass, policy, prepared
        raise ConfigEntryReferenceSnapshotError(
            "Opaque config-entry reference snapshot could not be read safely."
        )
    for opaque_key, locator, snapshot in prepared:
        transformed = _transform_opaque_config_entry_snapshot(
            opaque_key,
            locator,
            snapshot,
        )
        if type(transformed) is not ProviderDocumentSnapshot:
            del hass, policy, prepared, opaque_key, locator, snapshot, transformed
            raise ConfigEntryReferenceSnapshotError(
                "Opaque config-entry reference snapshot could not be read safely."
            )
        yield transformed


async def _async_prepare_opaque_config_entry_stream(
    hass: HomeAssistant,
    policy: tuple[ConfigEntryReferenceObjectPolicy, ...],
) -> tuple[
    tuple[
        str,
        ConfigEntryReferenceObjectPolicy,
        ProviderDocumentSnapshot,
    ],
    ...,
] | object:
    try:
        raw_snapshots = await async_read_config_entry_reference_snapshot(
            hass,
            policy,
        )
        if len(raw_snapshots) != len(policy):
            return _CONFIG_ENTRY_SOURCE_FAILED
        prepared = []
        for locator, snapshot in zip(policy, raw_snapshots, strict=True):
            if (
                snapshot.provider != "config_entry"
                or snapshot.object_id != locator.entry_id
                or snapshot.writable is not False
            ):
                return _CONFIG_ENTRY_SOURCE_FAILED
            prepared.append(
                (
                    _config_entry_reference_opaque_key(
                        locator.domain,
                        locator.entry_id,
                    ),
                    locator,
                    snapshot,
                )
            )
        return tuple(sorted(prepared, key=lambda item: item[0]))
    except asyncio.CancelledError:
        raise
    except Exception:
        return _CONFIG_ENTRY_SOURCE_FAILED


def _transform_opaque_config_entry_snapshot(
    opaque_key: str,
    locator: ConfigEntryReferenceObjectPolicy,
    snapshot: ProviderDocumentSnapshot,
) -> ProviderDocumentSnapshot | object:
    try:
        opaque_snapshot = ProviderDocumentSnapshot(
            provider="config_entry",
            object_id=opaque_key,
            revision=snapshot.revision,
            payload=snapshot.as_reference_document().payload,
        )
        if (
            snapshot.object_id != locator.entry_id
            or opaque_snapshot.fingerprint != snapshot.fingerprint
        ):
            return _CONFIG_ENTRY_SOURCE_FAILED
        return opaque_snapshot
    except Exception:
        return _CONFIG_ENTRY_SOURCE_FAILED


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


def _prevalidate_snapshot_sources(
    expected: ExpectedObjectManifest,
    sources: tuple[ReadOnlyProviderSnapshotSource, ...],
    *,
    deadline: float,
) -> tuple[_SnapshotSourceRegistration, ...]:
    if type(expected) is not ExpectedObjectManifest:
        raise TypeError("Expected object manifest is malformed.")
    _validate_expected_snapshot_resources(expected)
    if asyncio.get_running_loop().time() >= deadline:
        raise _SnapshotDeadlineExceeded
    if type(sources) is not tuple or len(sources) != len(PROVIDER_NAMES):
        raise ExactReferenceInventorySnapshotError(
            "Snapshot sources must contain all five providers exactly once."
        )

    names: list[str] = []
    declarations: list[ExpectedProviderObjects] = []
    registrations: list[_SnapshotSourceRegistration] = []
    for source in sources:
        try:
            name = source.name
        except Exception:
            name = None
        if asyncio.get_running_loop().time() >= deadline:
            raise _SnapshotDeadlineExceeded
        try:
            declaration = source.expected_objects
        except Exception:
            declaration = None
        if asyncio.get_running_loop().time() >= deadline:
            raise _SnapshotDeadlineExceeded
        try:
            reader = source.async_read_snapshot
        except Exception:
            reader = None
        if asyncio.get_running_loop().time() >= deadline:
            raise _SnapshotDeadlineExceeded
        if name is None or declaration is None or reader is None:
            raise ExactReferenceInventorySnapshotError(
                "Snapshot source metadata is malformed."
            )
        if type(name) is not str or name not in TRUE_FAMILY_PROVIDER_MANIFEST:
            raise ExactReferenceInventorySnapshotError(
                "Snapshot source has a non-canonical provider name."
            )
        if type(declaration) is not ExpectedProviderObjects:
            raise ExactReferenceInventorySnapshotError(
                "Snapshot source expected objects are malformed."
            )
        if declaration.provider != name or not callable(reader):
            raise ExactReferenceInventorySnapshotError(
                "Snapshot source metadata is inconsistent."
            )
        _validate_expected_provider_resources(declaration)
        names.append(name)
        declarations.append(declaration)
        registrations.append(
            _SnapshotSourceRegistration(
                name,
                declaration,
                reader,
            )
        )

    if tuple(names) != PROVIDER_NAMES:
        raise ExactReferenceInventorySnapshotError(
            "Snapshot sources must occur once in canonical provider order."
        )
    if tuple(declarations) != expected.providers:
        raise ExactReferenceInventorySnapshotError(
            "Snapshot source declarations do not match the expected manifest."
        )
    return tuple(registrations)


def _validate_expected_snapshot_resources(expected: ExpectedObjectManifest) -> None:
    _bounded_json_string_size(
        expected.revision,
        _REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES,
    )
    total = 0
    for item in expected._typed_providers():
        _validate_expected_provider_resources(item)
        total += item.count
    if total > _REFERENCE_SNAPSHOT_MAX_DOCUMENTS:
        raise ExactReferenceInventorySnapshotError(
            "Expected snapshot exceeds its aggregate document limit."
        )


def _validate_expected_provider_resources(expected: ExpectedProviderObjects) -> None:
    _validate_object_keys(expected.object_keys)
    if expected.count > _REFERENCE_SNAPSHOT_MAX_DOCUMENTS_PER_PROVIDER:
        raise ExactReferenceInventorySnapshotError(
            "Expected provider snapshot exceeds its document limit."
        )
    for object_key in expected.object_keys:
        _validate_snapshot_object_key(object_key)


def _validate_snapshot_object_key(object_key: str) -> None:
    if type(object_key) is not str or len(object_key) > (
        _REFERENCE_SNAPSHOT_MAX_OBJECT_KEY_BYTES
    ):
        raise ExactReferenceInventorySnapshotError(
            "Snapshot object key exceeds its size limit."
        )
    _validate_nonempty_string(object_key, "Snapshot object key")
    if len(object_key.encode("utf-8")) > _REFERENCE_SNAPSHOT_MAX_OBJECT_KEY_BYTES:
        raise ExactReferenceInventorySnapshotError(
            "Snapshot object key exceeds its size limit."
        )


class _ProjectedPayloadError(ValueError):
    """Internal marker for a bounded canonical-payload rejection."""


class _CanonicalJsonHasher:
    """Incrementally hash canonical ensure-ASCII JSON with a hard byte limit."""

    __slots__ = ("_count", "_hasher", "_limit")

    def __init__(self, limit: int) -> None:
        self._count = 0
        self._hasher = hashlib.sha256()
        self._limit = limit

    def _write_bytes(self, value: bytes | bytearray) -> None:
        if self._count + len(value) > self._limit:
            raise _ProjectedPayloadError("Canonical payload exceeds its byte limit.")
        self._hasher.update(value)
        self._count += len(value)

    def write_ascii(self, value: str) -> None:
        self._write_bytes(value.encode("ascii"))

    def write_string(self, value: str) -> None:
        self._write_bytes(b'"')
        chunk = bytearray()
        short_escapes = {
            8: b"\\b",
            9: b"\\t",
            10: b"\\n",
            12: b"\\f",
            13: b"\\r",
        }
        for character in value:
            codepoint = ord(character)
            if character == '"':
                chunk.extend(b'\\"')
            elif character == "\\":
                chunk.extend(b"\\\\")
            elif codepoint in short_escapes:
                chunk.extend(short_escapes[codepoint])
            elif 0x20 <= codepoint <= 0x7E:
                chunk.append(codepoint)
            elif codepoint <= 0xFFFF:
                chunk.extend(f"\\u{codepoint:04x}".encode("ascii"))
            else:
                adjusted = codepoint - 0x10000
                high = 0xD800 + (adjusted >> 10)
                low = 0xDC00 + (adjusted & 0x3FF)
                chunk.extend(f"\\u{high:04x}\\u{low:04x}".encode("ascii"))
            if len(chunk) >= _REFERENCE_SNAPSHOT_JSON_CHUNK_BYTES:
                self._write_bytes(chunk)
                chunk.clear()
        if chunk:
            self._write_bytes(chunk)
        self._write_bytes(b'"')

    @property
    def count(self) -> int:
        return self._count

    @property
    def hexdigest(self) -> str:
        return self._hasher.hexdigest()


def _bounded_json_string_size(value: str, remaining: int) -> int:
    if type(value) is not str or remaining < 2:
        raise _ProjectedPayloadError("Canonical JSON string is malformed.")
    size = 2
    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\"} or codepoint in {8, 9, 10, 12, 13}:
            increment = 2
        elif 0x20 <= codepoint <= 0x7E:
            increment = 1
        elif codepoint <= 0xFFFF:
            increment = 6
        else:
            increment = 12
        size += increment
        if size > remaining:
            raise _ProjectedPayloadError(
                "Canonical JSON string exceeds its byte limit."
            )
    return size


def _canonical_scalar_text(value: Any, remaining: int) -> str:
    if type(value) is int:
        if value.bit_length() > _REFERENCE_SNAPSHOT_MAX_INTEGER_BITS:
            raise _ProjectedPayloadError("Canonical integer exceeds its size limit.")
        rendered = str(value)
    elif type(value) is float:
        if not math.isfinite(value):
            raise _ProjectedPayloadError("Canonical float must be finite.")
        rendered = json.dumps(value, allow_nan=False, separators=(",", ":"))
    else:
        raise _ProjectedPayloadError("Canonical scalar type is unsupported.")
    if len(rendered) > remaining:
        raise _ProjectedPayloadError("Canonical scalar exceeds its byte limit.")
    return rendered


def _validate_and_copy_projected_payload(
    payload: Any,
    *,
    max_bytes: int,
) -> tuple[dict[str, Any] | list[Any], int, int]:
    if type(payload) not in (dict, list):
        raise _ProjectedPayloadError(
            "Projected payload root must be a built-in mapping or list."
        )
    if max_bytes < 0:
        raise _ProjectedPayloadError("Projected payload has no byte budget.")

    root: list[Any] = [None]
    stack: list[tuple[Any, int, dict[str, Any] | list[Any], str | int]] = [
        (payload, 0, root, 0)
    ]
    seen_containers: set[int] = set()
    nodes = 0
    size = 0

    def add_size(amount: int) -> None:
        nonlocal size
        size += amount
        if size > max_bytes:
            raise _ProjectedPayloadError(
                "Projected payload exceeds its canonical byte limit."
            )

    def attach(
        parent: dict[str, Any] | list[Any],
        slot: str | int,
        value: Any,
    ) -> None:
        parent[slot] = value  # type: ignore[index]

    while stack:
        value, depth, parent, slot = stack.pop()
        if depth > _REFERENCE_SNAPSHOT_MAX_PAYLOAD_DEPTH:
            raise _ProjectedPayloadError(
                "Projected payload exceeds its depth limit."
            )
        nodes += 1
        if nodes + len(stack) > _REFERENCE_SNAPSHOT_MAX_PAYLOAD_NODES:
            raise _ProjectedPayloadError(
                "Projected payload exceeds its node limit."
            )

        value_type = type(value)
        if value_type is dict:
            identity = id(value)
            if identity in seen_containers:
                raise _ProjectedPayloadError(
                    "Projected payload contains a container alias."
                )
            seen_containers.add(identity)
            item_count = len(value)
            if (
                nodes + len(stack) + (item_count * 2)
                > _REFERENCE_SNAPSHOT_MAX_PAYLOAD_NODES
            ):
                raise _ProjectedPayloadError(
                    "Projected payload exceeds its node limit."
                )
            add_size(2 + item_count + max(0, item_count - 1))
            nodes += item_count
            copied: dict[str, Any] = {}
            attach(parent, slot, copied)
            items: list[tuple[str, Any]] = []
            for key, item in value.items():
                if type(key) is not str:
                    raise _ProjectedPayloadError(
                        "Projected payload mapping key is not canonical."
                    )
                add_size(_bounded_json_string_size(key, max_bytes - size))
                items.append((key, item))
            items.sort(key=lambda item: item[0])
            for key, item in reversed(items):
                stack.append((item, depth + 1, copied, key))
            continue

        if value_type is list:
            identity = id(value)
            if identity in seen_containers:
                raise _ProjectedPayloadError(
                    "Projected payload contains a container alias."
                )
            seen_containers.add(identity)
            item_count = len(value)
            if (
                nodes + len(stack) + item_count
                > _REFERENCE_SNAPSHOT_MAX_PAYLOAD_NODES
            ):
                raise _ProjectedPayloadError(
                    "Projected payload exceeds its node limit."
                )
            add_size(2 + max(0, item_count - 1))
            copied_list: list[Any] = [None] * item_count
            attach(parent, slot, copied_list)
            for index in range(item_count - 1, -1, -1):
                stack.append((value[index], depth + 1, copied_list, index))
            continue

        if value_type is str:
            add_size(_bounded_json_string_size(value, max_bytes - size))
        elif value is None:
            add_size(4)
        elif value_type is bool:
            add_size(4 if value else 5)
        elif value_type in (int, float):
            add_size(len(_canonical_scalar_text(value, max_bytes - size)))
        else:
            raise _ProjectedPayloadError(
                "Projected payload contains a noncanonical value."
            )
        attach(parent, slot, value)

    canonical = root[0]
    if type(canonical) not in (dict, list):
        raise _ProjectedPayloadError("Projected payload copy is malformed.")
    return canonical, size, nodes


def _preflight_frozen_projected_payload(
    payload: Any,
    *,
    max_bytes: int,
) -> tuple[int, int]:
    if type(payload) not in (MappingProxyType, tuple):
        raise _ProjectedPayloadError(
            "Frozen projected payload root is malformed."
        )
    if max_bytes < 0:
        raise _ProjectedPayloadError("Projected payload has no byte budget.")

    stack: list[tuple[Any, int]] = [(payload, 0)]
    nodes = 0
    size = 0

    def add_size(amount: int) -> None:
        nonlocal size
        size += amount
        if size > max_bytes:
            raise _ProjectedPayloadError(
                "Projected payload exceeds its canonical byte limit."
            )

    while stack:
        value, depth = stack.pop()
        if depth > _REFERENCE_SNAPSHOT_MAX_PAYLOAD_DEPTH:
            raise _ProjectedPayloadError(
                "Projected payload exceeds its depth limit."
            )
        nodes += 1
        if nodes + len(stack) > _REFERENCE_SNAPSHOT_MAX_PAYLOAD_NODES:
            raise _ProjectedPayloadError(
                "Projected payload exceeds its node limit."
            )

        value_type = type(value)
        if value_type is MappingProxyType:
            item_count = len(value)
            if (
                nodes + len(stack) + (item_count * 2)
                > _REFERENCE_SNAPSHOT_MAX_PAYLOAD_NODES
            ):
                raise _ProjectedPayloadError(
                    "Projected payload exceeds its node limit."
                )
            add_size(2 + item_count + max(0, item_count - 1))
            nodes += item_count
            for key, item in value.items():
                if type(key) is not str:
                    raise _ProjectedPayloadError(
                        "Projected payload mapping key is not canonical."
                    )
                add_size(_bounded_json_string_size(key, max_bytes - size))
                stack.append((item, depth + 1))
            continue

        if value_type is tuple:
            item_count = len(value)
            if (
                nodes + len(stack) + item_count
                > _REFERENCE_SNAPSHOT_MAX_PAYLOAD_NODES
            ):
                raise _ProjectedPayloadError(
                    "Projected payload exceeds its node limit."
                )
            add_size(2 + max(0, item_count - 1))
            stack.extend((item, depth + 1) for item in value)
            continue

        if value_type is str:
            add_size(_bounded_json_string_size(value, max_bytes - size))
        elif value is None:
            add_size(4)
        elif value_type is bool:
            add_size(4 if value else 5)
        elif value_type in (int, float):
            add_size(len(_canonical_scalar_text(value, max_bytes - size)))
        else:
            raise _ProjectedPayloadError(
                "Projected payload contains a noncanonical value."
            )

    return size, nodes


def _canonical_revision_json_size(revision: Revision, remaining: int) -> int:
    kind = "integer" if type(revision) is int else "string"
    size = len('{"kind":')
    size += _bounded_json_string_size(kind, remaining - size)
    size += len(',"value":')
    if type(revision) is int:
        size += len(_canonical_scalar_text(revision, remaining - size - 1))
    elif type(revision) is str:
        size += _bounded_json_string_size(revision, remaining - size - 1)
    else:
        raise _ProjectedPayloadError("Provider document revision is malformed.")
    size += 1
    if size > remaining:
        raise _ProjectedPayloadError("Provider document revision is too large.")
    return size


def _canonical_document_overhead(
    provider: str,
    object_id: str,
    revision: Revision,
) -> int:
    _validate_provider(provider)
    _validate_snapshot_object_key(object_id)
    if type(revision) not in (str, int) or type(revision) is bool:
        raise _ProjectedPayloadError("Provider document revision is malformed.")
    if (
        type(revision) is str
        and len(revision) > _REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES
    ):
        raise _ProjectedPayloadError("Provider document revision is too large.")
    _validate_revision(revision, "Provider document revision")

    limit = _REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES
    size = len('{"object_key":')
    size += _bounded_json_string_size(object_id, limit - size)
    size += len(',"payload":')
    size += len(',"provider":')
    size += _bounded_json_string_size(provider, limit - size)
    size += len(',"revision":')
    size += _canonical_revision_json_size(revision, limit - size - 1)
    size += 1
    if size > limit:
        raise _ProjectedPayloadError("Provider document metadata is too large.")
    return size


def _stream_canonical_json_digest(value: Any, max_bytes: int) -> tuple[str, int]:
    writer = _CanonicalJsonHasher(max_bytes)

    def emit(item: Any) -> None:
        item_type = type(item)
        if item_type in (dict, MappingProxyType):
            writer.write_ascii("{")
            for index, key in enumerate(sorted(item)):
                if index:
                    writer.write_ascii(",")
                writer.write_string(key)
                writer.write_ascii(":")
                emit(item[key])
            writer.write_ascii("}")
        elif item_type in (list, tuple):
            writer.write_ascii("[")
            for index, child in enumerate(item):
                if index:
                    writer.write_ascii(",")
                emit(child)
            writer.write_ascii("]")
        elif item_type is str:
            writer.write_string(item)
        elif item is None:
            writer.write_ascii("null")
        elif item_type is bool:
            writer.write_ascii("true" if item else "false")
        elif item_type in (int, float):
            writer.write_ascii(_canonical_scalar_text(item, max_bytes - writer.count))
        else:
            raise _ProjectedPayloadError(
                "Projected payload contains a noncanonical value."
            )

    emit(value)
    return writer.hexdigest, writer.count


def _prepare_provider_document_snapshot(
    provider: str,
    object_id: str,
    revision: Revision,
    payload: Any,
) -> _PreparedProviderDocument | object:
    try:
        overhead = _canonical_document_overhead(provider, object_id, revision)
        canonical_payload, payload_size, node_count = (
            _validate_and_copy_projected_payload(
                payload,
                max_bytes=_REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES - overhead,
            )
        )
        fingerprint, streamed_size = _stream_canonical_json_digest(
            canonical_payload,
            payload_size,
        )
        if streamed_size != payload_size:
            return _PREPARED_PAYLOAD_FAILED
        return _PreparedProviderDocument(
            _freeze_projected_payload(canonical_payload),
            fingerprint,
            payload_size,
            overhead + payload_size,
            node_count,
        )
    except Exception:
        return _PREPARED_PAYLOAD_FAILED


def _recompute_snapshot_document(
    document: ProviderDocumentSnapshot,
) -> tuple[str, int, int] | object:
    try:
        overhead = _canonical_document_overhead(
            document.provider,
            document.object_id,
            document.revision,
        )
        payload_size, node_count = _preflight_frozen_projected_payload(
            document.payload,
            max_bytes=_REFERENCE_SNAPSHOT_MAX_DOCUMENT_BYTES - overhead,
        )
        fingerprint, streamed_size = _stream_canonical_json_digest(
            document.payload,
            payload_size,
        )
        document_size = overhead + payload_size
        if (
            streamed_size != payload_size
            or document._canonical_payload_size != payload_size
            or document._canonical_document_size != document_size
            or document._canonical_node_count != node_count
            or document.fingerprint != fingerprint
        ):
            return _RECOMPUTED_DOCUMENT_FAILED
        return fingerprint, document_size, node_count
    except Exception:
        return _RECOMPUTED_DOCUMENT_FAILED


def _validate_snapshot_document(
    document: ProviderDocumentSnapshot,
) -> tuple[str, int, int]:
    recomputed = _recompute_snapshot_document(document)
    if type(recomputed) is not tuple:
        del document
        raise ExactReferenceInventorySnapshotError(
            "Provider snapshot document is not canonical."
        )
    return recomputed


def _config_entry_reference_policy_is_valid(
    policy: tuple[ConfigEntryReferenceObjectPolicy, ...],
) -> bool:
    try:
        _validate_config_entry_reference_policy(policy)
    except Exception:
        return False
    return True


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


def _copy_projected_payload(payload: Any) -> dict[str, Any] | list[Any]:
    if type(payload) not in (dict, list, MappingProxyType, tuple):
        raise ConfigEntryReferenceSnapshotError(
            "Projected provider document payload must be a mapping or list."
        )

    def copy_value(value: Any) -> Any:
        if type(value) in (dict, MappingProxyType):
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


def _config_entry_reference_opaque_key(domain: str, entry_id: str) -> str:
    return _CONFIG_ENTRY_OPAQUE_KEY_PREFIX + _digest_json(
        {
            "purpose": "true-family-config-entry-reference-object-key-v1",
            "provider": "config_entry",
            "domain": domain,
            "entry_id": entry_id,
        }
    )


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
