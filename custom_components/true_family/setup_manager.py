"""Sanitized component-level orchestration for offline setup wiring.

The manager deliberately owns no production write bridge. Bootstrap is the
only built-in mutation and is permitted only while the sole True Family config
entry is unloaded. Reference migration execution remains unavailable until a
server-side executor and five production-ready bridge proofs are injected.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import re
import secrets
from types import MappingProxyType
from typing import Any, Protocol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import Context, HomeAssistant

from .bootstrap import BootstrapError, CANONICAL_ROOM_IDS
from .bootstrap_ha import (
    HomeAssistantBootstrapCoordinator,
    HomeAssistantBootstrapPlan,
)
from .const import CONF_BOOTSTRAP, CONF_ROOMS, DOMAIN
from .models import RoomSlot, default_rooms, rooms_from_dict
from .reference_migration import (
    MigrationPlan,
    MigrationResult,
    MigrationState,
    ReferenceMigrationError,
    Revision,
)
from .reference_migration_ha import (
    ReferencePlanExecutionBinding,
    ReferenceJournalCodecError,
    ReferenceJournalDurabilityError,
    ReferenceJournalNotProvisionedError,
    ReferenceJournalThreadError,
    decode_migration_plan,
    encode_migration_plan,
)
from .reference_providers_ha import (
    PROVIDER_NAMES,
    BridgeRecoveryCapability,
    BridgeReadiness,
    ExpectedObjectManifest,
    ExternalAttestationVerifier,
    HomeAssistantInventoryScope,
    ProductionReadiness,
    ProviderHostBridge,
    ProviderInventory,
    ProviderPublicSummary,
    PublicProviderStatus,
    SignedExternalWriterAttestation,
    assess_production_readiness,
    async_probe_home_assistant_inventory,
)


_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_RECOVERY_CAPABILITY_METHODS = MappingProxyType(
    {
        BridgeRecoveryCapability.ACQUISITION_LEDGER: (
            "async_reconcile_fence_acquisition"
        ),
        BridgeRecoveryCapability.OBJECT_LEDGER: "async_reconcile_operation",
        BridgeRecoveryCapability.RELEASE_LEDGER: "async_reconcile_fence_release",
        BridgeRecoveryCapability.OBJECT_OBSERVATION: "async_observe_object",
        BridgeRecoveryCapability.FENCE_STATE: "async_fence_authority_snapshot",
        BridgeRecoveryCapability.EPOCH_RESERVATION: (
            "async_reserve_next_fence_epoch"
        ),
        BridgeRecoveryCapability.FENCE_ACQUISITION: "async_acquire_writer_fence",
        BridgeRecoveryCapability.CONDITIONAL_WRITE: "async_compare_and_swap",
        BridgeRecoveryCapability.ROLLBACK: "async_rollback",
        BridgeRecoveryCapability.FENCE_RELEASE: "async_release_writer_fence",
    }
)


_ERROR_MESSAGES = MappingProxyType(
    {
        "busy": "Another True Family setup operation is in progress.",
        "entry_not_singleton": "True Family requires exactly one config entry.",
        "entry_not_unloaded": "True Family must be unloaded for bootstrap.",
        "bootstrap_already_complete": "True Family bootstrap is already complete.",
        "bootstrap_invalid": "The bootstrap selection could not be verified.",
        "bootstrap_commit_failed": "The bootstrap plan could not be committed.",
        "plan_unknown": "The setup plan is unknown or expired.",
        "room_unknown": "The selected room is unavailable.",
        "migration_executor_missing": "Reference migration is not configured.",
        "migration_requires_load": "True Family must be loaded for migration.",
        "migration_bootstrap_required": "True Family bootstrap must be complete.",
        "migration_revision_stale": "The room changed before migration planning.",
        "migration_recovery_required": "Reference migration recovery is required.",
        "migration_not_ready": "Reference migration is not ready.",
        "migration_plan_failed": "The reference migration plan could not be created.",
        "migration_commit_failed": "The reference migration plan could not be committed.",
        "migration_recovery_failed": "The reference migration could not be recovered.",
    }
)

_MIGRATION_BACKEND_ERRORS = (
    ReferenceMigrationError,
    ReferenceJournalCodecError,
    ReferenceJournalDurabilityError,
    ReferenceJournalNotProvisionedError,
    ReferenceJournalThreadError,
)


class SetupManagerError(RuntimeError):
    """One fixed public setup error with no backend exception detail."""

    def __init__(self, code: str) -> None:
        try:
            message = _ERROR_MESSAGES[code]
        except KeyError as err:
            raise ValueError("Unknown setup-manager error code.") from err
        self.code = code
        self.message = message
        super().__init__(message)

    def as_dict(self) -> dict[str, str]:
        """Return the fixed WebSocket-safe error shape."""

        return {"code": self.code, "message": self.message}


@dataclass(frozen=True, slots=True)
class ProviderExecutionBinding:
    """Immutable identity and revisions for one execution-scope bridge."""

    provider: str
    bridge_id: str
    readiness_revision: Revision
    inventory_revision: Revision

    def __post_init__(self) -> None:
        _validate_provider_name(self.provider)
        _validate_opaque_id(self.bridge_id, "Bridge ID")
        _validate_revision(self.readiness_revision, "Readiness revision")
        _validate_revision(self.inventory_revision, "Inventory revision")


@dataclass(frozen=True, slots=True)
class TransactionRecorderCoverage:
    """Opaque durable recorder identity with exact provider coverage."""

    recorder_id: str
    journal_id: str
    providers: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_opaque_id(self.recorder_id, "Transaction recorder ID")
        _validate_opaque_id(self.journal_id, "Transaction journal ID")
        if self.providers != PROVIDER_NAMES:
            raise ValueError(
                "Production transaction recorder coverage must include all providers."
            )


@dataclass(frozen=True, slots=True)
class MigrationExecutionScope:
    """Immutable production scope captured before any migration is issued."""

    expected_manifest_digest: str
    providers: tuple[ProviderExecutionBinding, ...]
    transaction_recorder: TransactionRecorderCoverage

    def __post_init__(self) -> None:
        _validate_digest(self.expected_manifest_digest, "Execution manifest digest")
        if type(self.providers) is not tuple or any(
            not isinstance(item, ProviderExecutionBinding) for item in self.providers
        ):
            raise TypeError("Execution provider bindings must be an immutable tuple.")
        if tuple(item.provider for item in self.providers) != PROVIDER_NAMES:
            raise ValueError(
                "Execution scope must bind every provider once in canonical order."
            )
        bridge_ids = tuple(item.bridge_id for item in self.providers)
        if len(set(bridge_ids)) != len(bridge_ids):
            raise ValueError("Execution scope bridge IDs must be unique.")
        if not isinstance(self.transaction_recorder, TransactionRecorderCoverage):
            raise TypeError("Execution scope requires transaction recorder coverage.")

    def for_provider(self, provider: str) -> ProviderExecutionBinding:
        """Return the immutable binding for one canonical provider."""

        _validate_provider_name(provider)
        return self.providers[PROVIDER_NAMES.index(provider)]

    @property
    def digest(self) -> str:
        """Return a domain-separated digest of the complete execution scope."""

        return _digest_json(
            {
                "domain": "true-family/migration-execution-scope/v1",
                "expected_manifest_digest": self.expected_manifest_digest,
                "providers": [
                    {
                        "provider": item.provider,
                        "bridge_id": item.bridge_id,
                        "readiness_revision": _canonical_revision(
                            item.readiness_revision
                        ),
                        "inventory_revision": _canonical_revision(
                            item.inventory_revision
                        ),
                    }
                    for item in self.providers
                ],
                "transaction_recorder": {
                    "recorder_id": self.transaction_recorder.recorder_id,
                    "journal_id": self.transaction_recorder.journal_id,
                    "providers": list(self.transaction_recorder.providers),
                },
            }
        )


@dataclass(frozen=True, slots=True)
class MigrationDurableOutcome:
    """Exact terminal Store evidence for one bound migration plan."""

    plan_id: str
    plan_digest: str
    execution_binding: ReferencePlanExecutionBinding = field(repr=False)
    state: MigrationState
    result: MigrationResult | None = field(repr=False)

    def __post_init__(self) -> None:
        _validate_opaque_id(self.plan_id, "Durable outcome plan ID")
        _validate_digest(self.plan_digest, "Durable outcome plan digest")
        if type(self.execution_binding) is not ReferencePlanExecutionBinding:
            raise TypeError("Durable outcome requires an exact execution binding.")
        self.execution_binding.__post_init__()
        if type(self.state) is not MigrationState or self.state not in {
            MigrationState.COMPLETE,
            MigrationState.FAILED,
        }:
            raise ValueError("Durable outcome must be complete or restored failure.")
        if self.state is MigrationState.FAILED:
            if self.result is not None:
                raise ValueError("A restored failure cannot contain a migration result.")
            return
        if type(self.result) is not MigrationResult:
            raise TypeError("A complete durable outcome requires a migration result.")
        if (
            self.result.plan_id != self.plan_id
            or self.result.digest != self.plan_digest
            or self.result.state is not MigrationState.COMPLETE
            or isinstance(self.result.changed_documents, bool)
            or not isinstance(self.result.changed_documents, int)
            or self.result.changed_documents < 0
            or type(self.result.exact_replacements) is not int
            or self.result.exact_replacements < 0
            or self.result.idempotent is not False
        ):
            raise ValueError("The complete durable outcome result is malformed.")


@dataclass(frozen=True, slots=True)
class ProviderRecoveryReadiness:
    """Journal-selected capabilities for one exact recovery bridge identity."""

    provider: str
    journal_bridge_id: str
    required_capabilities: tuple[BridgeRecoveryCapability, ...]
    available_capabilities: tuple[BridgeRecoveryCapability, ...]

    def __post_init__(self) -> None:
        _validate_provider_name(self.provider)
        _validate_opaque_id(self.journal_bridge_id, "Journal bridge ID")
        for values, label in (
            (self.required_capabilities, "Required recovery capabilities"),
            (self.available_capabilities, "Available recovery capabilities"),
        ):
            if type(values) is not tuple or any(
                not isinstance(item, BridgeRecoveryCapability) for item in values
            ):
                raise TypeError(f"{label} must be an immutable capability tuple.")
            if values != tuple(sorted(set(values), key=lambda item: item.value)):
                raise ValueError(f"{label} must be unique and canonical.")
        if not self.required_capabilities:
            raise ValueError("A listed recovery provider must have required capabilities.")

    @property
    def ready(self) -> bool:
        """Return whether every journal-selected capability is available."""

        return set(self.required_capabilities).issubset(self.available_capabilities)


@dataclass(frozen=True, slots=True)
class MigrationRecoveryReadiness:
    """Recovery-only evidence bound to one incomplete journal plan and scope."""

    plan_id: str
    execution_scope_digest: str
    recorder_id: str
    journal_id: str
    journal_readable: bool
    providers: tuple[ProviderRecoveryReadiness, ...]

    def __post_init__(self) -> None:
        _validate_opaque_id(self.plan_id, "Recovery plan ID")
        _validate_digest(self.execution_scope_digest, "Recovery execution scope digest")
        _validate_opaque_id(self.recorder_id, "Recovery recorder ID")
        _validate_opaque_id(self.journal_id, "Recovery journal ID")
        if type(self.journal_readable) is not bool:
            raise TypeError("Recovery journal readability must be a boolean.")
        if type(self.providers) is not tuple or any(
            not isinstance(item, ProviderRecoveryReadiness) for item in self.providers
        ):
            raise TypeError("Recovery providers must be an immutable tuple.")
        provider_names = tuple(item.provider for item in self.providers)
        if provider_names != tuple(
            provider for provider in PROVIDER_NAMES if provider in provider_names
        ) or len(provider_names) != len(set(provider_names)):
            raise ValueError("Recovery providers must be unique and canonical.")

    @property
    def ready(self) -> bool:
        """Return whether the selected journal and exact required bridges are ready."""

        return self.journal_readable and all(item.ready for item in self.providers)


class MigrationExecutor(Protocol):
    """Transaction-recorded production boundary around future migration writes.

    The direct-write ``ReferenceMigrationCoordinator`` remains an offline and
    in-memory core only. It is not a production executor at this boundary.
    """

    @property
    def bridge_registry(self) -> Mapping[str, ProviderHostBridge]:
        """Return the currently available exact bridge objects."""

        ...

    @property
    def execution_scope(self) -> MigrationExecutionScope:
        """Return one immutable manifest, revision, and recorder-bound scope."""

        ...

    async def async_plan(self, room_id: str, /) -> MigrationPlan:
        """Return one opaque internal plan for authoritative room state."""

        ...

    async def async_execution_binding(
        self,
        plan_id: str,
        /,
    ) -> ReferencePlanExecutionBinding | None:
        """Return the exact Store-bound execution identity for an active plan."""

        ...

    async def async_recovery_plan(self, plan_id: str, /) -> MigrationPlan:
        """Return the exact durable active plan used for recovery validation."""

        ...

    async def async_terminal_outcome(
        self,
        plan_id: str,
        /,
    ) -> MigrationDurableOutcome:
        """Return exact terminal Store evidence; absence is never an outcome."""

        ...

    async def async_commit(
        self,
        plan: MigrationPlan,
        context: Context,
        /,
    ) -> MigrationResult:
        """Commit with immediate authority revalidation around provider writes."""

        ...

    async def async_recover(
        self,
        plan_id: str,
        context: Context,
        /,
    ) -> MigrationResult | None:
        """Recover one internal journal plan selected by a public token."""

        ...

    async def async_incomplete_plan_ids(self) -> tuple[str, ...]:
        """Return internal incomplete journal plan IDs for tokenization."""

        ...

    async def async_recovery_readiness(
        self,
        plan_id: str,
        /,
    ) -> MigrationRecoveryReadiness:
        """Read exact journal-selected bridge needs without normal attestations."""

        ...


@dataclass(frozen=True, slots=True)
class _ReadinessEvaluation:
    public: ProductionReadiness
    bridges: tuple[BridgeReadiness, ...]
    execution_scope_matches: bool


class SetupManager:
    """Serialize setup operations and expose only allowlisted public data."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        expected_manifest: ExpectedObjectManifest,
        bridge_registry: Mapping[str, ProviderHostBridge] | None = None,
        inventory_scope: HomeAssistantInventoryScope | None = None,
        external_attestation: SignedExternalWriterAttestation | None = None,
        external_verifier: ExternalAttestationVerifier | None = None,
        migration_executor: MigrationExecutor | None = None,
    ) -> None:
        if not isinstance(expected_manifest, ExpectedObjectManifest):
            raise TypeError("A server-owned expected object manifest is required.")
        if inventory_scope is not None and not isinstance(
            inventory_scope, HomeAssistantInventoryScope
        ):
            raise TypeError("The inventory scope is malformed.")
        if (
            inventory_scope is not None
            and inventory_scope.expected_manifest_digest != expected_manifest.digest
        ):
            raise ValueError("The inventory scope is not bound to the manifest.")
        bridges = dict(bridge_registry or {})
        if not set(bridges).issubset(PROVIDER_NAMES):
            raise ValueError("The bridge registry contains an unknown provider.")
        for provider, bridge in bridges.items():
            if (
                getattr(bridge, "name", None) != provider
                or type(getattr(bridge, "bridge_id", None)) is not str
                or not callable(getattr(bridge, "async_readiness", None))
            ):
                raise TypeError("The bridge readiness registry is malformed.")
            _validate_opaque_id(bridge.bridge_id, "Bridge ID")

        self._hass = hass
        self._expected_manifest = expected_manifest
        self._bridges = MappingProxyType(bridges)
        self._inventory_scope = inventory_scope
        self._external_attestation = external_attestation
        self._external_verifier = external_verifier
        self._migration_executor = migration_executor
        self._execution_scope: MigrationExecutionScope | None = None
        self._executor_bridges: Mapping[str, ProviderHostBridge] = MappingProxyType(
            {}
        )
        if migration_executor is not None:
            required_executor_methods = (
                "async_plan",
                "async_execution_binding",
                "async_recovery_plan",
                "async_terminal_outcome",
                "async_commit",
                "async_recover",
                "async_incomplete_plan_ids",
                "async_recovery_readiness",
            )
            if any(
                not callable(getattr(migration_executor, name, None))
                for name in required_executor_methods
            ):
                raise TypeError(
                    "The migration executor contract is incomplete."
                )
            executor_bridges = getattr(migration_executor, "bridge_registry", None)
            if not isinstance(executor_bridges, Mapping) or set(
                executor_bridges
            ) != set(bridges) or any(
                executor_bridges[provider] is not bridge
                for provider, bridge in bridges.items()
            ):
                raise TypeError(
                    "The migration executor is not bound to the readiness bridges."
                )
            execution_scope = getattr(migration_executor, "execution_scope", None)
            if not isinstance(execution_scope, MigrationExecutionScope):
                raise TypeError(
                    "A migration executor requires an immutable execution scope."
                )
            if execution_scope.expected_manifest_digest != expected_manifest.digest:
                raise TypeError(
                    "The migration executor scope is not bound to the manifest."
                )
            if any(
                execution_scope.for_provider(provider).bridge_id != bridge.bridge_id
                for provider, bridge in bridges.items()
            ):
                raise TypeError(
                    "The migration executor scope changed an active bridge identity."
                )
            self._execution_scope = execution_scope
            self._executor_bridges = MappingProxyType(dict(executor_bridges))
        self._lock = asyncio.Lock()

        self._bootstrap_token: str | None = None
        self._bootstrap_plan: HomeAssistantBootstrapPlan | None = None
        self._migration_token: str | None = None
        self._migration_plan: MigrationPlan | None = None
        self._migration_room: dict[str, str | int] | None = None
        self._migration_runtime: object | None = None
        self._migration_scope_digest: str | None = None
        self._recovery_plan_ids: dict[str, str] = {}
        self._recovery_discovery_failed = False

    async def async_status(self) -> dict[str, Any]:
        """Return the complete fixed-shape, identifier-free setup status."""

        async with self._operation():
            entry = self._single_entry()
            await self._async_refresh_recovery_tokens()
            readiness = await self._async_readiness()
            return {
                "entry_state": _public_entry_state(entry.state),
                "bootstrap_complete": CONF_BOOTSTRAP in entry.data,
                "bootstrap_plan_pending": self._bootstrap_token is not None,
                "migration": {
                    "ready": readiness.public.ready
                    and readiness.execution_scope_matches
                    and self._migration_executor is not None
                    and not self._recovery_discovery_failed
                    and not self._recovery_plan_ids,
                    "providers_ready": readiness.public.ready,
                    "executor_configured": self._migration_executor is not None,
                    "plan_pending": self._migration_token is not None,
                    "recovery_pending": bool(self._recovery_plan_ids),
                    "recovery_checked": not self._recovery_discovery_failed,
                    "recovery_tokens": sorted(self._recovery_plan_ids),
                    "providers": [
                        provider.as_dict() for provider in readiness.public.providers
                    ],
                },
            }

    async def async_check_migration_readiness(self) -> dict[str, Any]:
        """Run read-only inventories and bridge readiness for all providers."""

        async with self._operation():
            self._single_entry()
            return (await self._async_readiness()).public.as_dict()

    async def async_plan_bootstrap(
        self,
        room_entities: Mapping[str, str],
    ) -> dict[str, Any]:
        """Create a random-token wrapper around one exact seven-room plan."""

        async with self._operation():
            entry = self._single_entry()
            self._require_bootstrap_entry(entry)
            if (
                type(room_entities) is not dict
                or set(room_entities) != set(CANONICAL_ROOM_IDS)
                or len(room_entities) != len(CANONICAL_ROOM_IDS)
                or any(type(entity_id) is not str for entity_id in room_entities.values())
            ):
                raise SetupManagerError("bootstrap_invalid")
            try:
                plan = HomeAssistantBootstrapCoordinator(
                    self._hass,
                    entry,
                ).create_plan(dict(room_entities))
            except BootstrapError:
                raise SetupManagerError("bootstrap_invalid") from None
            except Exception:
                raise SetupManagerError("bootstrap_invalid") from None

            token = self._new_token()
            self._bootstrap_token = token
            self._bootstrap_plan = plan
            rooms = default_rooms()
            return {
                "token": token,
                "room_count": len(CANONICAL_ROOM_IDS),
                "rooms": [
                    _room_summary(rooms[room_id]) for room_id in CANONICAL_ROOM_IDS
                ],
            }

    async def async_commit_bootstrap(self, token: str) -> dict[str, Any]:
        """Commit only the newest public bootstrap token without loading it."""

        async with self._operation():
            entry = self._single_entry()
            self._require_bootstrap_entry(entry)
            if (
                type(token) is not str
                or token != self._bootstrap_token
                or self._bootstrap_plan is None
            ):
                raise SetupManagerError("plan_unknown")
            plan = self._bootstrap_plan
            try:
                record = HomeAssistantBootstrapCoordinator(
                    self._hass,
                    entry,
                ).commit(plan.plan_id)
            except BootstrapError:
                self._clear_bootstrap_plan()
                raise SetupManagerError("bootstrap_commit_failed") from None
            except Exception:
                self._clear_bootstrap_plan()
                raise SetupManagerError("bootstrap_commit_failed") from None

            self._clear_bootstrap_plan()
            rooms = self._rooms(entry)
            return {
                "state": "complete",
                "room_count": len(record.rooms),
                "rooms": [
                    _room_summary(rooms[room_id]) for room_id in CANONICAL_ROOM_IDS
                ],
            }

    async def async_plan_migration(
        self,
        room_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Issue a random public token only after full production readiness."""

        async with self._operation():
            entry = self._single_entry()
            self._require_migration_entry(entry)
            room = self._room(entry, room_id)
            if (
                isinstance(expected_revision, bool)
                or not isinstance(expected_revision, int)
                or expected_revision < 0
                or room.revision != expected_revision
            ):
                raise SetupManagerError("migration_revision_stale")
            executor = self._require_executor()
            await self._async_refresh_recovery_tokens()
            if self._recovery_discovery_failed or self._recovery_plan_ids:
                raise SetupManagerError("migration_recovery_required")
            readiness = await self._async_readiness()
            if not readiness.public.ready or not readiness.execution_scope_matches:
                raise SetupManagerError("migration_not_ready")
            executor = self._require_executor()
            try:
                plan = await executor.async_plan(room.room_id)
            except _MIGRATION_BACKEND_ERRORS:
                raise SetupManagerError("migration_plan_failed") from None
            except Exception:
                raise SetupManagerError("migration_plan_failed") from None
            self._require_executor()
            if not _valid_migration_plan(plan, room):
                raise SetupManagerError("migration_plan_failed")
            await self._async_require_execution_binding(
                executor,
                plan.plan_id,
                error_code="migration_plan_failed",
            )

            token = self._new_token()
            self._clear_migration_plan()
            self._migration_token = token
            self._migration_plan = plan
            self._migration_room = _room_summary(room)
            self._migration_runtime = entry.runtime_data
            self._migration_scope_digest = self._execution_scope_digest()
            return self._migration_plan_summary(token, plan)

    async def async_commit_migration(
        self,
        token: str,
        context: Context,
    ) -> dict[str, Any]:
        """Commit the exact opaque plan selected by the newest public token."""

        async with self._operation():
            entry = self._single_entry()
            self._require_migration_entry(entry)
            executor = self._require_executor()
            plan = self._migration_plan_for_token(token)
            room = self._room(entry, plan.room_id)
            if (
                entry.runtime_data is not self._migration_runtime
                or self._migration_scope_digest != self._execution_scope_digest()
                or not _valid_migration_plan(plan, room)
            ):
                self._clear_migration_plan()
                raise SetupManagerError("migration_revision_stale")
            await self._async_require_execution_binding(
                executor,
                plan.plan_id,
                error_code="migration_commit_failed",
            )
            readiness = await self._async_readiness()
            await self._async_require_execution_binding(
                executor,
                plan.plan_id,
                error_code="migration_commit_failed",
            )
            if not readiness.public.ready or not readiness.execution_scope_matches:
                raise SetupManagerError("migration_not_ready")
            current_entry = self._single_entry()
            self._require_migration_entry(current_entry)
            current_room = self._room(current_entry, plan.room_id)
            if (
                current_entry is not entry
                or current_entry.runtime_data is not self._migration_runtime
                or self._migration_scope_digest != self._execution_scope_digest()
                or not _valid_migration_plan(plan, current_room)
            ):
                self._clear_migration_plan()
                raise SetupManagerError("migration_revision_stale")
            executor = self._require_executor()
            await self._async_require_execution_binding(
                executor,
                plan.plan_id,
                error_code="migration_commit_failed",
            )
            try:
                result = await executor.async_commit(plan, context)
            except _MIGRATION_BACKEND_ERRORS:
                await self._async_refresh_recovery_tokens()
                raise SetupManagerError("migration_commit_failed") from None
            except Exception:
                await self._async_refresh_recovery_tokens()
                raise SetupManagerError("migration_commit_failed") from None
            executor = self._require_executor()
            await self._async_require_execution_binding(
                executor,
                plan.plan_id,
                error_code="migration_commit_failed",
            )
            if not _valid_migration_result(result, plan):
                raise SetupManagerError("migration_commit_failed")
            await self._async_require_terminal_outcome(
                executor,
                plan,
                result,
                error_code="migration_commit_failed",
            )

            summary = self._migration_result_summary(plan, result)
            self._clear_migration_plan()
            return summary

    async def async_recover_migration(
        self,
        token: str,
        context: Context,
    ) -> dict[str, Any]:
        """Recover an internal plan ID without accepting or returning that ID."""

        async with self._operation():
            entry = self._single_entry()
            self._require_migration_entry(entry)
            executor = self._require_executor()
            await self._async_refresh_recovery_tokens()
            if self._recovery_discovery_failed:
                raise SetupManagerError("migration_recovery_required")
            if type(token) is not str:
                raise SetupManagerError("plan_unknown")
            try:
                internal_plan_id = self._recovery_plan_ids[token]
            except KeyError:
                raise SetupManagerError("plan_unknown") from None
            await self._async_require_execution_binding(
                executor,
                internal_plan_id,
                error_code="migration_not_ready",
            )
            try:
                recovery_plan = await executor.async_recovery_plan(internal_plan_id)
            except _MIGRATION_BACKEND_ERRORS:
                raise SetupManagerError("migration_recovery_failed") from None
            except Exception:
                raise SetupManagerError("migration_recovery_failed") from None
            self._require_executor()
            if not _valid_durable_migration_plan(recovery_plan, internal_plan_id):
                raise SetupManagerError("migration_recovery_failed")
            await self._async_require_execution_binding(
                executor,
                internal_plan_id,
                error_code="migration_not_ready",
            )
            try:
                recovery_readiness = await executor.async_recovery_readiness(
                    internal_plan_id
                )
            except Exception:
                raise SetupManagerError("migration_not_ready") from None
            executor = self._require_executor()
            await self._async_require_execution_binding(
                executor,
                internal_plan_id,
                error_code="migration_not_ready",
            )
            if not self._recovery_readiness_matches(
                internal_plan_id,
                recovery_readiness,
            ):
                raise SetupManagerError("migration_not_ready")
            await self._async_require_execution_binding(
                executor,
                internal_plan_id,
                error_code="migration_not_ready",
            )
            try:
                result = await executor.async_recover(internal_plan_id, context)
            except _MIGRATION_BACKEND_ERRORS:
                raise SetupManagerError("migration_recovery_failed") from None
            except Exception:
                raise SetupManagerError("migration_recovery_failed") from None
            executor = self._require_executor()
            await self._async_require_execution_binding(
                executor,
                internal_plan_id,
                error_code="migration_recovery_failed",
            )
            if result is not None and not _valid_migration_result(
                result,
                recovery_plan,
            ):
                raise SetupManagerError("migration_recovery_failed")
            await self._async_require_terminal_outcome(
                executor,
                recovery_plan,
                result,
                error_code="migration_recovery_failed",
            )
            await self._async_refresh_recovery_tokens()
            if (
                self._recovery_discovery_failed
                or internal_plan_id in self._recovery_plan_ids.values()
            ):
                raise SetupManagerError("migration_recovery_failed")

            self._clear_migration_plan()
            return {
                "state": "recovered",
            }

    @asynccontextmanager
    async def _operation(self) -> AsyncIterator[None]:
        if self._lock.locked():
            raise SetupManagerError("busy")
        await self._lock.acquire()
        try:
            yield
        finally:
            self._lock.release()

    def _single_entry(self):
        try:
            entries = self._hass.config_entries.async_entries(DOMAIN)
        except Exception:
            raise SetupManagerError("entry_not_singleton") from None
        if len(entries) != 1:
            raise SetupManagerError("entry_not_singleton")
        return entries[0]

    @staticmethod
    def _require_bootstrap_entry(entry) -> None:
        if entry.state is not ConfigEntryState.NOT_LOADED:
            raise SetupManagerError("entry_not_unloaded")
        if CONF_BOOTSTRAP in entry.data:
            raise SetupManagerError("bootstrap_already_complete")

    def _rooms(self, entry) -> dict[str, RoomSlot]:
        try:
            raw_rooms = entry.data.get(CONF_ROOMS)
            return rooms_from_dict(raw_rooms) if raw_rooms else default_rooms()
        except (KeyError, TypeError, ValueError):
            raise SetupManagerError("room_unknown") from None

    @staticmethod
    def _require_migration_entry(entry) -> None:
        if entry.state is not ConfigEntryState.LOADED:
            raise SetupManagerError("migration_requires_load")
        if CONF_BOOTSTRAP not in entry.data:
            raise SetupManagerError("migration_bootstrap_required")

    def _room(self, entry, room_id: str) -> RoomSlot:
        if type(room_id) is not str:
            raise SetupManagerError("room_unknown")
        try:
            return self._rooms(entry)[room_id]
        except KeyError:
            raise SetupManagerError("room_unknown") from None

    def _require_executor(self) -> MigrationExecutor:
        if self._migration_executor is None or self._execution_scope is None:
            raise SetupManagerError("migration_executor_missing")
        current_bridges = getattr(self._migration_executor, "bridge_registry", None)
        if not isinstance(current_bridges, Mapping) or set(current_bridges) != set(
            self._executor_bridges
        ) or any(
            current_bridges[provider] is not bridge
            for provider, bridge in self._executor_bridges.items()
        ):
            raise SetupManagerError("migration_executor_missing")
        if getattr(self._migration_executor, "execution_scope", None) is not (
            self._execution_scope
        ):
            raise SetupManagerError("migration_executor_missing")
        if any(
            getattr(bridge, "bridge_id", None)
            != self._execution_scope.for_provider(provider).bridge_id
            for provider, bridge in self._executor_bridges.items()
        ):
            raise SetupManagerError("migration_executor_missing")
        return self._migration_executor

    async def _async_readiness(self) -> _ReadinessEvaluation:
        try:
            inventories = await async_probe_home_assistant_inventory(
                self._hass,
                self._expected_manifest,
                scope=self._inventory_scope,
                external_attestation=self._external_attestation,
                external_verifier=self._external_verifier,
            )
        except Exception:
            inventories = tuple(
                ProviderInventory.unavailable(provider)
                for provider in PROVIDER_NAMES
            )

        bridges: list[BridgeReadiness] = []
        for provider in PROVIDER_NAMES:
            bridge = self._bridges.get(provider)
            if bridge is None:
                bridges.append(BridgeReadiness.unavailable(provider))
                continue
            try:
                readiness = await bridge.async_readiness(self._expected_manifest)
            except Exception:
                readiness = BridgeReadiness.unavailable(provider)
            if (
                not isinstance(readiness, BridgeReadiness)
                or readiness.provider != provider
                or (
                    readiness.available
                    and readiness.bridge_id != getattr(bridge, "bridge_id", None)
                )
            ):
                readiness = BridgeReadiness.unavailable(provider)
            bridges.append(readiness)

        try:
            public = assess_production_readiness(
                self._expected_manifest,
                inventories,
                bridges,
                external_attestation=self._external_attestation,
                external_verifier=self._external_verifier,
            )
        except Exception:
            public = _closed_readiness(self._expected_manifest)
        bridge_tuple = tuple(bridges)
        return _ReadinessEvaluation(
            public,
            bridge_tuple,
            self._readiness_matches_execution_scope(bridge_tuple),
        )

    def _readiness_matches_execution_scope(
        self,
        bridges: tuple[BridgeReadiness, ...],
    ) -> bool:
        scope = self._execution_scope
        if scope is None or len(bridges) != len(PROVIDER_NAMES):
            return False
        for readiness in bridges:
            binding = scope.for_provider(readiness.provider)
            active = self._bridges.get(readiness.provider)
            if (
                active is None
                or not readiness.available
                or readiness.bridge_id != binding.bridge_id
                or readiness.readiness_revision != binding.readiness_revision
                or type(readiness.readiness_revision)
                is not type(binding.readiness_revision)
                or readiness.inventory_revision != binding.inventory_revision
                or type(readiness.inventory_revision)
                is not type(binding.inventory_revision)
                or getattr(active, "bridge_id", None) != binding.bridge_id
            ):
                return False
        return True

    def _recovery_readiness_matches(
        self,
        plan_id: str,
        readiness: object,
    ) -> bool:
        scope = self._execution_scope
        if (
            scope is None
            or not isinstance(readiness, MigrationRecoveryReadiness)
            or readiness.plan_id != plan_id
            or readiness.execution_scope_digest != scope.digest
            or readiness.recorder_id != scope.transaction_recorder.recorder_id
            or readiness.journal_id != scope.transaction_recorder.journal_id
            or not readiness.ready
        ):
            return False
        for provider_readiness in readiness.providers:
            provider = provider_readiness.provider
            bridge = self._executor_bridges.get(provider)
            if (
                bridge is None
                or provider_readiness.journal_bridge_id
                != scope.for_provider(provider).bridge_id
                or getattr(bridge, "bridge_id", None)
                != provider_readiness.journal_bridge_id
            ):
                return False
            if any(
                not callable(
                    getattr(bridge, _RECOVERY_CAPABILITY_METHODS[capability], None)
                )
                for capability in provider_readiness.required_capabilities
            ):
                return False
        return True

    async def _async_require_execution_binding(
        self,
        executor: MigrationExecutor,
        plan_id: str,
        *,
        error_code: str,
    ) -> ReferencePlanExecutionBinding:
        try:
            binding = await executor.async_execution_binding(plan_id)
        except _MIGRATION_BACKEND_ERRORS:
            raise SetupManagerError(error_code) from None
        except Exception:
            raise SetupManagerError(error_code) from None
        self._require_executor()
        expected = self._expected_execution_binding()
        if type(binding) is not ReferencePlanExecutionBinding or binding != expected:
            raise SetupManagerError(error_code)
        return binding

    async def _async_require_terminal_outcome(
        self,
        executor: MigrationExecutor,
        plan: MigrationPlan,
        result: MigrationResult | None,
        *,
        error_code: str,
    ) -> MigrationDurableOutcome:
        try:
            outcome = await executor.async_terminal_outcome(plan.plan_id)
        except _MIGRATION_BACKEND_ERRORS:
            raise SetupManagerError(error_code) from None
        except Exception:
            raise SetupManagerError(error_code) from None
        self._require_executor()
        binding = await self._async_require_execution_binding(
            executor,
            plan.plan_id,
            error_code=error_code,
        )
        if not _valid_durable_outcome(outcome, plan, binding, result):
            raise SetupManagerError(error_code)
        return outcome

    def _expected_execution_binding(self) -> ReferencePlanExecutionBinding:
        scope = self._execution_scope
        if scope is None:
            raise SetupManagerError("migration_executor_missing")
        coverage = scope.transaction_recorder
        return ReferencePlanExecutionBinding(
            execution_scope_digest=scope.digest,
            recorder_id=coverage.recorder_id,
            journal_id=coverage.journal_id,
            provider_bridge_ids=tuple(
                (provider, scope.for_provider(provider).bridge_id)
                for provider in sorted(PROVIDER_NAMES)
            ),
        )

    def _execution_scope_digest(self) -> str:
        if self._execution_scope is None:
            raise SetupManagerError("migration_executor_missing")
        return self._execution_scope.digest

    async def _async_refresh_recovery_tokens(self) -> None:
        if self._migration_executor is None:
            self._recovery_plan_ids.clear()
            self._recovery_discovery_failed = False
            return
        try:
            executor = self._require_executor()
            incomplete = await executor.async_incomplete_plan_ids()
        except Exception:
            self._recovery_discovery_failed = True
            return
        if type(incomplete) is not tuple or any(
            type(plan_id) is not str or not plan_id for plan_id in incomplete
        ) or len(set(incomplete)) != len(incomplete):
            self._recovery_discovery_failed = True
            return
        existing_by_plan = {
            plan_id: token for token, plan_id in self._recovery_plan_ids.items()
        }
        refreshed: dict[str, str] = {}
        for plan_id in sorted(incomplete):
            token = existing_by_plan.get(plan_id) or self._new_token()
            refreshed[token] = plan_id
        self._recovery_plan_ids = refreshed
        self._recovery_discovery_failed = False

    def _new_token(self) -> str:
        active = {
            token
            for token in (self._bootstrap_token, self._migration_token)
            if token is not None
        }
        active.update(self._recovery_plan_ids)
        while True:
            token = secrets.token_urlsafe(32)
            if token not in active:
                return token

    def _clear_bootstrap_plan(self) -> None:
        self._bootstrap_token = None
        self._bootstrap_plan = None

    def _clear_migration_plan(self) -> None:
        self._migration_token = None
        self._migration_plan = None
        self._migration_room = None
        self._migration_runtime = None
        self._migration_scope_digest = None

    def _migration_plan_for_token(self, token: str) -> MigrationPlan:
        if (
            type(token) is not str
            or token != self._migration_token
            or self._migration_plan is None
        ):
            raise SetupManagerError("plan_unknown")
        return self._migration_plan

    def _migration_plan_summary(
        self,
        token: str,
        plan: MigrationPlan,
    ) -> dict[str, Any]:
        return {
            "token": token,
            "room": dict(self._migration_room or {}),
            "provider_count": len(plan.providers),
            "document_count": len(plan.documents),
            "replacement_count": plan.exact_replacements,
        }

    def _migration_result_summary(
        self,
        plan: MigrationPlan,
        result: MigrationResult,
    ) -> dict[str, Any]:
        return {
            "state": "complete",
            "room": dict(self._migration_room or {}),
            "provider_count": len(plan.providers),
            "changed_document_count": result.changed_documents,
            "replacement_count": result.exact_replacements,
        }


def _public_entry_state(state: ConfigEntryState) -> str:
    if state is ConfigEntryState.NOT_LOADED:
        return "not_loaded"
    if state is ConfigEntryState.LOADED:
        return "loaded"
    return "unavailable"


def _room_summary(room: RoomSlot) -> dict[str, str | int]:
    return {
        "room_id": room.room_id,
        "display_name": room.display_name,
        "revision": room.revision,
    }


def _valid_migration_plan(plan: object, room: RoomSlot) -> bool:
    if not isinstance(plan, MigrationPlan):
        return False
    try:
        encode_migration_plan(plan)
    except Exception:
        return False
    if (
        plan.room_id != room.room_id
        or plan.room_revision != room.revision
        or plan.providers != tuple(PROVIDER_NAMES)
    ):
        return False
    return True


def _valid_durable_migration_plan(plan: object, plan_id: str) -> bool:
    if not isinstance(plan, MigrationPlan) or plan.plan_id != plan_id:
        return False
    try:
        encoded = encode_migration_plan(plan)
        return decode_migration_plan(encoded) == plan
    except Exception:
        return False


def _valid_durable_outcome(
    outcome: object,
    plan: MigrationPlan,
    binding: ReferencePlanExecutionBinding,
    result: MigrationResult | None,
) -> bool:
    if type(outcome) is not MigrationDurableOutcome:
        return False
    try:
        outcome.__post_init__()
    except Exception:
        return False
    if (
        outcome.plan_id != plan.plan_id
        or outcome.plan_digest != plan.digest
        or outcome.execution_binding != binding
    ):
        return False
    if result is None:
        return outcome.state is MigrationState.FAILED and outcome.result is None
    return (
        outcome.state is MigrationState.COMPLETE
        and outcome.result is not None
        and _valid_migration_result(result, plan)
        and _valid_migration_result(outcome.result, plan)
        and _migration_result_effect(outcome.result)
        == _migration_result_effect(result)
    )


def _valid_migration_result(result: object, plan: MigrationPlan) -> bool:
    if not isinstance(result, MigrationResult):
        return False
    return (
        result.plan_id == plan.plan_id
        and result.digest == plan.digest
        and result.state is MigrationState.COMPLETE
        and not isinstance(result.changed_documents, bool)
        and isinstance(result.changed_documents, int)
        and result.changed_documents
        == sum(bool(document.exact_paths) for document in plan.documents)
        and type(result.exact_replacements) is int
        and result.exact_replacements >= 0
        and result.exact_replacements == plan.exact_replacements
        and type(result.idempotent) is bool
    )


def _migration_result_effect(
    result: MigrationResult,
) -> tuple[str, str, MigrationState, int, int]:
    return (
        result.plan_id,
        result.digest,
        result.state,
        result.changed_documents,
        result.exact_replacements,
    )


def _closed_readiness(
    expected_manifest: ExpectedObjectManifest,
) -> ProductionReadiness:
    return ProductionReadiness(
        False,
        tuple(
            ProviderPublicSummary(
                provider,
                PublicProviderStatus.UNAVAILABLE,
                expected_manifest.for_provider(provider).count,
                0,
            )
            for provider in PROVIDER_NAMES
        ),
    )


def _validate_provider_name(provider: str) -> None:
    if type(provider) is not str or provider not in PROVIDER_NAMES:
        raise ValueError("Provider name is not in the execution manifest.")


def _validate_opaque_id(value: str, label: str) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} must be an opaque non-secret identifier.")


def _validate_revision(value: Revision, label: str) -> None:
    if type(value) is int:
        if value < 0:
            raise ValueError(f"{label} cannot be negative.")
        return
    if type(value) is str:
        _validate_opaque_id(value, label)
        return
    raise TypeError(f"{label} must be a typed string or integer revision.")


def _validate_digest(value: str, label: str) -> None:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest.")


def _canonical_revision(value: Revision) -> dict[str, str | int]:
    _validate_revision(value, "Execution revision")
    return {
        "type": "integer" if type(value) is int else "string",
        "value": value,
    }


def _digest_json(value: Any) -> str:
    canonical = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
