"""Pure fail-closed planning for logical entity reference migrations."""

from __future__ import annotations

from collections.abc import Iterable, Sequence, Set as AbstractSet
from copy import deepcopy
from dataclasses import dataclass, replace
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any, Mapping, Protocol

from .reference_projection import (
    replace_semantic_references,
    scan_semantic_references,
)


Revision = str | int
PathPart = str | int
ReferencePath = tuple[PathPart, ...]

_CLIMATE_ENTITY_PATTERN = re.compile(r"^climate\.[a-z0-9_]+$")
_LOGICAL_UNIQUE_ID_PATTERN = re.compile(r"^logical_valve_[a-z0-9_]+$")

TRUE_FAMILY_PROVIDER_MANIFEST = frozenset(
    {
        "active_yaml",
        "config_entry",
        "external_writers",
        "lovelace",
        "scheduler",
    }
)


class ReferenceMigrationError(RuntimeError):
    """Base error for a blocked reference migration."""


class MalformedReferenceDocumentError(ReferenceMigrationError):
    """Raised when a document is not a canonical mapping/list tree."""


class MigrationPlanningBlocked(ReferenceMigrationError):
    """Raised when discovery cannot produce a safe migration plan."""

    def __init__(self, reasons: Iterable[str]) -> None:
        self.reasons = tuple(reasons)
        super().__init__("; ".join(self.reasons))


class UnknownMigrationPlan(ReferenceMigrationError):
    """Raised when apply does not identify a coordinator-issued plan."""


class StaleMigrationPlan(ReferenceMigrationError):
    """Raised when a document changed after planning or completion."""


class MigrationApplyFailed(ReferenceMigrationError):
    """Raised when apply fails after all changed documents are restored."""

    def __init__(self, message: str, *, rolled_back: bool) -> None:
        self.rolled_back = rolled_back
        super().__init__(message)


class MigrationRestoreFailed(MigrationApplyFailed):
    """Raised when a partial apply cannot be restored completely."""

    def __init__(self, message: str, failed_documents: Iterable[str]) -> None:
        self.failed_documents = tuple(failed_documents)
        super().__init__(message, rolled_back=False)


class MigrationState(StrEnum):
    """Coordinator state for one issued migration plan."""

    PLANNED = "planned"
    APPLYING = "applying"
    COMPLETE = "complete"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class ReferenceDocument:
    """One revisioned provider object that may contain entity references."""

    provider: str
    object_id: str
    revision: Revision
    payload: Any
    writable: bool

    def __post_init__(self) -> None:
        if not isinstance(self.provider, str) or not self.provider:
            raise ValueError("A reference document provider is required.")
        if not isinstance(self.object_id, str) or not self.object_id:
            raise ValueError("A reference document object ID is required.")
        if isinstance(self.revision, bool) or not isinstance(
            self.revision, (str, int)
        ):
            raise ValueError("A reference document revision must be a string or integer.")
        if isinstance(self.revision, str) and not self.revision:
            raise ValueError("A string revision cannot be empty.")
        if not isinstance(self.writable, bool):
            raise ValueError("Reference document writable must be a boolean.")


class ReferenceProvider(Protocol):
    """Schema-aware provider contract used by the migration coordinator.

    Concrete providers must expose only semantically recognized entity-reference
    fields. Approved literal template-helper arguments may remain as templates;
    unknown or computed occurrences must remain visible so planning blocks them.
    """

    @property
    def name(self) -> str:
        """Return the stable provider name."""

        ...

    def list_documents(self) -> Sequence[ReferenceDocument]:
        """Return the provider's complete reference-document inventory."""

        ...

    def get_document(self, object_id: str) -> ReferenceDocument:
        """Re-fetch one document by stable object ID."""

        ...

    def write_document(
        self,
        object_id: str,
        *,
        expected_revision: Revision,
        payload: Any,
    ) -> ReferenceDocument:
        """Replace one payload only if its revision is still current."""

        ...


class ReferenceJournal(Protocol):
    """Adapter contract for durable original-document journaling."""

    def record_original(
        self,
        plan_id: str,
        document: ReferenceDocument,
        post_fingerprint: str,
    ) -> None:
        """Persist an original document before any provider write."""

        ...

    def set_state(
        self,
        plan_id: str,
        state: MigrationState,
        reason: str | None = None,
    ) -> None:
        """Persist the current migration state before returning control."""

        ...

    def incomplete_plan_ids(self) -> tuple[str, ...]:
        """Return plans left applying or blocked by a prior process."""

        ...

    def originals_for(self, plan_id: str) -> tuple[JournaledOriginal, ...]:
        """Load originals and attested postimages for explicit recovery."""

        ...

    def record_completion(self, completion: JournaledCompletion) -> None:
        """Persist a completed plan, result, and verified provider snapshots."""

        ...

    def completed_plan_ids(self) -> tuple[str, ...]:
        """Return durably completed plan IDs available for replay."""

        ...

    def completion_for(self, plan_id: str) -> JournaledCompletion:
        """Load one durable completion record."""

        ...


@dataclass(frozen=True, slots=True)
class MigrationSubject:
    """Server-owned room identity and provider-specific migration targets."""

    room_id: str
    room_revision: int
    old_entity_id: str
    logical_unique_id: str
    provider_targets: tuple[tuple[str, str], ...]


class MigrationAuthority(Protocol):
    """Resolve migration subjects from trusted server-owned room state."""

    def resolve_subject(self, room_id: str) -> MigrationSubject:
        """Return current authoritative migration fields for one room."""

        ...


@dataclass(frozen=True, slots=True)
class EmbeddedReference:
    """An unsafe textual reference that cannot be scalar-replaced."""

    path: ReferencePath
    text: str
    mapping_key: bool = False


@dataclass(frozen=True, slots=True)
class ReferenceScan:
    """Exact replaceable paths and unsafe embedded textual references."""

    exact_paths: tuple[ReferencePath, ...]
    embedded: tuple[EmbeddedReference, ...]


@dataclass(frozen=True, slots=True)
class PlannedDocument:
    """Immutable metadata snapshot for one discovered provider document."""

    provider: str
    object_id: str
    revision: Revision
    writable: bool
    fingerprint: str
    post_fingerprint: str
    exact_paths: tuple[ReferencePath, ...]


@dataclass(frozen=True, slots=True)
class JournaledOriginal:
    """One durable original paired with its coordinator-planned postimage."""

    document: ReferenceDocument
    post_fingerprint: str


@dataclass(frozen=True, slots=True)
class MigrationPlan:
    """Deterministic plan metadata containing no caller-supplied patches."""

    plan_id: str
    digest: str
    room_id: str
    room_revision: int
    old_entity_id: str
    logical_unique_id: str
    target_entity_id: str | None
    provider_targets: tuple[tuple[str, str], ...]
    providers: tuple[str, ...]
    references_expected: bool
    documents: tuple[PlannedDocument, ...]
    exact_replacements: int


@dataclass(frozen=True, slots=True)
class MigrationResult:
    """Successful application result for one deterministic plan."""

    plan_id: str
    digest: str
    state: MigrationState
    changed_documents: int
    exact_replacements: int
    idempotent: bool


@dataclass(frozen=True, slots=True)
class _DocumentSnapshot:
    provider: str
    object_id: str
    revision: Revision
    writable: bool
    fingerprint: str


@dataclass(frozen=True, slots=True)
class _CompletionRecord:
    result: MigrationResult
    documents: tuple[_DocumentSnapshot, ...]


@dataclass(frozen=True, slots=True)
class JournaledCompletion:
    """Durable data needed to verify idempotent replay after restart."""

    plan: MigrationPlan
    result: MigrationResult
    documents: tuple[_DocumentSnapshot, ...]


def canonical_document_fingerprint(document: ReferenceDocument) -> str:
    """Return a canonical SHA-256 fingerprint of a document payload."""

    return _payload_fingerprint(document.payload)


def scan_references(
    payload: Any,
    old_entity_id: str,
    *,
    provider: str | None = None,
) -> ReferenceScan:
    """Find typed scalar/template references and unsafe textual occurrences."""

    if not isinstance(old_entity_id, str) or not old_entity_id:
        raise ValueError("The old entity ID is required.")
    _validate_payload(payload)
    scan = scan_semantic_references(
        payload,
        old_entity_id,
        provider=provider,
    )
    return ReferenceScan(
        scan.replaceable_paths,
        tuple(
            EmbeddedReference(item.path, item.text, item.mapping_key)
            for item in scan.blocked
        ),
    )


class ReferenceMigrationCoordinator:
    """Plan, apply, verify, and restore provider-neutral reference changes."""

    def __init__(
        self,
        providers: Iterable[ReferenceProvider],
        journal: ReferenceJournal,
        authority: MigrationAuthority,
    ) -> None:
        provider_map: dict[str, ReferenceProvider] = {}
        for provider in providers:
            name = provider.name
            if not isinstance(name, str) or not name:
                raise ValueError("Every reference provider needs a stable name.")
            if name in provider_map:
                raise ValueError(f"Duplicate reference provider: {name}.")
            provider_map[name] = provider
        if set(provider_map) != set(TRUE_FAMILY_PROVIDER_MANIFEST):
            missing = sorted(set(TRUE_FAMILY_PROVIDER_MANIFEST) - set(provider_map))
            unexpected = sorted(set(provider_map) - set(TRUE_FAMILY_PROVIDER_MANIFEST))
            details = []
            if missing:
                details.append(f"missing: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected: {', '.join(unexpected)}")
            raise ValueError(
                "The production reference-provider manifest is incomplete ("
                + "; ".join(details)
                + ")."
            )
        required_journal_methods = (
            "record_original",
            "set_state",
            "incomplete_plan_ids",
            "originals_for",
            "record_completion",
            "completed_plan_ids",
            "completion_for",
        )
        if any(not callable(getattr(journal, name, None)) for name in required_journal_methods):
            raise TypeError("A stateful reference journal adapter is required.")
        if not callable(getattr(authority, "resolve_subject", None)):
            raise TypeError("A server-side migration authority is required.")
        self._journal = journal
        self._authority = authority
        self._providers = provider_map
        self._plans: dict[str, MigrationPlan] = {}
        self._states: dict[str, MigrationState] = {}
        self._completed: dict[str, _CompletionRecord] = {}
        for plan_id in journal.completed_plan_ids():
            completion = journal.completion_for(plan_id)
            _validate_journaled_completion(completion, plan_id)
            self._plans[plan_id] = completion.plan
            self._states[plan_id] = MigrationState.COMPLETE
            self._completed[plan_id] = _CompletionRecord(
                completion.result,
                completion.documents,
            )
        incomplete = tuple(journal.incomplete_plan_ids())
        self._blocked_reason: str | None = (
            "An incomplete migration journal requires explicit recovery: "
            + ", ".join(incomplete)
            if incomplete
            else None
        )

    @property
    def blocked(self) -> bool:
        """Return whether an incomplete restoration blocked the coordinator."""

        return self._blocked_reason is not None

    @property
    def blocked_reason(self) -> str | None:
        """Return the restoration failure that blocked further mutations."""

        return self._blocked_reason

    def state(self, plan_id: str) -> MigrationState | None:
        """Return the current state of an issued plan."""

        return self._states.get(plan_id)

    def create_plan(
        self,
        *,
        room_id: str,
        room_revision: int,
        old_entity_id: str,
        logical_unique_id: str,
        target_entity_id: str | None,
        provider_targets: Mapping[str, str] | None = None,
        required_providers: AbstractSet[str],
        references_expected: bool,
    ) -> MigrationPlan:
        """Discover all documents and issue a deterministic safe plan."""

        if self.blocked:
            raise MigrationPlanningBlocked(
                (self._blocked_reason or "Reference migrations are blocked.",)
            )
        reasons = self._validate_plan_request(
            room_id=room_id,
            room_revision=room_revision,
            old_entity_id=old_entity_id,
            logical_unique_id=logical_unique_id,
            target_entity_id=target_entity_id,
            provider_targets=provider_targets,
            required_providers=required_providers,
            references_expected=references_expected,
        )
        if reasons:
            raise MigrationPlanningBlocked(reasons)

        provider_names = tuple(sorted(required_providers))
        targets = _normalize_provider_targets(
            provider_names,
            target_entity_id,
            provider_targets,
        )
        try:
            subject = self._authority.resolve_subject(room_id)
        except Exception as err:
            raise MigrationPlanningBlocked(
                (f"The authoritative room state could not be resolved: {err}",)
            ) from err
        requested_subject = MigrationSubject(
            room_id=room_id,
            room_revision=room_revision,
            old_entity_id=old_entity_id,
            logical_unique_id=logical_unique_id,
            provider_targets=tuple(sorted(targets.items())),
        )
        if subject != requested_subject:
            raise MigrationPlanningBlocked(
                ("The requested migration fields do not match server-owned room state.",)
            )
        documents: list[PlannedDocument] = []
        seen: set[tuple[str, str]] = set()
        exact_replacements = 0
        for provider_name in provider_names:
            provider = self._providers[provider_name]
            try:
                provider_documents = provider.list_documents()
            except Exception as err:
                reasons.append(f"Provider {provider_name} could not be enumerated: {err}")
                continue
            if not isinstance(provider_documents, Sequence) or isinstance(
                provider_documents, (str, bytes)
            ):
                reasons.append(
                    f"Provider {provider_name} returned a malformed document inventory."
                )
                continue
            for document in sorted(
                provider_documents,
                key=lambda item: getattr(item, "object_id", ""),
            ):
                if not isinstance(document, ReferenceDocument):
                    reasons.append(
                        f"Provider {provider_name} returned a malformed document."
                    )
                    continue
                key = (provider_name, document.object_id)
                if document.provider != provider_name:
                    reasons.append(
                        f"Document {document.object_id} belongs to the wrong provider."
                    )
                    continue
                if key in seen:
                    reasons.append(
                        f"Provider {provider_name} returned duplicate object "
                        f"{document.object_id}."
                    )
                    continue
                seen.add(key)
                try:
                    fingerprint = canonical_document_fingerprint(document)
                    scan = scan_references(
                        document.payload,
                        old_entity_id,
                        provider=provider_name,
                    )
                except MalformedReferenceDocumentError as err:
                    reasons.append(
                        f"Document {provider_name}/{document.object_id} is malformed: {err}"
                    )
                    continue
                if not document.writable:
                    reasons.append(
                        f"Document {provider_name}/{document.object_id} is not writable."
                    )
                if scan.embedded:
                    paths = ", ".join(
                        _format_path(reference.path) for reference in scan.embedded
                    )
                    reasons.append(
                        f"Document {provider_name}/{document.object_id} contains "
                        f"embedded references at {paths}."
                    )
                replaced_payload, replaced_count = _replace_exact_scalars(
                    document.payload,
                    old_entity_id,
                    targets[provider_name],
                    provider=provider_name,
                )
                exact_replacements += replaced_count
                documents.append(
                    PlannedDocument(
                        provider=provider_name,
                        object_id=document.object_id,
                        revision=document.revision,
                        writable=document.writable,
                        fingerprint=fingerprint,
                        post_fingerprint=_payload_fingerprint(replaced_payload),
                        exact_paths=scan.exact_paths,
                    )
                )

        if references_expected and exact_replacements == 0:
            reasons.append("No safe exact entity references were found.")
        if reasons:
            raise MigrationPlanningBlocked(reasons)

        documents.sort(key=lambda item: (item.provider, item.object_id))
        digest_payload = {
            "schema": 1,
            "room_id": room_id,
            "room_revision": room_revision,
            "old_entity_id": old_entity_id,
            "logical_unique_id": logical_unique_id,
            "target_entity_id": target_entity_id,
            "provider_targets": targets,
            "providers": list(provider_names),
            "references_expected": references_expected,
            "documents": [
                {
                    "provider": document.provider,
                    "object_id": document.object_id,
                    "revision": _canonical_revision(document.revision),
                    "writable": document.writable,
                    "fingerprint": document.fingerprint,
                    "post_fingerprint": document.post_fingerprint,
                    "exact_paths": [
                        _canonical_path(path) for path in document.exact_paths
                    ],
                }
                for document in documents
            ],
        }
        digest = hashlib.sha256(_canonical_json(digest_payload)).hexdigest()
        plan_id_hash = hashlib.sha256(f"reference-plan:{digest}".encode()).hexdigest()
        plan = MigrationPlan(
            plan_id=f"tf-reference-{plan_id_hash[:24]}",
            digest=digest,
            room_id=room_id,
            room_revision=room_revision,
            old_entity_id=old_entity_id,
            logical_unique_id=logical_unique_id,
            target_entity_id=target_entity_id,
            provider_targets=tuple(sorted(targets.items())),
            providers=provider_names,
            references_expected=references_expected,
            documents=tuple(documents),
            exact_replacements=exact_replacements,
        )
        existing = self._plans.get(plan.plan_id)
        if existing is not None and existing != plan:
            raise ReferenceMigrationError("A deterministic plan ID collision occurred.")
        if existing is not None:
            return existing
        self._plans[plan.plan_id] = plan
        self._states.setdefault(plan.plan_id, MigrationState.PLANNED)
        self._journal.set_state(plan.plan_id, MigrationState.PLANNED)
        return plan

    def recover_incomplete(self, plan_id: str) -> None:
        """Restore a journaled interrupted plan without reconstructing its plan."""

        if plan_id not in self._journal.incomplete_plan_ids():
            raise UnknownMigrationPlan("The migration journal is not incomplete.")
        entries = self._journal.originals_for(plan_id)
        originals: dict[tuple[str, str], ReferenceDocument] = {}
        attempted: list[tuple[ReferenceDocument, str]] = []
        for entry in entries:
            if not isinstance(entry, JournaledOriginal):
                raise MigrationRestoreFailed("The migration journal is malformed.", ())
            original = entry.document
            key = (original.provider, original.object_id)
            if key in originals or original.provider not in self._providers:
                raise MigrationRestoreFailed("The migration journal is malformed.", ())
            canonical_document_fingerprint(original)
            if not isinstance(entry.post_fingerprint, str) or not entry.post_fingerprint:
                raise MigrationRestoreFailed("The migration journal is malformed.", ())
            originals[key] = original
            attempted.append((original, entry.post_fingerprint))
        failures = self._restore_originals(
            attempted,
            originals,
            verify_full_inventory=False,
        )
        if failures:
            reason = "Interrupted migration recovery requires manual reconciliation."
            self._journal.set_state(plan_id, MigrationState.BLOCKED, reason)
            self._blocked_reason = reason
            raise MigrationRestoreFailed(reason, failures)
        self._journal.set_state(
            plan_id,
            MigrationState.FAILED,
            "Interrupted migration was restored explicitly.",
        )
        if plan_id in self._states:
            self._states[plan_id] = MigrationState.FAILED
        self._completed.pop(plan_id, None)
        incomplete = self._journal.incomplete_plan_ids()
        self._blocked_reason = (
            "An incomplete migration journal requires explicit recovery: "
            + ", ".join(incomplete)
            if incomplete
            else None
        )

    def apply(self, *, plan_id: str, digest: str) -> MigrationResult:
        """Apply a coordinator-issued plan without accepting external patches."""

        plan = self._plans.get(plan_id)
        if plan is None or plan.digest != digest:
            raise UnknownMigrationPlan("The migration plan ID or digest is unknown.")
        if self.blocked:
            raise MigrationRestoreFailed(
                self._blocked_reason or "Reference migrations are blocked.",
                (),
            )
        state = self._states[plan_id]
        if state is MigrationState.APPLYING:
            raise ReferenceMigrationError("The migration plan is already being applied.")
        if state is MigrationState.BLOCKED:
            raise StaleMigrationPlan("The migration plan is blocked and cannot be replayed.")
        if state is MigrationState.COMPLETE:
            return self._replay_completed(plan)

        try:
            self._assert_authority(plan)
            originals = self._fetch_inventory(plan.providers)
            self._assert_preflight(plan, originals)
        except Exception as err:
            self._states[plan_id] = MigrationState.BLOCKED
            self._journal.set_state(plan_id, MigrationState.FAILED, str(err))
            if isinstance(err, StaleMigrationPlan):
                raise
            raise StaleMigrationPlan(f"Migration preflight failed: {err}") from err

        changes: list[tuple[ReferenceDocument, Any]] = []
        for document_plan in plan.documents:
            if not document_plan.exact_paths:
                continue
            original = originals[(document_plan.provider, document_plan.object_id)]
            payload, count = _replace_exact_scalars(
                original.payload,
                plan.old_entity_id,
                dict(plan.provider_targets)[document_plan.provider],
                provider=document_plan.provider,
            )
            if count != len(document_plan.exact_paths):
                self._states[plan_id] = MigrationState.BLOCKED
                raise StaleMigrationPlan("The exact reference paths changed before apply.")
            changes.append((original, payload))

        self._states[plan_id] = MigrationState.APPLYING
        self._journal.set_state(plan_id, MigrationState.APPLYING)
        try:
            for original, _payload in changes:
                self._journal.record_original(
                    plan.plan_id,
                    _copy_document(original),
                    next(
                        document.post_fingerprint
                        for document in plan.documents
                        if document.provider == original.provider
                        and document.object_id == original.object_id
                    ),
                )
        except Exception as err:
            self._states[plan_id] = MigrationState.FAILED
            self._journal.set_state(plan_id, MigrationState.FAILED, str(err))
            raise MigrationApplyFailed(
                f"Original-document journaling failed before writes: {err}",
                rolled_back=False,
            ) from err

        attempted: list[tuple[ReferenceDocument, str]] = []
        try:
            for original, payload in changes:
                provider = self._providers[original.provider]
                expected = next(
                    item
                    for item in plan.documents
                    if item.provider == original.provider
                    and item.object_id == original.object_id
                )
                try:
                    provider.write_document(
                        original.object_id,
                        expected_revision=original.revision,
                        payload=deepcopy(payload),
                    )
                except Exception:
                    current = provider.get_document(original.object_id)
                    current_fingerprint = canonical_document_fingerprint(current)
                    if current_fingerprint == expected.post_fingerprint:
                        attempted.append((original, expected.post_fingerprint))
                    raise
                written = provider.get_document(original.object_id)
                if canonical_document_fingerprint(written) != expected.post_fingerprint:
                    raise ReferenceMigrationError(
                        f"Provider {original.provider} did not persist the planned payload."
                    )
                attempted.append((original, expected.post_fingerprint))
            final_documents = self._fetch_inventory(plan.providers)
            self._assert_post_apply(plan, final_documents)
            self._assert_authority(plan)
        except Exception as err:
            failed_restores = self._restore_originals(attempted, originals)
            if failed_restores:
                self._states[plan_id] = MigrationState.BLOCKED
                self._blocked_reason = (
                    "Reference migration restoration failed; manual recovery is required."
                )
                self._journal.set_state(
                    plan_id,
                    MigrationState.BLOCKED,
                    self._blocked_reason,
                )
                raise MigrationRestoreFailed(
                    self._blocked_reason,
                    failed_restores,
                ) from err
            self._states[plan_id] = MigrationState.FAILED
            self._journal.set_state(plan_id, MigrationState.FAILED, str(err))
            raise MigrationApplyFailed(
                f"Reference migration failed and was restored: {err}",
                rolled_back=bool(attempted),
            ) from err

        result = MigrationResult(
            plan_id=plan.plan_id,
            digest=plan.digest,
            state=MigrationState.COMPLETE,
            changed_documents=len(changes),
            exact_replacements=plan.exact_replacements,
            idempotent=False,
        )
        completion = _CompletionRecord(
            result=result,
            documents=_snapshots(final_documents),
        )
        try:
            self._journal.record_completion(
                JournaledCompletion(
                    plan=plan,
                    result=result,
                    documents=completion.documents,
                )
            )
            self._journal.set_state(plan_id, MigrationState.COMPLETE)
        except Exception as err:
            reason = (
                "Migration completion could not be persisted; explicit recovery "
                "is required."
            )
            self._states[plan_id] = MigrationState.BLOCKED
            self._blocked_reason = reason
            try:
                self._journal.set_state(plan_id, MigrationState.BLOCKED, reason)
            except Exception:
                pass
            raise MigrationRestoreFailed(reason, ()) from err
        self._completed[plan.plan_id] = completion
        self._states[plan_id] = MigrationState.COMPLETE
        return result

    def _validate_plan_request(
        self,
        *,
        room_id: str,
        room_revision: int,
        old_entity_id: str,
        logical_unique_id: str,
        target_entity_id: str | None,
        provider_targets: Mapping[str, str] | None,
        required_providers: AbstractSet[str],
        references_expected: bool,
    ) -> list[str]:
        reasons: list[str] = []
        for label, value in (
            ("room ID", room_id),
            ("old entity ID", old_entity_id),
            ("logical unique ID", logical_unique_id),
        ):
            if not isinstance(value, str) or not value:
                reasons.append(f"A non-empty {label} is required.")
        if isinstance(room_revision, bool) or not isinstance(room_revision, int):
            reasons.append("Room revision must be an integer.")
        elif room_revision < 0:
            reasons.append("Room revision cannot be negative.")
        if not isinstance(references_expected, bool):
            reasons.append("references_expected must be explicit true or false.")
        if not isinstance(required_providers, AbstractSet) or not required_providers:
            reasons.append("A non-empty explicit required-provider set is required.")
            return reasons
        if any(not isinstance(name, str) or not name for name in required_providers):
            reasons.append("Required provider names must be non-empty strings.")
            return reasons
        configured = set(self._providers)
        required = set(required_providers)
        missing = sorted(required - configured)
        omitted = sorted(configured - required)
        if missing:
            reasons.append(f"Missing required providers: {', '.join(missing)}.")
        if omitted:
            reasons.append(
                f"The required-provider set is incomplete: {', '.join(omitted)}."
            )
        if old_entity_id and not _CLIMATE_ENTITY_PATTERN.fullmatch(old_entity_id):
            reasons.append("The old entity ID must be a canonical climate entity ID.")
        if logical_unique_id and not _LOGICAL_UNIQUE_ID_PATTERN.fullmatch(
            logical_unique_id
        ):
            reasons.append("The logical unique ID is malformed.")
        if provider_targets is None:
            if not isinstance(target_entity_id, str) or not _CLIMATE_ENTITY_PATTERN.fullmatch(
                target_entity_id
            ):
                reasons.append("The target entity ID must be a canonical climate entity ID.")
            elif old_entity_id == target_entity_id:
                reasons.append("The old and target entity IDs must differ.")
        elif not isinstance(provider_targets, Mapping):
            reasons.append("Provider-specific targets must be a mapping.")
        else:
            if target_entity_id is not None:
                reasons.append(
                    "Use either one target entity or provider-specific targets, not both."
                )
            if set(provider_targets) != set(required_providers):
                reasons.append("Provider-specific targets must cover every provider exactly.")
            for provider, target in provider_targets.items():
                if not isinstance(provider, str) or not isinstance(target, str):
                    reasons.append("Provider target entries must be strings.")
                elif not _CLIMATE_ENTITY_PATTERN.fullmatch(target):
                    reasons.append(
                        f"Provider {provider} target must be a canonical climate entity ID."
                    )
                elif target == old_entity_id:
                    reasons.append(f"Provider {provider} target is not a safe replacement.")
        return reasons

    def _fetch_inventory(
        self,
        provider_names: tuple[str, ...],
    ) -> dict[tuple[str, str], ReferenceDocument]:
        inventory: dict[tuple[str, str], ReferenceDocument] = {}
        for provider_name in provider_names:
            provider = self._providers.get(provider_name)
            if provider is None:
                raise StaleMigrationPlan(f"Required provider {provider_name} is missing.")
            documents = provider.list_documents()
            if not isinstance(documents, Sequence) or isinstance(
                documents, (str, bytes)
            ):
                raise StaleMigrationPlan(
                    f"Provider {provider_name} returned a malformed inventory."
                )
            for listed in documents:
                if not isinstance(listed, ReferenceDocument):
                    raise StaleMigrationPlan(
                        f"Provider {provider_name} returned a malformed document."
                    )
                document = provider.get_document(listed.object_id)
                if document.provider != provider_name:
                    raise StaleMigrationPlan(
                        f"Document {document.object_id} changed providers."
                    )
                key = (provider_name, document.object_id)
                if key in inventory:
                    raise StaleMigrationPlan(
                        f"Provider {provider_name} returned duplicate object "
                        f"{document.object_id}."
                    )
                canonical_document_fingerprint(document)
                inventory[key] = document
        return inventory

    def _assert_preflight(
        self,
        plan: MigrationPlan,
        inventory: dict[tuple[str, str], ReferenceDocument],
    ) -> None:
        planned = {
            (document.provider, document.object_id): document
            for document in plan.documents
        }
        if set(inventory) != set(planned):
            raise StaleMigrationPlan("The provider document inventory changed.")
        exact_count = 0
        for key, document_plan in planned.items():
            current = inventory[key]
            fingerprint = canonical_document_fingerprint(current)
            if current.revision != document_plan.revision:
                raise StaleMigrationPlan(
                    f"Document {current.provider}/{current.object_id} changed revision."
                )
            if fingerprint != document_plan.fingerprint:
                raise StaleMigrationPlan(
                    f"Document {current.provider}/{current.object_id} changed content."
                )
            if not current.writable or current.writable != document_plan.writable:
                raise StaleMigrationPlan(
                    f"Document {current.provider}/{current.object_id} is not writable."
                )
            scan = scan_references(
                current.payload,
                plan.old_entity_id,
                provider=current.provider,
            )
            if scan.embedded:
                raise StaleMigrationPlan(
                    f"Document {current.provider}/{current.object_id} gained an "
                    "embedded reference."
                )
            if scan.exact_paths != document_plan.exact_paths:
                raise StaleMigrationPlan(
                    f"Document {current.provider}/{current.object_id} changed exact paths."
                )
            exact_count += len(scan.exact_paths)
        if exact_count != plan.exact_replacements:
            raise StaleMigrationPlan("The exact reference count changed.")
        if plan.references_expected and exact_count == 0:
            raise StaleMigrationPlan("Expected references are no longer present.")

    def _assert_authority(self, plan: MigrationPlan) -> None:
        try:
            current = self._authority.resolve_subject(plan.room_id)
        except Exception as err:
            raise StaleMigrationPlan(
                f"The authoritative room state could not be resolved: {err}"
            ) from err
        expected = MigrationSubject(
            room_id=plan.room_id,
            room_revision=plan.room_revision,
            old_entity_id=plan.old_entity_id,
            logical_unique_id=plan.logical_unique_id,
            provider_targets=plan.provider_targets,
        )
        if current != expected:
            raise StaleMigrationPlan(
                "The authoritative room state changed after plan creation."
            )

    def _assert_post_apply(
        self,
        plan: MigrationPlan,
        inventory: dict[tuple[str, str], ReferenceDocument],
    ) -> None:
        planned = {
            (document.provider, document.object_id): document
            for document in plan.documents
        }
        if set(inventory) != set(planned):
            raise ReferenceMigrationError(
                "The provider document inventory changed during apply."
            )
        for key, document_plan in planned.items():
            current = inventory[key]
            if not current.writable:
                raise ReferenceMigrationError(
                    f"Document {current.provider}/{current.object_id} became read-only."
                )
            if canonical_document_fingerprint(current) != document_plan.post_fingerprint:
                raise ReferenceMigrationError(
                    f"Document {current.provider}/{current.object_id} failed verification."
                )
            scan = scan_references(
                current.payload,
                plan.old_entity_id,
                provider=current.provider,
            )
            if scan.exact_paths or scan.embedded:
                raise ReferenceMigrationError(
                    f"Document {current.provider}/{current.object_id} still references "
                    "the old entity."
                )

    def _restore_originals(
        self,
        attempted: list[tuple[ReferenceDocument, str]],
        originals: dict[tuple[str, str], ReferenceDocument],
        *,
        verify_full_inventory: bool = True,
    ) -> tuple[str, ...]:
        failures: list[str] = []
        for original, post_fingerprint in reversed(attempted):
            label = f"{original.provider}/{original.object_id}"
            provider = self._providers[original.provider]
            try:
                current = provider.get_document(original.object_id)
                current_fingerprint = canonical_document_fingerprint(current)
                original_fingerprint = canonical_document_fingerprint(original)
                if current_fingerprint == post_fingerprint:
                    provider.write_document(
                        original.object_id,
                        expected_revision=current.revision,
                        payload=deepcopy(original.payload),
                    )
                elif current_fingerprint != original_fingerprint:
                    raise ReferenceMigrationError(
                        "A concurrent writer changed the planned postimage."
                    )
                restored = provider.get_document(original.object_id)
                if canonical_document_fingerprint(
                    restored
                ) != canonical_document_fingerprint(original):
                    raise ReferenceMigrationError("Restored content did not verify.")
            except Exception:
                failures.append(label)
        if verify_full_inventory:
            try:
                current_inventory = self._fetch_inventory(
                    tuple(sorted({provider for provider, _object_id in originals}))
                )
                if set(current_inventory) != set(originals):
                    failures.append("provider inventory")
                else:
                    for key, original in originals.items():
                        current = current_inventory[key]
                        if (
                            canonical_document_fingerprint(current)
                            != canonical_document_fingerprint(original)
                            or current.writable != original.writable
                        ):
                            failures.append(f"{key[0]}/{key[1]}")
            except Exception:
                failures.append("provider inventory")
        else:
            for key, original in originals.items():
                try:
                    current = self._providers[key[0]].get_document(key[1])
                    if (
                        canonical_document_fingerprint(current)
                        != canonical_document_fingerprint(original)
                        or current.writable != original.writable
                    ):
                        failures.append(f"{key[0]}/{key[1]}")
                except Exception:
                    failures.append(f"{key[0]}/{key[1]}")
        return tuple(dict.fromkeys(failures))

    def _replay_completed(self, plan: MigrationPlan) -> MigrationResult:
        completion = self._completed[plan.plan_id]
        try:
            self._assert_authority(plan)
            inventory = self._fetch_inventory(plan.providers)
            if _snapshots(inventory) != completion.documents:
                raise StaleMigrationPlan(
                    "Completed migration documents changed and cannot be replayed."
                )
            self._assert_post_apply(plan, inventory)
        except Exception as err:
            self._states[plan.plan_id] = MigrationState.BLOCKED
            if isinstance(err, StaleMigrationPlan):
                raise
            raise StaleMigrationPlan(
                f"Completed migration verification failed: {err}"
            ) from err
        return replace(completion.result, idempotent=True)


class InMemoryReferenceProvider:
    """Small deterministic provider useful for isolated tests and prototypes."""

    def __init__(self, name: str, documents: Iterable[ReferenceDocument] = ()) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("An in-memory provider name is required.")
        self._name = name
        self._documents: dict[str, ReferenceDocument] = {}
        self._write_counts: dict[str, int] = {}
        for document in documents:
            self.put_document(document)

    @property
    def name(self) -> str:
        return self._name

    def list_documents(self) -> Sequence[ReferenceDocument]:
        return tuple(
            _copy_document(self._documents[object_id])
            for object_id in sorted(self._documents)
        )

    def get_document(self, object_id: str) -> ReferenceDocument:
        try:
            return _copy_document(self._documents[object_id])
        except KeyError as err:
            raise KeyError(f"Unknown reference document: {object_id}.") from err

    def put_document(self, document: ReferenceDocument) -> None:
        """Insert or externally replace a document, including its revision."""

        if not isinstance(document, ReferenceDocument):
            raise TypeError("Only ReferenceDocument instances can be stored.")
        if document.provider != self.name:
            raise ValueError("The document belongs to a different provider.")
        self._documents[document.object_id] = _copy_document(document)

    def write_document(
        self,
        object_id: str,
        *,
        expected_revision: Revision,
        payload: Any,
    ) -> ReferenceDocument:
        current = self.get_document(object_id)
        if current.revision != expected_revision:
            raise StaleMigrationPlan(
                f"Document {self.name}/{object_id} changed revision."
            )
        if not current.writable:
            raise ReferenceMigrationError(
                f"Document {self.name}/{object_id} is not writable."
            )
        _validate_payload(payload)
        write_count = self._write_counts.get(object_id, 0) + 1
        self._write_counts[object_id] = write_count
        if isinstance(current.revision, int):
            revision: Revision = current.revision + 1
        else:
            revision = f"{current.revision}@{write_count}"
        updated = ReferenceDocument(
            provider=self.name,
            object_id=object_id,
            revision=revision,
            payload=deepcopy(payload),
            writable=current.writable,
        )
        self._documents[object_id] = updated
        return _copy_document(updated)


class InMemoryMigrationAuthority:
    """Mutable server-authority stand-in for deterministic offline tests."""

    def __init__(self, subjects: Iterable[MigrationSubject] = ()) -> None:
        self._subjects: dict[str, MigrationSubject] = {}
        for subject in subjects:
            self.put_subject(subject)

    def put_subject(self, subject: MigrationSubject) -> None:
        if not isinstance(subject, MigrationSubject):
            raise TypeError("Only migration subjects can be authoritative.")
        self._subjects[subject.room_id] = subject

    def resolve_subject(self, room_id: str) -> MigrationSubject:
        try:
            return self._subjects[room_id]
        except KeyError as err:
            raise KeyError(f"Unknown migration room: {room_id}.") from err


class InMemoryReferenceJournal:
    """Stateful journal for deterministic tests and disposable prototypes."""

    def __init__(self) -> None:
        self._states: dict[str, tuple[MigrationState, str | None]] = {}
        self._originals: dict[str, list[JournaledOriginal]] = {}
        self._completions: dict[str, JournaledCompletion] = {}

    def record_original(
        self,
        plan_id: str,
        document: ReferenceDocument,
        post_fingerprint: str,
    ) -> None:
        if not isinstance(plan_id, str) or not plan_id:
            raise ValueError("A journal plan ID is required.")
        if not isinstance(document, ReferenceDocument):
            raise TypeError("A journal original must be a reference document.")
        if not isinstance(post_fingerprint, str) or not post_fingerprint:
            raise ValueError("A journal postimage fingerprint is required.")
        entry = JournaledOriginal(_copy_document(document), post_fingerprint)
        originals = self._originals.setdefault(plan_id, [])
        for existing in originals:
            if (
                existing.document.provider == document.provider
                and existing.document.object_id == document.object_id
            ):
                if existing == entry:
                    return
                raise ValueError("A journal original changed across migration attempts.")
        originals.append(entry)

    def set_state(
        self,
        plan_id: str,
        state: MigrationState,
        reason: str | None = None,
    ) -> None:
        if not isinstance(plan_id, str) or not plan_id:
            raise ValueError("A journal plan ID is required.")
        if not isinstance(state, MigrationState):
            raise TypeError("A journal migration state is required.")
        if reason is not None and not isinstance(reason, str):
            raise TypeError("A journal reason must be a string.")
        self._states[plan_id] = (state, reason)

    def incomplete_plan_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                plan_id
                for plan_id, (state, _reason) in self._states.items()
                if state in {MigrationState.APPLYING, MigrationState.BLOCKED}
            )
        )

    def originals_for(self, plan_id: str) -> tuple[JournaledOriginal, ...]:
        """Return immutable copies of originals recorded for one plan."""

        return tuple(
            JournaledOriginal(
                _copy_document(entry.document),
                entry.post_fingerprint,
            )
            for entry in self._originals.get(plan_id, ())
        )

    def state(self, plan_id: str) -> tuple[MigrationState, str | None] | None:
        """Return one persisted state for assertions and recovery tooling."""

        return self._states.get(plan_id)

    def record_completion(self, completion: JournaledCompletion) -> None:
        plan_id = completion.plan.plan_id if isinstance(completion, JournaledCompletion) else ""
        _validate_journaled_completion(completion, plan_id)
        existing = self._completions.get(completion.plan.plan_id)
        if existing is not None and existing != completion:
            raise ValueError("A journal completion changed across writes.")
        self._completions[completion.plan.plan_id] = completion

    def completed_plan_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                plan_id
                for plan_id, (state, _reason) in self._states.items()
                if state is MigrationState.COMPLETE
                and plan_id in self._completions
            )
        )

    def completion_for(self, plan_id: str) -> JournaledCompletion:
        try:
            return self._completions[plan_id]
        except KeyError as err:
            raise KeyError(f"Unknown completed migration: {plan_id}.") from err


def _validate_journaled_completion(
    completion: JournaledCompletion,
    expected_plan_id: str,
) -> None:
    if not isinstance(completion, JournaledCompletion):
        raise TypeError("The reference completion journal is malformed.")
    plan = completion.plan
    result = completion.result
    if not isinstance(plan, MigrationPlan) or not isinstance(result, MigrationResult):
        raise TypeError("The reference completion journal is malformed.")
    if plan.plan_id != expected_plan_id or result.plan_id != expected_plan_id:
        raise TypeError("The reference completion journal has mismatched plan IDs.")
    if tuple(plan.providers) != tuple(sorted(TRUE_FAMILY_PROVIDER_MANIFEST)):
        raise TypeError("The completed plan has an incomplete provider manifest.")
    if set(dict(plan.provider_targets)) != set(TRUE_FAMILY_PROVIDER_MANIFEST):
        raise TypeError("The completed plan has incomplete provider targets.")
    if len({(item.provider, item.object_id) for item in plan.documents}) != len(
        plan.documents
    ):
        raise TypeError("The completed plan contains duplicate documents.")
    if any(item.provider not in TRUE_FAMILY_PROVIDER_MANIFEST for item in plan.documents):
        raise TypeError("The completed plan contains an unknown provider.")
    digest_payload = {
        "schema": 1,
        "room_id": plan.room_id,
        "room_revision": plan.room_revision,
        "old_entity_id": plan.old_entity_id,
        "logical_unique_id": plan.logical_unique_id,
        "target_entity_id": plan.target_entity_id,
        "provider_targets": dict(plan.provider_targets),
        "providers": list(plan.providers),
        "references_expected": plan.references_expected,
        "documents": [
            {
                "provider": document.provider,
                "object_id": document.object_id,
                "revision": _canonical_revision(document.revision),
                "writable": document.writable,
                "fingerprint": document.fingerprint,
                "post_fingerprint": document.post_fingerprint,
                "exact_paths": [
                    _canonical_path(path) for path in document.exact_paths
                ],
            }
            for document in plan.documents
        ],
    }
    expected_digest = hashlib.sha256(_canonical_json(digest_payload)).hexdigest()
    expected_id_hash = hashlib.sha256(
        f"reference-plan:{expected_digest}".encode()
    ).hexdigest()
    if plan.digest != expected_digest or plan.plan_id != (
        f"tf-reference-{expected_id_hash[:24]}"
    ):
        raise TypeError("The completed plan digest is invalid.")
    expected_changed = sum(bool(item.exact_paths) for item in plan.documents)
    if (
        result.digest != plan.digest
        or result.state is not MigrationState.COMPLETE
        or result.changed_documents != expected_changed
        or result.exact_replacements != plan.exact_replacements
        or result.idempotent
        or plan.exact_replacements
        != sum(len(item.exact_paths) for item in plan.documents)
    ):
        raise TypeError("The completed migration result is invalid.")
    snapshots = {
        (snapshot.provider, snapshot.object_id): snapshot
        for snapshot in completion.documents
    }
    if len(snapshots) != len(completion.documents) or set(snapshots) != {
        (item.provider, item.object_id) for item in plan.documents
    }:
        raise TypeError("The completed provider snapshots are incomplete.")
    for item in plan.documents:
        snapshot = snapshots[(item.provider, item.object_id)]
        if (
            snapshot.fingerprint != item.post_fingerprint
            or snapshot.writable != item.writable
        ):
            raise TypeError("A completed provider snapshot is invalid.")


def _validate_payload(payload: Any) -> None:
    if type(payload) not in (dict, list):
        raise MalformedReferenceDocumentError(
            "The payload root must be a built-in dict or list."
        )
    ancestors: set[int] = set()

    def validate(value: Any, depth: int = 0) -> None:
        if depth > 100:
            raise MalformedReferenceDocumentError(
                "Reference payload nesting exceeds the supported limit."
            )
        if type(value) is dict:
            identity = id(value)
            if identity in ancestors:
                raise MalformedReferenceDocumentError(
                    "Cyclic mappings/lists are not supported."
                )
            ancestors.add(identity)
            for key, item in value.items():
                if not isinstance(key, str):
                    raise MalformedReferenceDocumentError(
                        "Mapping keys must be strings."
                    )
                validate(item, depth + 1)
            ancestors.remove(identity)
            return
        if type(value) is list:
            identity = id(value)
            if identity in ancestors:
                raise MalformedReferenceDocumentError(
                    "Cyclic mappings/lists are not supported."
                )
            ancestors.add(identity)
            for item in value:
                validate(item, depth + 1)
            ancestors.remove(identity)
            return
        if value is None or type(value) in (str, bool, int):
            return
        if type(value) is float and math.isfinite(value):
            return
        raise MalformedReferenceDocumentError(
            f"Unsupported payload value type: {type(value).__name__}."
        )

    validate(payload)


def _normalize_provider_targets(
    provider_names: tuple[str, ...],
    target_entity_id: str | None,
    provider_targets: Mapping[str, str] | None,
) -> dict[str, str]:
    if provider_targets is not None:
        return {name: provider_targets[name] for name in provider_names}
    if target_entity_id is None:
        raise MigrationPlanningBlocked(("A migration target is required.",))
    return {name: target_entity_id for name in provider_names}


def _replace_exact_scalars(
    payload: Any,
    old_entity_id: str,
    target_entity_id: str,
    *,
    provider: str | None = None,
) -> tuple[Any, int]:
    _validate_payload(payload)
    return replace_semantic_references(
        payload,
        old_entity_id,
        target_entity_id,
        provider=provider,
    )


def _payload_fingerprint(payload: Any) -> str:
    _validate_payload(payload)
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _canonical_json(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as err:
        raise MalformedReferenceDocumentError(
            "The payload cannot be represented canonically."
        ) from err
    return rendered.encode("utf-8")


def _canonical_revision(revision: Revision) -> dict[str, Any]:
    return {
        "type": "integer" if isinstance(revision, int) else "string",
        "value": revision,
    }


def _canonical_path(path: ReferencePath) -> list[dict[str, Any]]:
    return [
        {
            "type": "index" if isinstance(part, int) else "key",
            "value": part,
        }
        for part in path
    ]


def _format_path(path: ReferencePath) -> str:
    if not path:
        return "$"
    rendered = "$"
    for part in path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f"[{json.dumps(part, ensure_ascii=True)}]"
    return rendered


def _copy_document(document: ReferenceDocument) -> ReferenceDocument:
    return ReferenceDocument(
        provider=document.provider,
        object_id=document.object_id,
        revision=document.revision,
        payload=deepcopy(document.payload),
        writable=document.writable,
    )


def _snapshots(
    inventory: dict[tuple[str, str], ReferenceDocument],
) -> tuple[_DocumentSnapshot, ...]:
    return tuple(
        _DocumentSnapshot(
            provider=document.provider,
            object_id=document.object_id,
            revision=document.revision,
            writable=document.writable,
            fingerprint=canonical_document_fingerprint(document),
        )
        for _key, document in sorted(inventory.items())
    )
