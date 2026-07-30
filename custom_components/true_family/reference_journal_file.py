"""Linux crash-durable canonical JSON store for reference journals.

Every supported writer uses the same persisted lock protocol and holds one
per-journal ``flock`` for its complete lifetime.  That serializes cooperating
backends across processes; inode-and-byte CAS then detects accidental drift.

Security boundary: the trusted config directory and its private 0700 child are
owned by the current effective UID/GID.  Code running as that same UID or as
root can ignore advisory locks or mutate the namespace and is deliberately out
of scope.  This is not cryptographic tamper resistance.  Process-crash tests
exercise kernel-visible recovery, not hardware power-loss behavior; production
mount metadata is only a prerequisite and never substitutes for external
power-cut certification of the exact deployed storage stack and persistence
primitive.  This phase can qualify only directly attached, non-composite ext4
and XFS block storage with complete stable identity and feature evidence.  A
finite transport/driver allowlist is authoritative; unknown or incomplete
hardware ancestry never falls back to a generic block-device claim.  Structural
model recognition is not hardware provenance and never replaces the mandatory
external power-cut certification.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import InitVar, dataclass
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import sys
import threading
from typing import TYPE_CHECKING, Any, Self, TypeVar, cast

if TYPE_CHECKING:
    from .reference_migration_ha import (
        ReferenceJournalDurabilityProof,
        ReferenceJournalTestDurabilityProof,
    )


REFERENCE_JOURNAL_DIRECTORY_NAME = "true_family_reference_journal"
DEFAULT_MAX_BYTES = 16 * 1024 * 1024
MAX_CONFIGURED_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
MAX_INTEGER_DIGITS = 128
MAX_JSON_STRING_BYTES = 4 * 1024 * 1024
MAX_JSON_TOKEN_BYTES = 1024

_PRODUCTION_FILESYSTEM_TYPES = frozenset({"ext4", "xfs"})
_PRODUCTION_POLICY_ID = "sealed-nvme-ext4-xfs-linux-v7"
_LOCK_PROTOCOL_ID = "true-family/reference-journal-lifetime-flock/v1"
_LOCK_PROTOCOL_PROOF_ID = "flock-v1"
PERSISTENCE_PRIMITIVE_ID = (
    "true-family/reference-journal/"
    "temp-write+file-fsync+atomic-same-directory-replace+"
    "directory-fsync+reopen-verification/v1"
)
_PRODUCTION_POLICY_SEAL = object()
_TEST_POLICY_SEAL = object()
_PRODUCTION_CERTIFICATION_SEAL = object()
_TEST_CERTIFICATION_SEAL = object()
_CERTIFICATION_SCHEMA = "true-family/durable-filesystem-certification/v6"
_FILESYSTEM_TYPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.+-]{0,63}$")
_DEVICE_PATTERN = re.compile(r"^[0-9]+:[0-9]+$")
_JOURNAL_BASENAME_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CERTIFICATION_AUTHORITY_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9._/+:-]{0,94}[a-z0-9])?$"
)
_CERTIFICATION_REPORT_SUBJECT_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9._/+:-]{0,126}[a-z0-9])?$"
)
_CERTIFICATION_PRIMITIVE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9._/+:-]{0,159}$"
)
_MOUNT_OPTION_PATTERN = re.compile(r"^[^,\x00-\x20\x7f]+$")
_READ_CHUNK_SIZE = 128 * 1024
_MOUNTINFO_MAX_BYTES = 8 * 1024 * 1024
_FDINFO_MAX_BYTES = 64 * 1024
_SYSFS_VALUE_MAX_BYTES = 16 * 1024
_SYSFS_STABLE_UEVENT_KEYS = frozenset(
    {
        "DEVNAME",
        "DEVTYPE",
        "MAJOR",
        "MINOR",
        "PARTNAME",
        "PARTN",
        "PARTUUID",
    }
)
_SYSFS_NODE_FIELDS = (
    "alignment_offset",
    "dev",
    "discard_alignment",
    "partition",
    "removable",
    "ro",
    "size",
    "start",
)
_SYSFS_DEVICE_IDENTITY_FIELDS = (
    "device/device/vendor",
    "device/firmware_rev",
    "device/model",
    "device/serial",
    "device/subsysnqn",
    "device/transport",
    "device/wwid",
    "eui",
    "wwid",
)
_SYSFS_QUEUE_FIELDS = (
    "queue/add_random",
    "queue/atomic_write_boundary_bytes",
    "queue/atomic_write_max_bytes",
    "queue/atomic_write_unit_max_bytes",
    "queue/atomic_write_unit_min_bytes",
    "queue/chunk_sectors",
    "queue/dax",
    "queue/discard_granularity",
    "queue/discard_max_bytes",
    "queue/discard_max_hw_bytes",
    "queue/discard_zeroes_data",
    "queue/dma_alignment",
    "queue/fua",
    "queue/hw_sector_size",
    "queue/io_poll",
    "queue/io_poll_delay",
    "queue/io_timeout",
    "queue/logical_block_size",
    "queue/max_discard_segments",
    "queue/max_hw_sectors_kb",
    "queue/max_integrity_segments",
    "queue/max_sectors_kb",
    "queue/max_segment_size",
    "queue/max_segments",
    "queue/minimum_io_size",
    "queue/nomerges",
    "queue/nr_requests",
    "queue/optimal_io_size",
    "queue/physical_block_size",
    "queue/read_ahead_kb",
    "queue/rotational",
    "queue/rq_affinity",
    "queue/scheduler",
    "queue/stable_writes",
    "queue/virt_boundary_mask",
    "queue/write_cache",
    "queue/write_same_max_bytes",
    "queue/write_zeroes_max_bytes",
    "queue/write_zeroes_unmap_max_bytes",
    "queue/write_zeroes_unmap_max_hw_bytes",
    "queue/zoned",
    "queue/zone_append_max_bytes",
    "queue/zone_write_granularity",
)
_MANDATORY_QUEUE_FIELDS = frozenset(
    {
        "queue/discard_granularity",
        "queue/discard_max_bytes",
        "queue/fua",
        "queue/logical_block_size",
        "queue/max_hw_sectors_kb",
        "queue/max_sectors_kb",
        "queue/minimum_io_size",
        "queue/optimal_io_size",
        "queue/physical_block_size",
        "queue/rotational",
        "queue/stable_writes",
        "queue/write_cache",
        "queue/write_same_max_bytes",
        "queue/write_zeroes_max_bytes",
        "queue/zoned",
    }
)
# These models establish structural eligibility only.  Production proof still
# requires a matching externally issued power-cut certification record.
_DIRECT_TRANSPORT_MODELS = {
    "nvme-pcie-direct": {
        "allowed_driver_identities": frozenset(
            {
                "bus/pci/drivers/nvme",
                "bus/pci/drivers/pcieport",
                "bus/platform/drivers/brcm-pcie",
                "bus/platform/drivers/simple-pm-bus",
            }
        ),
        "allowed_subsystems": frozenset(
            {
                "bus/pci",
                "bus/platform",
                "class/block",
                "class/nvme",
                "class/nvme-subsystem",
            }
        ),
        "device_pattern": re.compile(r"^nvme[0-9]+n[0-9]+(?:p[0-9]+)?$"),
        "raw_transports": frozenset({"pcie"}),
        "required_driver_groups": (frozenset({"bus/pci/drivers/nvme"}),),
        "required_subsystems": frozenset(
            {"bus/pci", "class/block", "class/nvme"}
        ),
    },
}
_PROHIBITED_PROVENANCE_SIGNATURES = (
    "bochs",
    "emulat",
    "hyper-v",
    "hyperv",
    "hv_storvsc",
    "logical disk",
    "logical drive",
    "logical volume",
    "logical-volume",
    "lvm",
    "megaraid",
    "microsoft virtual",
    "msft virtual",
    "parallels",
    "perc",
    "qemu",
    "raid",
    "raid volume",
    "smart array",
    "vbox",
    "virtual",
    "virtual disk",
    "virtualbox",
    "virtio",
    "vmbus",
    "vmware",
    "xen",
)
_PROHIBITED_PROVENANCE_WORD_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:raid|emulated|emulation|virtual)(?:[^a-z0-9]|$)"
)
_PROHIBITED_PCI_VENDOR_IDS = frozenset(
    {
        "1234",  # QEMU/Bochs
        "1414",  # Microsoft Hyper-V
        "15ad",  # VMware
        "1ab8",  # Parallels
        "1ae0",  # Google virtual devices
        "1af4",  # virtio
        "1b36",  # QEMU
        "1d0f",  # Amazon virtual devices
        "5853",  # XenSource
        "80ee",  # VirtualBox
    }
)
_PCI_MODALIAS_VENDOR_PATTERN = re.compile(r"pci:v(?:0000)?([0-9a-f]{4})")
_PCI_ID_PATTERN = re.compile(r"^0x[0-9a-f]{4}$")
_PCI_REVISION_PATTERN = re.compile(r"^0x[0-9a-f]{2}$")
_STABLE_ALIAS_DIRECTORIES = (
    ("by-id", "/dev/disk/by-id"),
    ("by-partuuid", "/dev/disk/by-partuuid"),
    ("by-uuid", "/dev/disk/by-uuid"),
)
_FILESYSTEM_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_UNSAFE_MOUNT_OPTIONS = frozenset(
    {
        "barrier=0",
        "data=writeback",
        "dax",
        "journal_dev",
        "lazytime",
        "logdev",
        "nobarrier",
        "noload",
        "nologreplay",
        "norecovery",
        "ro",
        "rtdev",
        "sb",
        "volatile",
    }
)
_EXT4_HAS_JOURNAL = 0x4
_EXT4_JOURNAL_DEV = 0x8
_EXT4_FEATURE_INCOMPAT_EXTENTS = 0x40
_EXT4_FEATURE_INCOMPAT_64BIT = 0x80
_EXT4_SUPPORTED_FEATURE_COMPAT = 0x4 | 0x8 | 0x10 | 0x20
_EXT4_SUPPORTED_FEATURE_INCOMPAT = 0x2 | 0x4 | 0x40 | 0x80 | 0x200
_EXT4_SUPPORTED_FEATURE_RO_COMPAT = 0x1 | 0x2 | 0x8 | 0x20 | 0x40
_EXT4_EXTENTS_INODE_FLAG = 0x00080000
_EXT4_EXTENT_MAGIC = 0xF30A
_EXT4_MAX_EXTENT_DEPTH = 2
_EXT4_MAX_EXTENT_NODES = 8
_EXT4_MAX_EXTENTS = 64
_EXT4_MAX_METADATA_READS = 16
_EXT4_MAX_JOURNAL_BYTES = 1 << 30
_JBD2_MAGIC = 0xC03B3998
_JBD2_SUPERBLOCK_V2 = 4
_JBD2_FEATURE_INCOMPAT_CSUM_V2 = 0x8
_JBD2_FEATURE_INCOMPAT_CSUM_V3 = 0x10
_JBD2_FEATURE_INCOMPAT_FAST_COMMIT = 0x20
_JBD2_SUPPORTED_FEATURE_INCOMPAT = 0x3F
_JBD2_CHECKSUM_TYPE_CRC32C = 4
_JBD2_MIN_JOURNAL_BLOCKS = 1024
_JBD2_IDENTITY_FIELDS = frozenset(
    {
        "block_size",
        "block_type",
        "checksum_semantics",
        "checksum_type",
        "dynamic_superblock",
        "fast_commit_blocks",
        "feature_compat",
        "feature_incompat",
        "feature_ro_compat",
        "first",
        "journal_superblock_bytes",
        "magic",
        "maximum_length",
        "maximum_transaction",
        "maximum_transaction_data",
        "normal_blocks",
        "users",
        "users_count",
        "uuid",
    }
)
_NETWORK_FILESYSTEM_TYPES = frozenset(
    {
        "9p",
        "afs",
        "ceph",
        "cifs",
        "davfs",
        "gcsfuse",
        "glusterfs",
        "lustre",
        "nfs",
        "nfs4",
        "smb3",
        "sshfs",
    }
)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW
_READ_FILE_FLAGS = os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK
_WRITE_FILE_FLAGS = os.O_RDWR | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK

# Indirections are intentionally module-local so tests can inject short writes,
# EINTR, and persistence failures without replacing process-wide ``os`` calls.
_raw_read = os.read
_raw_write = os.write
_raw_fsync = os.fsync
_raw_replace = os.replace
_raw_temp_close = os.close

_FORK_CONDITION = threading.Condition(threading.RLock())
_FORK_ACTIVE_OPERATIONS = 0
_FORK_REQUESTED = False
_FORK_TRACKING_LOCK = threading.RLock()
_FORK_TRACKED_RESOURCES: dict[int, Any] = {}


class _ForkSafeOperationGate:
    def __enter__(self) -> None:
        global _FORK_ACTIVE_OPERATIONS

        with _FORK_CONDITION:
            while _FORK_REQUESTED:
                _FORK_CONDITION.wait()
            _FORK_ACTIVE_OPERATIONS += 1

    def __exit__(self, *_args: Any) -> None:
        global _FORK_ACTIVE_OPERATIONS

        with _FORK_CONDITION:
            _FORK_ACTIVE_OPERATIONS -= 1
            if _FORK_ACTIVE_OPERATIONS == 0:
                _FORK_CONDITION.notify_all()


_FORK_OPERATION_LOCK = _ForkSafeOperationGate()


def _before_fork() -> None:
    global _FORK_REQUESTED

    _FORK_CONDITION.acquire()
    _FORK_REQUESTED = True
    while _FORK_ACTIVE_OPERATIONS:
        _FORK_CONDITION.wait()
    _FORK_TRACKING_LOCK.acquire()


def _after_fork_parent() -> None:
    global _FORK_REQUESTED

    _FORK_TRACKING_LOCK.release()
    _FORK_REQUESTED = False
    _FORK_CONDITION.notify_all()
    _FORK_CONDITION.release()


def _after_fork_child() -> None:
    global _FORK_ACTIVE_OPERATIONS, _FORK_REQUESTED

    for resources in tuple(_FORK_TRACKED_RESOURCES.values()):
        try:
            resources._close_in_fork_child()
        except BaseException:
            pass
    _FORK_TRACKED_RESOURCES.clear()
    _FORK_TRACKING_LOCK.release()
    _FORK_ACTIVE_OPERATIONS = 0
    _FORK_REQUESTED = False
    _FORK_CONDITION.notify_all()
    _FORK_CONDITION.release()


os.register_at_fork(
    before=_before_fork,
    after_in_parent=_after_fork_parent,
    after_in_child=_after_fork_child,
)

FailpointCallback = Callable[[str], None]


class ReferenceJournalFileError(RuntimeError):
    """Base class for every fail-closed file backend error."""


class ReferenceJournalBusyError(ReferenceJournalFileError):
    """Raised when another backend owns the journal lock."""


class ReferenceJournalCorruptionError(ReferenceJournalFileError):
    """Raised when durable bytes are malformed or noncanonical."""


class ReferenceJournalSecurityError(ReferenceJournalCorruptionError):
    """Raised when a path or inode violates the trusted-file policy."""


class ReferenceJournalUnsupportedFilesystemError(ReferenceJournalFileError):
    """Raised when the filesystem cannot provide the claimed guarantees."""


class ReferenceJournalCertificationError(
    ReferenceJournalUnsupportedFilesystemError
):
    """Raised when external power-cut certification is absent or mismatched."""


class ReferenceJournalConflictError(ReferenceJournalFileError):
    """Raised when generation or exact inode-and-byte CAS fails."""


class ReferenceJournalProtocolError(ReferenceJournalFileError):
    """Raised when load, save, and barrier ordering is invalid."""


class ReferenceJournalIOError(ReferenceJournalFileError):
    """Raised for an operating-system failure not safely treated as absence."""


class ReferenceJournalPoisonedError(ReferenceJournalFileError):
    """Raised after a failed save makes this object unusable."""


class ReferenceJournalAmbiguousDurabilityError(ReferenceJournalPoisonedError):
    """Raised when failure occurs after atomic replacement may have happened."""


class ReferenceJournalClosedError(ReferenceJournalFileError):
    """Raised when new work is submitted after closing begins."""


class ReferenceJournalForkError(ReferenceJournalSecurityError):
    """Raised when an inherited backend is used by a fork child."""


@dataclass(frozen=True, slots=True)
class DurableFilesystemPolicy:
    """Sealed direct-ext4/XFS policy or explicitly branded test-only policy."""

    allowed_filesystem_types: frozenset[str]
    policy_id: str
    test_only: bool
    _seal: InitVar[object]

    def __post_init__(self, _seal: object) -> None:
        expected_seal = (
            _TEST_POLICY_SEAL if self.test_only else _PRODUCTION_POLICY_SEAL
        )
        if _seal is not expected_seal:
            raise TypeError(
                "Use the sealed production policy or for_test_filesystems()."
            )
        if type(self.allowed_filesystem_types) is not frozenset:
            raise TypeError("Filesystem policy must use an immutable frozenset.")
        if any(
            type(item) is not str or not _FILESYSTEM_TYPE_PATTERN.fullmatch(item)
            for item in self.allowed_filesystem_types
        ):
            raise ValueError("Filesystem policy contains a noncanonical type.")
        if (
            type(self.policy_id) is not str
            or not self.policy_id
            or len(self.policy_id) > 48
            or not _MOUNT_OPTION_PATTERN.fullmatch(self.policy_id)
        ):
            raise ValueError("Filesystem policy identity is noncanonical.")
        if not self.test_only and (
            self.policy_id != _PRODUCTION_POLICY_ID
            or self.allowed_filesystem_types != _PRODUCTION_FILESYSTEM_TYPES
        ):
            raise TypeError("The production filesystem policy is sealed.")

    @classmethod
    def for_test_filesystems(
        cls,
        allowed_filesystem_types: frozenset[str],
    ) -> DurableFilesystemPolicy:
        """Create an explicit test-only policy that can never be the default."""

        if type(allowed_filesystem_types) is not frozenset:
            raise TypeError("Test filesystem policy requires an immutable frozenset.")
        digest = hashlib.sha256(
            ",".join(sorted(allowed_filesystem_types)).encode("ascii")
        ).hexdigest()[:16]
        return cls(
            allowed_filesystem_types=allowed_filesystem_types,
            policy_id=f"test-only-{digest}",
            test_only=True,
            _seal=_TEST_POLICY_SEAL,
        )

    def allows(self, filesystem_type: str) -> bool:
        """Return whether one exact mount type is explicitly audited."""

        return filesystem_type in self.allowed_filesystem_types


# This allowlist only rejects known-ineligible mounts.  It cannot itself make a
# hardware power-loss claim; production also requires an exact external record.
_SEALED_PRODUCTION_DURABLE_FILESYSTEM_POLICY = DurableFilesystemPolicy(
    allowed_filesystem_types=_PRODUCTION_FILESYSTEM_TYPES,
    policy_id=_PRODUCTION_POLICY_ID,
    test_only=False,
    _seal=_PRODUCTION_POLICY_SEAL,
)
PRODUCTION_DURABLE_FILESYSTEM_POLICY = (
    _SEALED_PRODUCTION_DURABLE_FILESYSTEM_POLICY
)


def _certification_digest(
    *,
    certification_authority_identity: str,
    certification_report_identity: str,
    mount_binding_digest: str,
    deployed_storage_stack_digest: str,
    power_cut_report_digest: str,
    covered_persistence_primitive: str,
    test_only: bool,
) -> str:
    raw = json.dumps(
        {
            "certification_authority_identity": certification_authority_identity,
            "certification_report_identity": certification_report_identity,
            "covered_persistence_primitive": covered_persistence_primitive,
            "deployed_storage_stack_digest": deployed_storage_stack_digest,
            "grade": "test-only" if test_only else "external-production",
            "mount_binding_digest": mount_binding_digest,
            "power_cut_report_digest": power_cut_report_digest,
            "schema": _CERTIFICATION_SCHEMA,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class DurableFilesystemCertification:
    """Immutable external evidence binding one exact power-cut-tested stack.

    The production factory validates a caller-supplied external record; it does
    not issue, discover, or infer certification.  The digest is an integrity
    binding, not an authority signature.  Trust in the named external authority
    remains an explicit deployment decision made by the integration wiring.
    """

    certification_authority_identity: str
    certification_report_identity: str
    mount_binding_digest: str
    deployed_storage_stack_digest: str
    power_cut_report_digest: str
    covered_persistence_primitive: str
    certification_digest: str
    test_only: bool
    _seal: InitVar[object]

    def __post_init__(self, _seal: object) -> None:
        if type(self.test_only) is not bool:
            raise TypeError("Certification grade must be a built-in bool.")
        expected_seal = (
            _TEST_CERTIFICATION_SEAL
            if self.test_only
            else _PRODUCTION_CERTIFICATION_SEAL
        )
        if _seal is not expected_seal:
            raise TypeError(
                "Use from_external_power_cut_report() or for_test_evidence()."
            )
        if (
            type(self.certification_authority_identity) is not str
            or not _CERTIFICATION_AUTHORITY_PATTERN.fullmatch(
                self.certification_authority_identity
            )
        ):
            raise ValueError("Certification authority identity is noncanonical.")
        report_identity = self.certification_report_identity
        if type(report_identity) is not str:
            raise TypeError(
                "Certification report identity must be a built-in string."
            )
        report_subject, separator, embedded_report_digest = report_identity.rpartition(
            "@sha256:"
        )
        if (
            separator != "@sha256:"
            or not _CERTIFICATION_REPORT_SUBJECT_PATTERN.fullmatch(report_subject)
            or not report_subject.startswith(
                f"{self.certification_authority_identity}/"
            )
        ):
            raise ValueError("Certification report identity is noncanonical.")
        for label, value in (
            ("mount binding", self.mount_binding_digest),
            ("deployed storage stack", self.deployed_storage_stack_digest),
            ("power-cut report", self.power_cut_report_digest),
            ("certification", self.certification_digest),
        ):
            if type(value) is not str or not _DIGEST_PATTERN.fullmatch(value):
                raise ValueError(f"{label.capitalize()} digest is noncanonical.")
        if embedded_report_digest != self.power_cut_report_digest:
            raise ValueError(
                "Certification report identity does not bind its report digest."
            )
        if (
            type(self.covered_persistence_primitive) is not str
            or not _CERTIFICATION_PRIMITIVE_PATTERN.fullmatch(
                self.covered_persistence_primitive
            )
        ):
            raise ValueError("Covered persistence primitive is noncanonical.")
        if self.test_only:
            if not self.certification_authority_identity.startswith("test-only/"):
                raise TypeError("Test certification must be visibly test-only.")
        elif self.certification_authority_identity.startswith("test-only/"):
            raise TypeError("Production certification cannot use a test authority.")
        expected_digest = _certification_digest(
            certification_authority_identity=self.certification_authority_identity,
            certification_report_identity=self.certification_report_identity,
            mount_binding_digest=self.mount_binding_digest,
            deployed_storage_stack_digest=self.deployed_storage_stack_digest,
            power_cut_report_digest=self.power_cut_report_digest,
            covered_persistence_primitive=self.covered_persistence_primitive,
            test_only=self.test_only,
        )
        if self.certification_digest != expected_digest:
            raise ValueError("Certification digest does not bind the exact record.")

    @classmethod
    def from_external_power_cut_report(
        cls,
        *,
        certification_authority_identity: str,
        certification_report_identity: str,
        mount_binding_digest: str,
        deployed_storage_stack_digest: str,
        power_cut_report_digest: str,
        covered_persistence_primitive: str,
        certification_digest: str,
    ) -> DurableFilesystemCertification:
        """Validate, without issuing, one externally supplied production record."""

        return cls(
            certification_authority_identity=certification_authority_identity,
            certification_report_identity=certification_report_identity,
            mount_binding_digest=mount_binding_digest,
            deployed_storage_stack_digest=deployed_storage_stack_digest,
            power_cut_report_digest=power_cut_report_digest,
            covered_persistence_primitive=covered_persistence_primitive,
            certification_digest=certification_digest,
            test_only=False,
            _seal=_PRODUCTION_CERTIFICATION_SEAL,
        )

    @classmethod
    def for_test_evidence(
        cls,
        *,
        mount_binding_digest: str,
        deployed_storage_stack_digest: str,
        covered_persistence_primitive: str = PERSISTENCE_PRIMITIVE_ID,
    ) -> DurableFilesystemCertification:
        """Create synthetic evidence permanently branded for tests only."""

        authority = "test-only/local-harness"
        report_digest = hashlib.sha256(
            json.dumps(
                {
                    "covered_persistence_primitive": covered_persistence_primitive,
                    "deployed_storage_stack_digest": deployed_storage_stack_digest,
                    "mount_binding_digest": mount_binding_digest,
                },
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
        report_identity = (
            f"{authority}/synthetic-power-cut-report@sha256:{report_digest}"
        )
        digest = _certification_digest(
            certification_authority_identity=authority,
            certification_report_identity=report_identity,
            mount_binding_digest=mount_binding_digest,
            deployed_storage_stack_digest=deployed_storage_stack_digest,
            power_cut_report_digest=report_digest,
            covered_persistence_primitive=covered_persistence_primitive,
            test_only=True,
        )
        return cls(
            certification_authority_identity=authority,
            certification_report_identity=report_identity,
            mount_binding_digest=mount_binding_digest,
            deployed_storage_stack_digest=deployed_storage_stack_digest,
            power_cut_report_digest=report_digest,
            covered_persistence_primitive=covered_persistence_primitive,
            certification_digest=digest,
            test_only=True,
            _seal=_TEST_CERTIFICATION_SEAL,
        )


@dataclass(frozen=True, slots=True)
class _MountRecord:
    mount_id: int
    parent_mount_id: int
    device: str
    root: str
    mount_point: str
    mount_options: tuple[str, ...]
    optional_fields: tuple[str, ...]
    filesystem_type: str
    mount_source: str
    super_options: tuple[str, ...]

    @property
    def canonical_data(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "filesystem_type": self.filesystem_type,
            "mount_id": self.mount_id,
            "mount_options": list(self.mount_options),
            "mount_point": self.mount_point,
            "mount_source": self.mount_source,
            "optional_fields": list(self.optional_fields),
            "parent_mount_id": self.parent_mount_id,
            "root": self.root,
            "super_options": list(self.super_options),
        }


@dataclass(frozen=True, slots=True)
class _FilesystemIdentity:
    descriptor_path: str
    record: _MountRecord

    @property
    def filesystem_type(self) -> str:
        return self.record.filesystem_type

    @property
    def device(self) -> str:
        return self.record.device

    @property
    def mount_point(self) -> str:
        return self.record.mount_point

    @property
    def mount_id(self) -> int:
        return self.record.mount_id

    @property
    def root(self) -> str:
        return self.record.root


@dataclass(frozen=True, slots=True)
class _Snapshot:
    raw: bytes | None
    device: int | None
    inode: int | None
    generation: int | None

    @classmethod
    def absent(cls) -> _Snapshot:
        return cls(raw=None, device=None, inode=None, generation=None)


@dataclass(frozen=True, slots=True)
class _ReadResult:
    data: dict[str, Any]
    snapshot: _Snapshot


@dataclass(frozen=True, slots=True)
class _CommitStamp:
    snapshot: _Snapshot
    sequence: int


@dataclass(slots=True, eq=False)
class _OpenedResources:
    config_fd: int
    directory_fd: int
    lock_fd: int
    filesystem: _FilesystemIdentity
    mount_binding_digest: str
    block_stack_binding_digest: str | None
    config_identity: tuple[int, int]
    directory_identity: tuple[int, int]
    lock_identity: tuple[int, int]
    transient_temp_fd: int = -1
    forked_child: bool = False

    def _close_in_fork_child(self) -> None:
        for attribute in (
            "transient_temp_fd",
            "config_fd",
            "directory_fd",
            "lock_fd",
        ):
            descriptor = cast(int, getattr(self, attribute))
            setattr(self, attribute, -1)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self.forked_child = True


_T = TypeVar("_T")


def reference_journal_basename(journal_id: str) -> str:
    """Return the fixed-width SHA-256 basename for an opaque journal ID."""

    if (
        type(journal_id) is not str
        or not journal_id
        or len(journal_id) > 255
        or journal_id != journal_id.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in journal_id)
    ):
        raise ValueError(
            "Journal ID must be trimmed non-empty text without control characters."
        )
    try:
        encoded = journal_id.encode("utf-8")
    except UnicodeEncodeError as err:
        raise ValueError("Journal ID must be valid Unicode text.") from err
    basename = hashlib.sha256(encoded).hexdigest()
    if not _JOURNAL_BASENAME_PATTERN.fullmatch(basename):
        raise AssertionError("SHA-256 returned a noncanonical digest.")
    return basename


def _file_names(journal_id: str) -> tuple[str, str, str]:
    basename = reference_journal_basename(journal_id)
    return f"{basename}.json", f"{basename}.tmp", f"{basename}.lock"


def _lock_protocol_bytes(journal_id: str) -> bytes:
    return json.dumps(
        {
            "journal_basename": reference_journal_basename(journal_id),
            "protocol": _LOCK_PROTOCOL_ID,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _track_resources(resources: _OpenedResources) -> None:
    with _FORK_TRACKING_LOCK:
        _FORK_TRACKED_RESOURCES[id(resources)] = resources


def _untrack_resources(resources: _OpenedResources) -> None:
    with _FORK_TRACKING_LOCK:
        _FORK_TRACKED_RESOURCES.pop(id(resources), None)


def _retry_eintr(function: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    while True:
        try:
            return function(*args, **kwargs)
        except OSError as err:
            if err.errno != errno.EINTR:
                raise


def _hit(failpoint: FailpointCallback | None, name: str) -> None:
    if failpoint is not None:
        failpoint(name)


def _fsync_boundary(
    descriptor: int,
    failpoint: FailpointCallback | None,
    name: str,
) -> None:
    _hit(failpoint, f"before_{name}")
    _retry_eintr(_raw_fsync, descriptor)
    _hit(failpoint, f"after_{name}")


def _mode(value: os.stat_result) -> int:
    return stat.S_IMODE(value.st_mode)


def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _validate_config_directory(value: os.stat_result) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise ReferenceJournalSecurityError(
            "The trusted config path is not a directory."
        )
    if value.st_uid != os.geteuid() or value.st_gid != os.getegid():
        raise ReferenceJournalSecurityError(
            "The trusted config directory has the wrong owner identity."
        )
    if _mode(value) & 0o022:
        raise ReferenceJournalSecurityError(
            "The trusted config directory is group- or world-writable."
        )


def _validate_store_directory(
    value: os.stat_result,
    *,
    config_device: int,
) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise ReferenceJournalSecurityError(
            "The reference journal child is not a directory."
        )
    if _mode(value) != 0o700:
        raise ReferenceJournalSecurityError(
            "The reference journal directory mode is not exactly 0700."
        )
    if value.st_uid != os.geteuid() or value.st_gid != os.getegid():
        raise ReferenceJournalSecurityError(
            "The reference journal directory has the wrong owner identity."
        )
    if value.st_dev != config_device:
        raise ReferenceJournalSecurityError(
            "The reference journal directory crosses a filesystem boundary."
        )


def _validate_regular_file(
    value: os.stat_result,
    *,
    directory_device: int,
    label: str,
) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise ReferenceJournalSecurityError(f"{label} is not a regular file.")
    if _mode(value) != 0o600:
        raise ReferenceJournalSecurityError(f"{label} mode is not exactly 0600.")
    if value.st_uid != os.geteuid() or value.st_gid != os.getegid():
        raise ReferenceJournalSecurityError(f"{label} has the wrong owner identity.")
    if value.st_nlink != 1:
        raise ReferenceJournalSecurityError(f"{label} must have exactly one link.")
    if value.st_dev != directory_device:
        raise ReferenceJournalSecurityError(
            f"{label} crosses the journal filesystem boundary."
        )


def _translate_os_error(message: str, err: OSError) -> ReferenceJournalFileError:
    if err.errno in {
        errno.EACCES,
        errno.ELOOP,
        errno.ENOTDIR,
        errno.EPERM,
    }:
        return ReferenceJournalSecurityError(message)
    if err.errno in {errno.ENOSYS, errno.EOPNOTSUPP}:
        return ReferenceJournalUnsupportedFilesystemError(message)
    return ReferenceJournalIOError(message)


def _decode_mount_field(value: bytes) -> str:
    output = bytearray()
    index = 0
    while index < len(value):
        if value[index] != 0x5C:
            output.append(value[index])
            index += 1
            continue
        if index + 3 >= len(value):
            raise ReferenceJournalUnsupportedFilesystemError(
                "Linux mount information contains a truncated escape."
            )
        digits = value[index + 1 : index + 4]
        if any(digit < 0x30 or digit > 0x37 for digit in digits):
            raise ReferenceJournalUnsupportedFilesystemError(
                "Linux mount information contains a non-octal escape."
            )
        output.append(int(digits, 8))
        index += 4
    return os.fsdecode(bytes(output))


def _read_proc_bytes(path: str, max_bytes: int, label: str) -> bytes:
    try:
        descriptor = _retry_eintr(
            os.open,
            path,
            os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW,
        )
    except OSError as err:
        raise ReferenceJournalUnsupportedFilesystemError(
            f"Linux {label} is unavailable."
        ) from err
    try:
        raw = bytearray()
        while True:
            try:
                chunk = _retry_eintr(_raw_read, descriptor, _READ_CHUNK_SIZE)
            except OSError as err:
                raise ReferenceJournalUnsupportedFilesystemError(
                    f"Linux {label} could not be read."
                ) from err
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise ReferenceJournalUnsupportedFilesystemError(
                    f"Linux {label} exceeds its safety bound."
                )
    finally:
        os.close(descriptor)
    return bytes(raw)


def _read_fdinfo_mount_id(descriptor: int) -> int:
    raw = _read_proc_bytes(
        f"/proc/self/fdinfo/{descriptor}",
        _FDINFO_MAX_BYTES,
        "file-descriptor mount information",
    )
    mount_ids: list[int] = []
    for line in raw.splitlines():
        if not line.startswith(b"mnt_id:"):
            continue
        value = line.partition(b":")[2].strip()
        if not value.isdigit():
            raise ReferenceJournalUnsupportedFilesystemError(
                "Linux fdinfo contains a noncanonical mount ID."
            )
        mount_ids.append(int(value))
    if len(mount_ids) != 1 or mount_ids[0] <= 0:
        raise ReferenceJournalUnsupportedFilesystemError(
            "Linux fdinfo does not contain one exact mount ID."
        )
    return mount_ids[0]


def _decode_ascii_mount_value(value: bytes, label: str) -> str:
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as err:
        raise ReferenceJournalUnsupportedFilesystemError(
            f"Linux mount {label} is not ASCII."
        ) from err
    if not decoded or any(ord(character) < 33 or ord(character) == 127 for character in decoded):
        raise ReferenceJournalUnsupportedFilesystemError(
            f"Linux mount {label} is noncanonical."
        )
    return decoded


def _mount_options(value: bytes, label: str) -> tuple[str, ...]:
    options = tuple(
        _decode_ascii_mount_value(item, label) for item in value.split(b",")
    )
    if not options or len(set(options)) != len(options) or any(
        not _MOUNT_OPTION_PATTERN.fullmatch(item) for item in options
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            f"Linux mount {label} is ambiguous or malformed."
        )
    return options


def _read_mountinfo() -> tuple[_MountRecord, ...]:
    raw = _read_proc_bytes(
        "/proc/self/mountinfo",
        _MOUNTINFO_MAX_BYTES,
        "mount information",
    )

    records: list[_MountRecord] = []
    mount_ids: set[int] = set()
    for line in raw.splitlines():
        separator = line.find(b" - ")
        if separator < 0:
            raise ReferenceJournalUnsupportedFilesystemError(
                "Linux mount information is malformed."
            )
        left = line[:separator].split()
        right = line[separator + 3 :].split()
        if len(left) < 6 or len(right) != 3:
            raise ReferenceJournalUnsupportedFilesystemError(
                "Linux mount information is incomplete."
            )
        if not left[0].isdigit() or not left[1].isdigit():
            raise ReferenceJournalUnsupportedFilesystemError(
                "Linux mount IDs are noncanonical."
            )
        mount_id = int(left[0])
        parent_mount_id = int(left[1])
        if mount_id <= 0 or parent_mount_id <= 0 or mount_id in mount_ids:
            raise ReferenceJournalUnsupportedFilesystemError(
                "Linux mount IDs are duplicate or invalid."
            )
        mount_ids.add(mount_id)
        device = _decode_ascii_mount_value(left[2], "device")
        filesystem_type = _decode_ascii_mount_value(right[0], "filesystem type")
        if not _DEVICE_PATTERN.fullmatch(device) or not _FILESYSTEM_TYPE_PATTERN.fullmatch(
            filesystem_type
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "Linux mount identity is noncanonical."
            )
        optional_fields = tuple(
            _decode_ascii_mount_value(item, "optional field") for item in left[6:]
        )
        records.append(
            _MountRecord(
                mount_id=mount_id,
                parent_mount_id=parent_mount_id,
                device=device,
                root=_decode_mount_field(left[3]),
                mount_point=_decode_mount_field(left[4]),
                mount_options=_mount_options(left[5], "options"),
                optional_fields=optional_fields,
                filesystem_type=filesystem_type,
                mount_source=_decode_mount_field(right[1]),
                super_options=_mount_options(right[2], "super options"),
            )
        )
    return tuple(records)


def _path_is_on_mount(path: str, mount_point: str) -> bool:
    if mount_point == "/":
        return path.startswith("/")
    return path == mount_point or path.startswith(f"{mount_point}/")


def _filesystem_identity_for_fd(
    descriptor: int,
    records: tuple[_MountRecord, ...] | None = None,
) -> _FilesystemIdentity:
    value = os.fstat(descriptor)
    device = f"{os.major(value.st_dev)}:{os.minor(value.st_dev)}"
    mount_id = _read_fdinfo_mount_id(descriptor)
    try:
        descriptor_path = os.readlink(f"/proc/self/fd/{descriptor}")
    except OSError as err:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The opened directory path cannot be proven through procfs."
        ) from err
    if not os.path.isabs(descriptor_path) or descriptor_path.endswith(" (deleted)"):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The opened directory has no stable absolute mount path."
        )
    selected_records = _read_mountinfo() if records is None else records
    exact = tuple(record for record in selected_records if record.mount_id == mount_id)
    if len(exact) != 1:
        raise ReferenceJournalUnsupportedFilesystemError(
            "No unique Linux mount record matches the fdinfo mount ID."
        )
    record = exact[0]
    if record.device != device or not _path_is_on_mount(
        descriptor_path, record.mount_point
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The fdinfo and mountinfo identities do not match the opened directory."
        )
    containing = tuple(
        candidate
        for candidate in selected_records
        if _path_is_on_mount(descriptor_path, candidate.mount_point)
    )
    longest_length = max(len(candidate.mount_point) for candidate in containing)
    longest = tuple(
        candidate
        for candidate in containing
        if len(candidate.mount_point) == longest_length
    )
    if len(longest) != 1 or longest[0].mount_id != mount_id:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The opened directory is covered by an ambiguous or unexpected nested mount."
        )
    return _FilesystemIdentity(descriptor_path=descriptor_path, record=record)


def _unsafe_mount_option(options: tuple[str, ...]) -> str | None:
    for option in options:
        name = option.split("=", 1)[0]
        if option in _UNSAFE_MOUNT_OPTIONS or name in _UNSAFE_MOUNT_OPTIONS:
            return option
    return None


def _qualify_filesystem(
    identity: _FilesystemIdentity,
    policy: DurableFilesystemPolicy,
) -> None:
    filesystem_type = identity.filesystem_type
    mount_options = identity.record.mount_options
    super_options = identity.record.super_options
    if "rw" not in mount_options or "ro" in mount_options or "ro" in super_options:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The journal filesystem mount is not read-write."
        )
    unsafe = _unsafe_mount_option(mount_options + super_options)
    if unsafe is not None:
        raise ReferenceJournalUnsupportedFilesystemError(
            f"The journal filesystem uses unsafe mount option {unsafe!r}."
        )
    if filesystem_type.startswith("fuse") or filesystem_type in _NETWORK_FILESYSTEM_TYPES:
        raise ReferenceJournalUnsupportedFilesystemError(
            "Network and FUSE filesystems cannot qualify for journal durability."
        )
    if not policy.allows(filesystem_type):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The journal filesystem type is not explicitly allowed."
        )


def _mount_binding_digest(
    identity: _FilesystemIdentity,
    policy: DurableFilesystemPolicy,
) -> str:
    raw = json.dumps(
        {
            "lock_protocol": _LOCK_PROTOCOL_ID,
            "mount": identity.record.canonical_data,
            "policy_id": policy.policy_id,
            "policy_test_only": policy.test_only,
            "scope": "lock-respecting-writers-only",
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _read_optional_sysfs_value(
    path: str,
    *,
    allow_newlines: bool = False,
) -> str | None:
    try:
        descriptor = _retry_eintr(
            os.open,
            path,
            os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW,
        )
    except OSError as err:
        if err.errno in {errno.ENOENT, errno.ENOTDIR}:
            return None
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack metadata could not be opened safely."
        ) from err
    try:
        raw = bytearray()
        while True:
            try:
                chunk = _retry_eintr(os.read, descriptor, 4096)
            except OSError as err:
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The live block-stack metadata could not be read safely."
                ) from err
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > _SYSFS_VALUE_MAX_BYTES:
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The live block-stack metadata exceeds its safety bound."
                )
    finally:
        os.close(descriptor)
    try:
        value = bytes(raw).decode("ascii").strip()
    except UnicodeDecodeError as err:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack metadata is not canonical ASCII."
        ) from err
    if not value or any(
        (ord(character) < 32 and not (allow_newlines and character == "\n"))
        or ord(character) == 127
        for character in value
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack metadata contains noncanonical text."
        )
    return value


def _sysfs_device_key(path: str) -> str:
    value = _read_optional_sysfs_value(os.path.join(path, "dev"))
    if value is None or not _DEVICE_PATTERN.fullmatch(value):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack node has no exact device identity."
        )
    return value


def _sysfs_node_path(device: str) -> str:
    if not _DEVICE_PATTERN.fullmatch(device):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack device identity is malformed."
        )
    path = os.path.realpath(f"/sys/dev/block/{device}")
    if not path.startswith("/sys/devices/") or not os.path.isdir(path):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack device is unavailable through sysfs."
        )
    if _sysfs_device_key(path) != device:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack sysfs identity changed while inspecting it."
        )
    return path


def _stable_uevent(path: str) -> dict[str, str]:
    raw = _read_optional_sysfs_value(
        os.path.join(path, "uevent"),
        allow_newlines=True,
    )
    if raw is None:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack node has no kernel identity record."
        )
    selected: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator != "=" or not key or not value:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The live block-stack kernel identity is malformed."
            )
        if key not in _SYSFS_STABLE_UEVENT_KEYS:
            continue
        if key in selected or any(
            ord(character) < 33 or ord(character) == 127 for character in value
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The live block-stack kernel identity is noncanonical."
            )
        selected[key] = value
    if not {"DEVNAME", "DEVTYPE", "MAJOR", "MINOR"}.issubset(selected):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack kernel identity is incomplete."
        )
    return selected


def _sysfs_related_devices(path: str, relation: str) -> tuple[str, ...] | None:
    if relation not in {"holders", "slaves"}:
        raise ValueError("Unsupported sysfs block relation.")
    relation_path = os.path.join(path, relation)
    try:
        with os.scandir(relation_path) as entries:
            children = tuple(
                sorted(_sysfs_device_key(entry.path) for entry in entries)
            )
    except OSError as err:
        if err.errno in {errno.ENOENT, errno.ENOTDIR}:
            return None
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack dependency graph could not be inspected."
        ) from err
    if len(children) != len(set(children)):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live block-stack dependency graph is ambiguous."
        )
    return children


def _sysfs_link_identity(path: str, relative_name: str) -> str | None:
    link_path = os.path.join(path, relative_name)
    try:
        value = os.lstat(link_path)
    except OSError as err:
        if err.errno in {errno.ENOENT, errno.ENOTDIR}:
            return None
        raise ReferenceJournalUnsupportedFilesystemError(
            "A block-stack driver identity could not be inspected."
        ) from err
    if not stat.S_ISLNK(value.st_mode):
        raise ReferenceJournalUnsupportedFilesystemError(
            "A block-stack driver identity is not a kernel symlink."
        )
    resolved = os.path.realpath(link_path)
    if not resolved.startswith("/sys/") or not os.path.exists(resolved):
        raise ReferenceJournalUnsupportedFilesystemError(
            "A block-stack driver identity leaves the trusted sysfs tree."
        )
    repeated = os.lstat(link_path)
    if not _same_inode(value, repeated) or os.path.realpath(link_path) != resolved:
        raise ReferenceJournalUnsupportedFilesystemError(
            "A block-stack driver identity changed while inspecting it."
        )
    return os.path.relpath(resolved, "/sys")


def _sysfs_device_entry_identity(path: str) -> tuple[str, str] | None:
    device_path = os.path.join(path, "device")
    try:
        before = os.lstat(device_path)
    except OSError as err:
        if err.errno in {errno.ENOENT, errno.ENOTDIR}:
            return None
        raise ReferenceJournalUnsupportedFilesystemError(
            "The sysfs device identity could not be inspected."
        ) from err
    if stat.S_ISLNK(before.st_mode):
        value = _sysfs_link_identity(path, "device")
        after = os.lstat(device_path)
        if value is None or not _same_inode(before, after):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The sysfs device path identity changed while inspecting it."
            )
        return "device_path", value
    if not stat.S_ISREG(before.st_mode):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The sysfs device identity is neither a symlink nor a regular ID."
        )
    value = _read_optional_sysfs_value(device_path)
    after = os.lstat(device_path)
    if (
        value is None
        or not stat.S_ISREG(after.st_mode)
        or not _same_inode(before, after)
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The regular sysfs PCI device ID changed while inspecting it."
        )
    return "device_id", value


def _driver_stack_identity(path: str) -> tuple[dict[str, str], ...]:
    identities: list[dict[str, str]] = []
    current = path
    for _depth in range(32):
        if current == "/sys/devices":
            break
        if not current.startswith("/sys/devices/"):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The block-stack driver ancestry leaves the trusted sysfs tree."
            )
        item: dict[str, str] = {
            "node": os.path.relpath(current, "/sys/devices"),
        }
        for name in ("driver", "subsystem"):
            resolved = _sysfs_link_identity(current, name)
            if resolved is not None:
                item[name] = resolved
        modalias = _read_optional_sysfs_value(os.path.join(current, "modalias"))
        if modalias is not None:
            item["modalias"] = modalias
        device_entry = _sysfs_device_entry_identity(current)
        if device_entry is not None:
            identity_name, identity_value = device_entry
            item[identity_name] = identity_value
        for source_name, identity_name in (
            ("revision", "revision"),
            ("vendor", "vendor_id"),
        ):
            identity_value = _read_optional_sysfs_value(
                os.path.join(current, source_name)
            )
            if identity_value is not None:
                item[identity_name] = identity_value
        if len(item) > 1:
            identities.append(item)
        current = os.path.dirname(current)
    else:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The block-stack driver ancestry exceeds its safety bound."
        )
    if not any("subsystem" in item for item in identities):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The block-stack subsystem identity is unavailable."
        )
    return tuple(identities)


def _kernel_release_identity() -> str:
    value = os.uname().release
    if (
        type(value) is not str
        or not value
        or len(value) > 128
        or not _MOUNT_OPTION_PATTERN.fullmatch(value)
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The running kernel release identity is noncanonical."
        )
    return value


def _device_key_from_stat(value: os.stat_result) -> str:
    if not stat.S_ISBLK(value.st_mode):
        raise ReferenceJournalUnsupportedFilesystemError(
            "A stable device identity does not resolve to a block device."
        )
    return f"{os.major(value.st_rdev)}:{os.minor(value.st_rdev)}"


def _stable_device_aliases(
    device: str,
    partition_uuid: str | None,
) -> tuple[dict[str, tuple[dict[str, str], ...]], str]:
    aliases: dict[str, tuple[dict[str, str], ...]] = {}
    exact_paths: dict[str, tuple[str, ...]] = {}
    for category, directory in _STABLE_ALIAS_DIRECTORIES:
        try:
            with os.scandir(directory) as entries:
                selected: list[dict[str, str]] = []
                paths: list[str] = []
                for entry in entries:
                    if (
                        not entry.name
                        or len(entry.name) > 255
                        or entry.name in {".", ".."}
                        or "/" in entry.name
                        or any(
                            ord(character) < 33 or ord(character) == 127
                            for character in entry.name
                        )
                    ):
                        raise ReferenceJournalUnsupportedFilesystemError(
                            "A stable device alias name is noncanonical."
                        )
                    alias_path = os.path.join(directory, entry.name)
                    alias_stat = os.lstat(alias_path)
                    if not stat.S_ISLNK(alias_stat.st_mode):
                        raise ReferenceJournalUnsupportedFilesystemError(
                            "A stable device alias is not a symlink."
                        )
                    resolved = os.path.realpath(alias_path)
                    if not resolved.startswith("/dev/"):
                        raise ReferenceJournalUnsupportedFilesystemError(
                            "A stable device alias leaves the trusted device tree."
                        )
                    target_stat = os.stat(resolved)
                    target_device = _device_key_from_stat(target_stat)
                    repeated = os.lstat(alias_path)
                    if (
                        not _same_inode(alias_stat, repeated)
                        or os.path.realpath(alias_path) != resolved
                    ):
                        raise ReferenceJournalUnsupportedFilesystemError(
                            "A stable device alias changed while inspecting it."
                        )
                    if target_device == device:
                        selected.append(
                            {"device": target_device, "name": entry.name}
                        )
                        paths.append(alias_path)
        except OSError as err:
            raise ReferenceJournalUnsupportedFilesystemError(
                "Stable device aliases are unavailable or unreadable."
            ) from err
        selected.sort(key=lambda item: item["name"])
        aliases[category] = tuple(selected)
        exact_paths[category] = tuple(sorted(paths))

    uuid_aliases = aliases["by-uuid"]
    id_aliases = aliases["by-id"]
    partuuid_aliases = aliases["by-partuuid"]
    if (
        len(uuid_aliases) != 1
        or not _FILESYSTEM_UUID_PATTERN.fullmatch(uuid_aliases[0]["name"])
        or not id_aliases
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The filesystem has no unique UUID and stable device identity."
        )
    if partition_uuid is not None:
        if (
            len(partuuid_aliases) != 1
            or partuuid_aliases[0]["name"] != partition_uuid
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The partition has no exact stable PARTUUID identity."
            )
    elif partuuid_aliases:
        raise ReferenceJournalUnsupportedFilesystemError(
            "A whole-device filesystem has an unexpected partition alias."
        )
    return aliases, exact_paths["by-uuid"][0]


def _read_exact_block_range(
    alias_path: str,
    expected_device: str,
    offset: int,
    size: int,
) -> bytes:
    if (
        type(offset) is not int
        or type(size) is not int
        or offset < 0
        or offset % 512 != 0
        or size < 512
        or size > 65_536
        or size & (size - 1) != 0
        or offset % size != 0
        or offset > (1 << 63) - size
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The raw block-device read range is not bounded and canonical."
        )
    try:
        alias_before = os.lstat(alias_path)
        if not stat.S_ISLNK(alias_before.st_mode):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The filesystem UUID alias is not a symlink."
            )
        resolved = os.path.realpath(alias_path)
        if not resolved.startswith("/dev/"):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The filesystem UUID alias leaves the trusted device tree."
            )
        descriptor = _retry_eintr(
            os.open,
            resolved,
            os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
        )
    except ReferenceJournalFileError:
        raise
    except OSError as err:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The filesystem superblock device could not be opened read-only."
        ) from err
    try:
        opened_before = os.fstat(descriptor)
        if _device_key_from_stat(opened_before) != expected_device:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The filesystem UUID alias targets a different block device."
            )
        raw = bytearray()
        while len(raw) < size:
            chunk = _retry_eintr(
                os.pread,
                descriptor,
                size - len(raw),
                offset + len(raw),
            )
            if not chunk:
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The filesystem superblock read was incomplete."
                )
            raw.extend(chunk)
        opened_after = os.fstat(descriptor)
        alias_after = os.lstat(alias_path)
        if (
            _device_key_from_stat(opened_after) != expected_device
            or not _same_inode(alias_before, alias_after)
            or os.path.realpath(alias_path) != resolved
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The filesystem superblock device changed while reading."
            )
        return bytes(raw)
    except ReferenceJournalFileError:
        raise
    except OSError as err:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The filesystem superblock could not be read safely."
        ) from err
    finally:
        os.close(descriptor)


def _format_filesystem_uuid(raw: bytes) -> str:
    if len(raw) != 16 or not any(raw):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The filesystem UUID is absent or malformed."
        )
    value = raw.hex()
    return (
        f"{value[:8]}-{value[8:12]}-{value[12:16]}-"
        f"{value[16:20]}-{value[20:]}"
    )


def _format_optional_filesystem_uuid(raw: bytes) -> str | None:
    return _format_filesystem_uuid(raw) if any(raw) else None


def _crc32c(raw: bytes, seed: int = 0xFFFFFFFF) -> int:
    checksum = seed
    for byte in raw:
        checksum ^= byte
        for _bit in range(8):
            checksum = (checksum >> 1) ^ (
                0x82F63B78 if checksum & 1 else 0
            )
    return checksum & 0xFFFFFFFF


class _Ext4BlockReader:
    def __init__(
        self,
        alias_path: str,
        device: str,
        block_size: int,
        total_blocks: int,
    ) -> None:
        self._alias_path = alias_path
        self._device = device
        self.block_size = block_size
        self.total_blocks = total_blocks
        self._reads = 0

    def read_block(self, block: int) -> bytes:
        if (
            type(block) is not int
            or block < 0
            or block >= self.total_blocks
            or self._reads >= _EXT4_MAX_METADATA_READS
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 metadata read exceeds its exact block bound."
            )
        self._reads += 1
        raw = _read_exact_block_range(
            self._alias_path,
            self._device,
            block * self.block_size,
            self.block_size,
        )
        if len(raw) != self.block_size:
            raise ReferenceJournalUnsupportedFilesystemError(
                "An ext4 metadata block read was incomplete."
            )
        return raw


def _ext4_extent_mapping(
    inode_block_map: bytes,
    reader: _Ext4BlockReader,
    journal_blocks: int,
) -> dict[str, Any]:
    extents: list[dict[str, int]] = []
    nodes: list[dict[str, Any]] = []
    tree_blocks: set[int] = set()

    def parse_node(
        raw: bytes,
        expected_depth: int,
        source_block: int | None,
    ) -> tuple[int, int]:
        if len(raw) < 12:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 journal extent node is truncated."
            )
        magic = int.from_bytes(raw[0:2], "little")
        entries = int.from_bytes(raw[2:4], "little")
        maximum = int.from_bytes(raw[4:6], "little")
        depth = int.from_bytes(raw[6:8], "little")
        generation = int.from_bytes(raw[8:12], "little")
        capacity = (len(raw) - 12) // 12
        if (
            magic != _EXT4_EXTENT_MAGIC
            or depth != expected_depth
            or entries == 0
            or entries > maximum
            or maximum != capacity
            or len(nodes) >= _EXT4_MAX_EXTENT_NODES
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 journal extent header is unsupported."
            )
        nodes.append(
            {
                "depth": depth,
                "entries": entries,
                "generation": generation,
                "maximum": maximum,
                "raw_digest": hashlib.sha256(raw).hexdigest(),
                "source_block": source_block,
            }
        )
        first_logical: int | None = None
        final_logical = 0
        previous_index = -1
        for ordinal in range(entries):
            offset = 12 + ordinal * 12
            logical = int.from_bytes(raw[offset : offset + 4], "little")
            if logical <= previous_index:
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The ext4 journal extent keys are not strictly ordered."
                )
            previous_index = logical
            if depth == 0:
                encoded_length = int.from_bytes(
                    raw[offset + 4 : offset + 6], "little"
                )
                physical = (
                    int.from_bytes(raw[offset + 6 : offset + 8], "little")
                    << 32
                ) | int.from_bytes(raw[offset + 8 : offset + 12], "little")
                if (
                    encoded_length == 0
                    or encoded_length > 0x8000
                    or physical == 0
                    or physical + encoded_length > reader.total_blocks
                    or len(extents) >= _EXT4_MAX_EXTENTS
                ):
                    raise ReferenceJournalUnsupportedFilesystemError(
                        "The ext4 journal extent is uninitialized or out of bounds."
                    )
                extents.append(
                    {
                        "length": encoded_length,
                        "logical": logical,
                        "physical": physical,
                    }
                )
                child_first = logical
                child_final = logical + encoded_length
            else:
                child_block = int.from_bytes(
                    raw[offset + 4 : offset + 8], "little"
                ) | (
                    int.from_bytes(raw[offset + 8 : offset + 10], "little")
                    << 32
                )
                if (
                    int.from_bytes(raw[offset + 10 : offset + 12], "little") != 0
                    or child_block == 0
                    or child_block >= reader.total_blocks
                    or child_block in tree_blocks
                ):
                    raise ReferenceJournalUnsupportedFilesystemError(
                        "The ext4 journal extent index is malformed."
                    )
                tree_blocks.add(child_block)
                child_first, child_final = parse_node(
                    reader.read_block(child_block),
                    depth - 1,
                    child_block,
                )
                if child_first != logical:
                    raise ReferenceJournalUnsupportedFilesystemError(
                        "The ext4 journal extent index key is inconsistent."
                    )
            if first_logical is None:
                first_logical = child_first
            final_logical = child_final
        if first_logical is None:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 journal extent tree is empty."
            )
        return first_logical, final_logical

    if len(inode_block_map) != 60:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 journal inode block map has an invalid size."
        )
    depth = int.from_bytes(inode_block_map[6:8], "little")
    if depth > _EXT4_MAX_EXTENT_DEPTH:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 journal extent depth exceeds the supported bound."
        )
    parse_node(inode_block_map, depth, None)
    expected_logical = 0
    physical_ranges: list[range] = []
    for extent in extents:
        if extent["logical"] != expected_logical:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 journal extent map contains a hole or overlap."
            )
        expected_logical += extent["length"]
        current = range(
            extent["physical"],
            extent["physical"] + extent["length"],
        )
        if any(
            current.start < previous.stop and previous.start < current.stop
            for previous in physical_ranges
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 journal physical extents overlap."
            )
        physical_ranges.append(current)
    if expected_logical != journal_blocks or any(
        physical_range.start <= block < physical_range.stop
        for physical_range in physical_ranges
        for block in tree_blocks
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 journal extent map does not exactly cover the inode."
        )
    return {
        "depth": depth,
        "extents": extents,
        "format": "extents",
        "nodes": nodes,
    }


def _ext4_direct_mapping(
    inode_block_map: bytes,
    reader: _Ext4BlockReader,
    journal_blocks: int,
) -> dict[str, Any]:
    if len(inode_block_map) != 60 or journal_blocks > 12:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 direct journal layout exceeds its supported bound."
        )
    pointers = [
        int.from_bytes(inode_block_map[offset : offset + 4], "little")
        for offset in range(0, 60, 4)
    ]
    selected = pointers[:journal_blocks]
    if (
        any(block == 0 or block >= reader.total_blocks for block in selected)
        or len(selected) != len(set(selected))
        or any(pointers[journal_blocks:])
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 direct journal block map is sparse or indirect."
        )
    return {"blocks": selected, "format": "direct"}


def _jbd2_superblock_identity(
    raw: bytes,
    filesystem_uuid: str,
    block_size: int,
    journal_blocks: int,
) -> dict[str, Any]:
    if len(raw) != block_size or block_size < 1024 or journal_blocks < 1:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The JBD2 superblock read is incomplete."
        )
    superblock = raw[:1024]
    magic = int.from_bytes(raw[0:4], "big")
    block_type = int.from_bytes(raw[4:8], "big")
    header_sequence = int.from_bytes(raw[8:12], "big")
    jbd_block_size = int.from_bytes(raw[12:16], "big")
    maximum_length = int.from_bytes(raw[16:20], "big")
    first = int.from_bytes(raw[20:24], "big")
    sequence = int.from_bytes(raw[24:28], "big")
    start = int.from_bytes(raw[28:32], "big")
    error = int.from_bytes(raw[32:36], "big")
    feature_compat = int.from_bytes(raw[36:40], "big")
    feature_incompat = int.from_bytes(raw[40:44], "big")
    feature_ro_compat = int.from_bytes(raw[44:48], "big")
    journal_uuid = _format_filesystem_uuid(raw[48:64])
    users_count = int.from_bytes(raw[64:68], "big")
    dynamic_superblock = int.from_bytes(raw[68:72], "big")
    maximum_transaction = int.from_bytes(raw[72:76], "big")
    maximum_transaction_data = int.from_bytes(raw[76:80], "big")
    checksum_type = raw[80]
    fast_commit_blocks = int.from_bytes(raw[84:88], "big")
    head = int.from_bytes(raw[88:92], "big")
    stored_checksum = int.from_bytes(raw[252:256], "big")
    if users_count != 1:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The internal JBD2 user identity is not singular."
        )
    users = (_format_filesystem_uuid(raw[256:272]),)
    checksum_features = feature_incompat & (
        _JBD2_FEATURE_INCOMPAT_CSUM_V2 | _JBD2_FEATURE_INCOMPAT_CSUM_V3
    )
    normal_blocks = maximum_length - fast_commit_blocks
    checksum_input = bytearray(superblock)
    checksum_input[252:256] = bytes(4)
    calculated_checksum = _crc32c(bytes(checksum_input))
    fast_commit_enabled = bool(
        feature_incompat & _JBD2_FEATURE_INCOMPAT_FAST_COMMIT
    )
    volatile_words = (header_sequence, sequence, start, error, head)
    if (
        magic != _JBD2_MAGIC
        or block_type != _JBD2_SUPERBLOCK_V2
        or jbd_block_size != block_size
        or maximum_length < _JBD2_MIN_JOURNAL_BLOCKS
        or maximum_length > journal_blocks
        or normal_blocks < _JBD2_MIN_JOURNAL_BLOCKS
        or not 1 <= first < maximum_length
        or first >= normal_blocks
        or not (start == 0 or first <= start < normal_blocks)
        or not (head == 0 or first <= head < normal_blocks)
        or any(value < 0 or value > 0xFFFFFFFF for value in volatile_words)
        or feature_compat != 0
        or feature_incompat & ~_JBD2_SUPPORTED_FEATURE_INCOMPAT
        or checksum_features
        not in {
            _JBD2_FEATURE_INCOMPAT_CSUM_V2,
            _JBD2_FEATURE_INCOMPAT_CSUM_V3,
        }
        or fast_commit_enabled != (fast_commit_blocks > 0)
        or feature_ro_compat != 0
        or journal_uuid != filesystem_uuid
        or not (
            dynamic_superblock == 0
            or first <= dynamic_superblock < normal_blocks
        )
        or maximum_transaction > normal_blocks
        or maximum_transaction_data > normal_blocks
        or checksum_type != _JBD2_CHECKSUM_TYPE_CRC32C
        or any(raw[81:84])
        or any(raw[92:252])
        or stored_checksum != calculated_checksum
        or users != (filesystem_uuid,)
        or any(raw[272:1024])
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The internal JBD2 superblock is malformed or unsupported."
        )
    return {
        "block_size": jbd_block_size,
        "block_type": block_type,
        "checksum_semantics": (
            "crc32c-seed-ffffffff-zeroed-offset-00fc-full-1024"
        ),
        "checksum_type": checksum_type,
        "dynamic_superblock": dynamic_superblock,
        "fast_commit_blocks": fast_commit_blocks,
        "feature_compat": feature_compat,
        "feature_incompat": feature_incompat,
        "feature_ro_compat": feature_ro_compat,
        "first": first,
        "journal_superblock_bytes": 1024,
        "magic": magic,
        "maximum_length": maximum_length,
        "maximum_transaction": maximum_transaction,
        "maximum_transaction_data": maximum_transaction_data,
        "normal_blocks": normal_blocks,
        "users": users,
        "users_count": users_count,
        "uuid": journal_uuid,
    }


def _ext4_internal_journal_identity(
    raw_superblock: bytes,
    alias_path: str,
    device: str,
    filesystem_uuid: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    feature_compat = int.from_bytes(raw_superblock[92:96], "little")
    feature_incompat = int.from_bytes(raw_superblock[96:100], "little")
    feature_ro_compat = int.from_bytes(raw_superblock[100:104], "little")
    journal_inode = int.from_bytes(raw_superblock[224:228], "little")
    journal_device = int.from_bytes(raw_superblock[228:232], "little")
    if (
        feature_compat & _EXT4_HAS_JOURNAL == 0
        or feature_compat & ~_EXT4_SUPPORTED_FEATURE_COMPAT
        or feature_incompat & _EXT4_JOURNAL_DEV
        or feature_incompat & ~_EXT4_SUPPORTED_FEATURE_INCOMPAT
        or feature_ro_compat & ~_EXT4_SUPPORTED_FEATURE_RO_COMPAT
        or journal_inode == 0
        or journal_device != 0
        or any(raw_superblock[208:224])
        or int.from_bytes(raw_superblock[260:264], "little") != 0
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "Ext4 requires one supported internal journal layout."
        )
    log_block_size = int.from_bytes(raw_superblock[24:28], "little")
    log_cluster_size = int.from_bytes(raw_superblock[28:32], "little")
    if log_block_size > 6 or log_cluster_size != log_block_size:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 block or cluster geometry is unsupported."
        )
    block_size = 1024 << log_block_size
    blocks_low = int.from_bytes(raw_superblock[4:8], "little")
    blocks_high = int.from_bytes(raw_superblock[336:340], "little")
    if feature_incompat & _EXT4_FEATURE_INCOMPAT_64BIT:
        total_blocks = blocks_low | (blocks_high << 32)
        descriptor_size = int.from_bytes(raw_superblock[254:256], "little")
        if descriptor_size != 64:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 64-bit group descriptor size is unsupported."
            )
    else:
        total_blocks = blocks_low
        descriptor_size = 32
        if blocks_high != 0 or int.from_bytes(raw_superblock[254:256], "little") not in {
            0,
            32,
        }:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 group descriptor geometry is inconsistent."
            )
    first_data_block = int.from_bytes(raw_superblock[20:24], "little")
    blocks_per_group = int.from_bytes(raw_superblock[32:36], "little")
    inodes_count = int.from_bytes(raw_superblock[0:4], "little")
    inodes_per_group = int.from_bytes(raw_superblock[40:44], "little")
    inode_size = int.from_bytes(raw_superblock[88:90], "little")
    if (
        total_blocks <= first_data_block
        or total_blocks * block_size > (1 << 63) - 1
        or blocks_per_group == 0
        or blocks_per_group > block_size * 8
        or inodes_count == 0
        or inodes_per_group == 0
        or inodes_per_group > block_size * 8
        or journal_inode > inodes_count
        or inode_size not in {128, 256}
        or block_size % inode_size != 0
        or descriptor_size > block_size
        or block_size % descriptor_size != 0
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 inode or group geometry is unsupported."
        )
    group_count = (
        total_blocks - first_data_block + blocks_per_group - 1
    ) // blocks_per_group
    inode_group = (journal_inode - 1) // inodes_per_group
    inode_index = (journal_inode - 1) % inodes_per_group
    if inode_group >= group_count:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 journal inode group is outside the filesystem."
        )
    reader = _Ext4BlockReader(alias_path, device, block_size, total_blocks)
    descriptor_table_block = 2 if block_size == 1024 else 1
    descriptor_byte = inode_group * descriptor_size
    descriptor_block = descriptor_table_block + descriptor_byte // block_size
    descriptor_offset = descriptor_byte % block_size
    descriptor_raw = reader.read_block(descriptor_block)[
        descriptor_offset : descriptor_offset + descriptor_size
    ]
    block_bitmap = int.from_bytes(descriptor_raw[0:4], "little")
    inode_bitmap = int.from_bytes(descriptor_raw[4:8], "little")
    inode_table_block = int.from_bytes(descriptor_raw[8:12], "little")
    if descriptor_size == 64:
        block_bitmap |= int.from_bytes(descriptor_raw[32:36], "little") << 32
        inode_bitmap |= int.from_bytes(descriptor_raw[36:40], "little") << 32
        inode_table_block |= int.from_bytes(descriptor_raw[40:44], "little") << 32
    inode_table_blocks = (
        inodes_per_group * inode_size + block_size - 1
    ) // block_size
    if (
        block_bitmap == 0
        or block_bitmap >= total_blocks
        or inode_bitmap == 0
        or inode_bitmap >= total_blocks
        or block_bitmap == inode_bitmap
        or inode_table_block == 0
        or inode_table_block + inode_table_blocks > total_blocks
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 journal inode table is outside the filesystem."
        )
    inode_byte = inode_index * inode_size
    inode_block = inode_table_block + inode_byte // block_size
    inode_offset = inode_byte % block_size
    inode_raw = reader.read_block(inode_block)[
        inode_offset : inode_offset + inode_size
    ]
    mode = int.from_bytes(inode_raw[0:2], "little")
    size = int.from_bytes(inode_raw[4:8], "little") | (
        int.from_bytes(inode_raw[108:112], "little") << 32
    )
    deleted_time = int.from_bytes(inode_raw[20:24], "little")
    links = int.from_bytes(inode_raw[26:28], "little")
    sectors = int.from_bytes(inode_raw[28:32], "little")
    flags = int.from_bytes(inode_raw[32:36], "little")
    generation = int.from_bytes(inode_raw[100:104], "little")
    file_acl = int.from_bytes(inode_raw[104:108], "little")
    blocks_high = int.from_bytes(inode_raw[116:118], "little")
    file_acl_high = int.from_bytes(inode_raw[118:120], "little")
    if (
        mode & 0xF000 != 0x8000
        or deleted_time != 0
        or links == 0
        or size == 0
        or size > _EXT4_MAX_JOURNAL_BYTES
        or size % block_size != 0
        or sectors < size // 512
        or flags not in {0, _EXT4_EXTENTS_INODE_FLAG}
        or file_acl != 0
        or file_acl_high != 0
        or blocks_high != 0
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 journal inode metadata is malformed or unsupported."
        )
    journal_blocks = size // block_size
    inode_block_map = inode_raw[40:100]
    if flags == _EXT4_EXTENTS_INODE_FLAG:
        if feature_incompat & _EXT4_FEATURE_INCOMPAT_EXTENTS == 0:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 journal inode uses unadvertised extents."
            )
        mapping = _ext4_extent_mapping(inode_block_map, reader, journal_blocks)
        journal_first_block = mapping["extents"][0]["physical"]
    else:
        mapping = _ext4_direct_mapping(inode_block_map, reader, journal_blocks)
        journal_first_block = mapping["blocks"][0]
    reserved_blocks = {
        1 if block_size == 1024 else 0,
        block_bitmap,
        descriptor_block,
        inode_bitmap,
        *range(inode_table_block, inode_table_block + inode_table_blocks),
    }
    if mapping["format"] == "extents":
        mapped_ranges = [
            range(
                extent["physical"],
                extent["physical"] + extent["length"],
            )
            for extent in mapping["extents"]
        ]
        tree_blocks = {
            node["source_block"]
            for node in mapping["nodes"]
            if node["source_block"] is not None
        }
    else:
        mapped_ranges = [range(block, block + 1) for block in mapping["blocks"]]
        tree_blocks = set()
    if (
        tree_blocks.intersection(reserved_blocks)
        or any(
            physical_range.start <= reserved < physical_range.stop
            for physical_range in mapped_ranges
            for reserved in reserved_blocks
        )
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 journal mapping overlaps filesystem metadata."
        )
    jbd2 = _jbd2_superblock_identity(
        reader.read_block(journal_first_block),
        filesystem_uuid,
        block_size,
        journal_blocks,
    )
    repeated_superblock = _read_exact_block_range(alias_path, device, 1024, 1024)
    if repeated_superblock != raw_superblock:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The ext4 superblock changed during journal inspection."
        )
    inode_identity = {
        "blocks_512": sectors,
        "flags": flags,
        "generation": generation,
        "group_descriptor": {
            "block_bitmap": block_bitmap,
            "inode_bitmap": inode_bitmap,
            "inode_table": inode_table_block,
            "raw_digest": hashlib.sha256(descriptor_raw).hexdigest(),
        },
        "group": inode_group,
        "inode": journal_inode,
        "links": links,
        "mapping": mapping,
        "mode": mode,
        "raw_digest": hashlib.sha256(inode_raw).hexdigest(),
        "size": size,
    }
    return inode_identity, jbd2


def _filesystem_feature_identity(
    filesystem_type: str,
    device: str,
    uuid_alias_path: str,
    expected_uuid: str,
) -> dict[str, Any]:
    if filesystem_type == "ext4":
        # ``sb=`` is rejected during mount qualification, so only the primary
        # ext4 superblock at its fixed byte offset can enter certification.
        raw = _read_exact_block_range(uuid_alias_path, device, 1024, 1024)
        if (
            len(raw) != 1024
            or int.from_bytes(raw[56:58], "little") != 0xEF53
            or int.from_bytes(raw[72:76], "little") != 0
            or int.from_bytes(raw[76:80], "little") != 1
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The mounted ext4 device has an invalid superblock identity."
            )
        filesystem_uuid = _format_filesystem_uuid(raw[104:120])
        feature_compat = int.from_bytes(raw[92:96], "little")
        feature_incompat = int.from_bytes(raw[96:100], "little")
        feature_ro_compat = int.from_bytes(raw[100:104], "little")
        journal_inode = int.from_bytes(raw[224:228], "little")
        journal_device = int.from_bytes(raw[228:232], "little")
        journal_inode_identity, jbd2 = _ext4_internal_journal_identity(
            raw,
            uuid_alias_path,
            device,
            filesystem_uuid,
        )
        log_block_size = int.from_bytes(raw[24:28], "little")
        descriptor_size = int.from_bytes(raw[254:256], "little")
        if feature_incompat & _EXT4_FEATURE_INCOMPAT_64BIT == 0:
            descriptor_size = 32
        identity: dict[str, Any] = {
            "block_size": 1024 << log_block_size,
            "blocks_per_group": int.from_bytes(raw[32:36], "little"),
            "checksum_seed": int.from_bytes(raw[624:628], "little"),
            "creator_os": int.from_bytes(raw[72:76], "little"),
            "descriptor_size": descriptor_size,
            "feature_compat": feature_compat,
            "feature_incompat": feature_incompat,
            "feature_ro_compat": feature_ro_compat,
            "first_data_block": int.from_bytes(raw[20:24], "little"),
            "filesystem_type": filesystem_type,
            "filesystem_uuid": filesystem_uuid,
            "hash_seed": raw[236:252].hex(),
            "inode_size": int.from_bytes(raw[88:90], "little"),
            "inodes_count": int.from_bytes(raw[0:4], "little"),
            "inodes_per_group": int.from_bytes(raw[40:44], "little"),
            "jbd2": jbd2,
            "journal_device": journal_device,
            "journal_device_format": False,
            "journal_has_internal": True,
            "journal_inode": journal_inode,
            "journal_inode_identity": journal_inode_identity,
            "journal_needs_recovery": bool(feature_incompat & 0x4),
            "journal_uuid": None,
            "log_block_size": log_block_size,
            "log_cluster_size": int.from_bytes(raw[28:32], "little"),
            "mkfs_time": int.from_bytes(raw[264:268], "little"),
            "revision": int.from_bytes(raw[76:80], "little"),
            "volume_name_hex": raw[120:136].hex(),
        }
    elif filesystem_type == "xfs":
        raw = _read_exact_block_range(uuid_alias_path, device, 0, 512)
        if raw[:4] != b"XFSB":
            raise ReferenceJournalUnsupportedFilesystemError(
                "The mounted XFS device has an invalid superblock identity."
            )
        filesystem_uuid = _format_filesystem_uuid(raw[32:48])
        log_start = int.from_bytes(raw[48:56], "big")
        realtime_blocks = int.from_bytes(raw[16:24], "big")
        realtime_extents = int.from_bytes(raw[24:32], "big")
        realtime_extent_size = int.from_bytes(raw[80:84], "big")
        realtime_bitmap_blocks = int.from_bytes(raw[92:96], "big")
        if (
            log_start == 0
            or realtime_blocks != 0
            or realtime_extents != 0
            or realtime_bitmap_blocks != 0
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "External-log and realtime XFS persistence devices are unsupported."
            )
        identity = {
            "bad_features2": int.from_bytes(raw[204:208], "big"),
            "block_size": int.from_bytes(raw[4:8], "big"),
            "feature_compat": int.from_bytes(raw[208:212], "big"),
            "feature_incompat": int.from_bytes(raw[216:220], "big"),
            "feature_log_incompat": int.from_bytes(raw[220:224], "big"),
            "feature_ro_compat": int.from_bytes(raw[212:216], "big"),
            "features2": int.from_bytes(raw[200:204], "big"),
            "filesystem_type": filesystem_type,
            "filesystem_uuid": filesystem_uuid,
            "inode_size": int.from_bytes(raw[104:106], "big"),
            "log_start": log_start,
            "log_sector_size": int.from_bytes(raw[194:196], "big"),
            "log_stripe_unit": int.from_bytes(raw[196:200], "big"),
            "metadata_uuid": _format_optional_filesystem_uuid(raw[248:264]),
            "realtime_bitmap_blocks": realtime_bitmap_blocks,
            "realtime_blocks": realtime_blocks,
            "realtime_extent_size": realtime_extent_size,
            "realtime_extents": realtime_extents,
            "sector_size": int.from_bytes(raw[102:104], "big"),
            "stripe_unit": int.from_bytes(raw[184:188], "big"),
            "stripe_width": int.from_bytes(raw[188:192], "big"),
            "version": int.from_bytes(raw[100:102], "big"),
            "volume_name_hex": raw[108:120].hex(),
        }
    else:
        raise ReferenceJournalUnsupportedFilesystemError(
            "Production filesystem feature binding supports only ext4 and XFS."
        )
    if filesystem_uuid != expected_uuid:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The filesystem superblock UUID does not match its stable alias."
        )
    return identity


def _production_block_node(device: str) -> dict[str, Any]:
    path = _sysfs_node_path(device)
    fields = {
        field: value
        for field in _SYSFS_NODE_FIELDS
        if (value := _read_optional_sysfs_value(os.path.join(path, field)))
        is not None
    }
    device_identity = {
        field: value
        for field in _SYSFS_DEVICE_IDENTITY_FIELDS
        if (value := _read_optional_sysfs_value(os.path.join(path, field)))
        is not None
    }
    queue = {
        field: value
        for field in _SYSFS_QUEUE_FIELDS
        if (value := _read_optional_sysfs_value(os.path.join(path, field)))
        is not None
    }
    return {
        "device": device,
        "device_identity": device_identity,
        "driver_stack": list(_driver_stack_identity(path)),
        "fields": fields,
        "holders": _sysfs_related_devices(path, "holders"),
        "queue": queue,
        "slaves": _sysfs_related_devices(path, "slaves"),
        "sysfs_identity": os.path.relpath(path, "/sys/devices"),
        "uevent": _stable_uevent(path),
    }


def _recognized_direct_transport(physical: dict[str, Any]) -> str:
    """Recognize one structural model; this is not provenance certification."""

    uevent = physical.get("uevent")
    device_identity = physical.get("device_identity")
    driver_stack = physical.get("driver_stack")
    if (
        type(uevent) is not dict
        or type(device_identity) is not dict
        or type(driver_stack) is not list
        or not driver_stack
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The direct physical transport evidence is incomplete."
        )
    device_name = uevent.get("DEVNAME")
    raw_transport = device_identity.get("device/transport", "")
    if type(device_name) is not str or type(raw_transport) is not str:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The direct physical transport identity is noncanonical."
        )
    canonical_transport = raw_transport.strip().lower()
    if raw_transport != canonical_transport:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The direct physical transport identity is not canonical."
        )
    raw_transport = canonical_transport
    drivers: set[str] = set()
    subsystems: set[str] = set()
    for item in driver_stack:
        if type(item) is not dict or any(
            type(value) is not str for value in item.values()
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The modeled driver ancestry is noncanonical."
            )
        driver = item.get("driver")
        subsystem = item.get("subsystem")
        node = item.get("node")
        if (
            type(node) is not str
            or not node
            or type(subsystem) is not str
            or not subsystem
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "Every driver ancestry item requires a recognized subsystem context."
            )
        if driver is not None:
            drivers.add(driver)
        subsystems.add(subsystem)
    if not drivers or not subsystems:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The modeled driver and subsystem ancestry is incomplete."
        )

    matches: list[str] = []
    for model_name, raw_model in _DIRECT_TRANSPORT_MODELS.items():
        model = cast(dict[str, Any], raw_model)
        pattern = cast(re.Pattern[str], model["device_pattern"])
        allowed_drivers = cast(
            frozenset[str],
            model["allowed_driver_identities"],
        )
        allowed_subsystems = cast(
            frozenset[str],
            model["allowed_subsystems"],
        )
        raw_transports = cast(frozenset[str], model["raw_transports"])
        required_groups = cast(
            tuple[frozenset[str], ...],
            model["required_driver_groups"],
        )
        required_subsystems = cast(
            frozenset[str],
            model["required_subsystems"],
        )
        if (
            pattern.fullmatch(device_name)
            and raw_transport in raw_transports
            and drivers.issubset(allowed_drivers)
            and all(drivers.intersection(group) for group in required_groups)
            and subsystems.issubset(allowed_subsystems)
            and required_subsystems.issubset(subsystems)
        ):
            _validate_transport_specific_ancestry(model_name, driver_stack)
            matches.append(model_name)
    if len(matches) != 1:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The storage driver ancestry is not one recognized direct "
            "physical model."
        )
    return matches[0]


def _validate_transport_specific_ancestry(
    transport_identity: str,
    driver_stack: list[dict[str, str]],
) -> None:
    if transport_identity != "nvme-pcie-direct":
        return
    for item in driver_stack:
        driver = item.get("driver")
        modalias = item.get("modalias")
        node = item.get("node")
        if not (
            (type(modalias) is str and "Csimple-bus" in modalias)
            or driver == "bus/platform/drivers/simple-pm-bus"
        ):
            continue
        if (
            driver != "bus/platform/drivers/simple-pm-bus"
            or item.get("subsystem") != "bus/platform"
            or type(node) is not str
            or node != "platform/axi"
            or modalias != "of:NaxiT(null)Csimple-bus"
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The Raspberry Pi simple-pm-bus ancestry is not exact."
            )


def _canonical_pci_vendor_id(value: str) -> str | None:
    matched = re.fullmatch(
        r"(?:0x)?(?:0000)?([0-9a-f]{4})",
        value.lower(),
    )
    return matched.group(1) if matched is not None else None


def _canonical_snapshot_strings(value: Any) -> tuple[str, ...]:
    evidence: list[str] = []
    active: set[int] = set()
    nodes = 0

    def visit(current: Any, depth: int) -> None:
        nonlocal nodes

        nodes += 1
        if nodes > 10_000 or depth > 128:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The storage evidence tree exceeds its safety bound."
            )
        if type(current) is str:
            if not current or any(
                ord(character) < 32 or ord(character) == 127
                for character in current
            ):
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The storage evidence contains a noncanonical string."
                )
            evidence.append(current)
            return
        if type(current) is dict:
            identity = id(current)
            if identity in active:
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The storage evidence tree contains a reference cycle."
                )
            active.add(identity)
            try:
                for key, item in current.items():
                    if type(key) is not str or not key:
                        raise ReferenceJournalUnsupportedFilesystemError(
                            "The storage evidence mapping key is noncanonical."
                        )
                    visit(item, depth + 1)
            finally:
                active.remove(identity)
            return
        if type(current) in {list, tuple}:
            identity = id(current)
            if identity in active:
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The storage evidence tree contains a reference cycle."
                )
            active.add(identity)
            try:
                for item in current:
                    visit(item, depth + 1)
            finally:
                active.remove(identity)
            return
        if current is None or type(current) in {bool, int}:
            return
        raise ReferenceJournalUnsupportedFilesystemError(
            "The storage evidence contains a noncanonical value type."
        )

    visit(value, 1)
    return tuple(evidence)


def _reject_prohibited_canonical_evidence(value: Any) -> None:
    evidence = _canonical_snapshot_strings(value)
    vendor_ids: set[str] = set()
    for item in evidence:
        vendor_id = _canonical_pci_vendor_id(item)
        if vendor_id is not None:
            vendor_ids.add(vendor_id)
        vendor_ids.update(
            matched.group(1)
            for matched in _PCI_MODALIAS_VENDOR_PATTERN.finditer(item.lower())
        )
    normalized = "\n".join(evidence).lower()
    if (
        any(
            signature in normalized
            for signature in _PROHIBITED_PROVENANCE_SIGNATURES
        )
        or _PROHIBITED_PROVENANCE_WORD_PATTERN.search(normalized) is not None
        or vendor_ids.intersection(_PROHIBITED_PCI_VENDOR_IDS)
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "Virtualized, emulated, RAID, or logical-volume hardware evidence "
            "cannot qualify for production."
        )


def _reject_prohibited_physical_provenance(physical: dict[str, Any]) -> None:
    _reject_prohibited_canonical_evidence(physical)


def _mandatory_hardware_evidence(
    physical: dict[str, Any],
    transport_identity: str,
) -> dict[str, Any]:
    device_identity = physical.get("device_identity")
    driver_stack = physical.get("driver_stack")
    if type(device_identity) is not dict or type(driver_stack) is not list:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The mandatory hardware evidence is malformed."
        )
    _reject_prohibited_physical_provenance(physical)
    if transport_identity != "nvme-pcie-direct":
        raise ReferenceJournalUnsupportedFilesystemError(
            "Production hardware evidence supports only direct PCIe NVMe."
        )
    endpoints = [
        item
        for item in driver_stack
        if type(item) is dict
        and type(item.get("driver")) is str
        and os.path.basename(item["driver"]) == "nvme"
        and item.get("subsystem") == "bus/pci"
    ]
    if len(endpoints) != 1:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The PCIe NVMe endpoint ancestry is absent or ambiguous."
        )
    endpoint = endpoints[0]
    endpoint_vendor = endpoint.get("vendor_id")
    endpoint_device = endpoint.get("device_id")
    endpoint_revision = endpoint.get("revision")
    namespace_vendor = device_identity.get("device/device/vendor")
    model = device_identity.get("device/model")
    firmware = device_identity.get("device/firmware_rev")
    serial = device_identity.get("device/serial")
    namespace_transport = device_identity.get("device/transport")
    wwids = {
        value
        for field, value in device_identity.items()
        if field in {"device/wwid", "eui", "wwid"}
        and type(value) is str
        and value
    }
    if (
        type(endpoint_vendor) is not str
        or not _PCI_ID_PATTERN.fullmatch(endpoint_vendor)
        or type(endpoint_device) is not str
        or not _PCI_ID_PATTERN.fullmatch(endpoint_device)
        or type(endpoint_revision) is not str
        or not _PCI_REVISION_PATTERN.fullmatch(endpoint_revision)
        or namespace_vendor != endpoint_vendor
        or type(namespace_vendor) is not str
        or not _PCI_ID_PATTERN.fullmatch(namespace_vendor)
        or type(model) is not str
        or not model
        or type(firmware) is not str
        or not firmware
        or type(serial) is not str
        or not serial
        or not wwids
        or any(type(value) is not str or not value for value in wwids)
        or namespace_transport != "pcie"
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The NVMe endpoint or namespace hardware evidence is incomplete."
        )
    return {
        "endpoint": {
            "device_id": endpoint_device,
            "revision": endpoint_revision,
            "vendor_id": endpoint_vendor,
        },
        "firmware": firmware,
        "model": model,
        "serial": serial,
        "transport": namespace_transport,
        "transport_identity": transport_identity,
        "vendor": namespace_vendor,
        "wwid": sorted(wwids),
    }


def _validate_production_storage_snapshot(snapshot: dict[str, Any]) -> None:
    _reject_prohibited_canonical_evidence(snapshot)
    root_device = snapshot.get("root_device")
    source_device = snapshot.get("mount_source_device")
    nodes = snapshot.get("nodes")
    if (
        type(root_device) is not str
        or not _DEVICE_PATTERN.fullmatch(root_device)
        or source_device != root_device
        or type(nodes) is not dict
        or root_device not in nodes
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The production storage stack has no single exact block root."
        )
    root = nodes[root_device]
    if type(root) is not dict or type(root.get("uevent")) is not dict:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The production storage root identity is malformed."
        )
    root_uevent = root["uevent"]
    root_name = root_uevent.get("DEVNAME", "")
    root_type = root_uevent.get("DEVTYPE")
    if type(root_name) is not str or not root_name:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The production block root has no canonical kernel device name."
        )
    if root.get("slaves") not in ((), [], None) or root.get("holders") not in (
        (),
        [],
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "Production storage cannot have slave or holder dependencies."
        )

    partition_parent = snapshot.get("partition_parent")
    if root_type == "partition":
        if (
            type(partition_parent) is not str
            or partition_parent not in nodes
            or set(nodes) != {root_device, partition_parent}
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The production partition topology is incomplete or composite."
            )
        physical = nodes[partition_parent]
        partition_uuid = root_uevent.get("PARTUUID")
        if not _FILESYSTEM_UUID_PATTERN.fullmatch(partition_uuid or ""):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The production partition has no canonical PARTUUID."
            )
    elif root_type == "disk":
        if partition_parent is not None or set(nodes) != {root_device}:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The production whole-device topology is composite."
            )
        physical = root
        partition_uuid = None
    else:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The production storage root is neither a disk nor a partition."
        )

    if type(physical) is not dict:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The physical production device identity is malformed."
        )
    physical_name = physical.get("uevent", {}).get("DEVNAME", "")
    physical_type = physical.get("uevent", {}).get("DEVTYPE")
    if physical_type != "disk" or type(physical_name) is not str:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The physical production device is not one exact disk."
        )
    if physical.get("slaves") not in ((), []) or physical.get("holders") not in (
        (),
        [],
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The physical production device has unmodeled dependencies."
        )
    transport_identity = _recognized_direct_transport(physical)
    model = cast(dict[str, Any], _DIRECT_TRANSPORT_MODELS[transport_identity])
    device_pattern = cast(re.Pattern[str], model["device_pattern"])
    if not device_pattern.fullmatch(root_name) or not device_pattern.fullmatch(
        physical_name
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The root and physical device names do not match the direct transport."
        )
    hardware_evidence = _mandatory_hardware_evidence(
        physical,
        transport_identity,
    )
    if (
        snapshot.get("transport_identity") != transport_identity
        or snapshot.get("hardware_evidence") != hardware_evidence
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The canonical transport or mandatory hardware evidence is incomplete."
        )
    queue = physical.get("queue")
    if type(queue) is not dict or not _MANDATORY_QUEUE_FIELDS.issubset(queue):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The physical write-cache and queue semantics are incomplete."
        )
    aliases = snapshot.get("stable_aliases")
    filesystem = snapshot.get("filesystem")
    if type(aliases) is not dict or type(filesystem) is not dict:
        raise ReferenceJournalUnsupportedFilesystemError(
            "Stable device and filesystem identities are unavailable."
        )
    uuid_aliases = aliases.get("by-uuid")
    id_aliases = aliases.get("by-id")
    partuuid_aliases = aliases.get("by-partuuid")
    if (
        type(uuid_aliases) is not tuple
        or len(uuid_aliases) != 1
        or type(id_aliases) is not tuple
        or not id_aliases
        or any(
            type(item) is not dict
            or type(item.get("name")) is not str
            or not cast(str, item["name"]).startswith("nvme-")
            for item in id_aliases
        )
        or type(partuuid_aliases) is not tuple
        or any(
            type(item) is not dict
            or item.get("device") != root_device
            or type(item.get("name")) is not str
            for category in (uuid_aliases, id_aliases, partuuid_aliases)
            if type(category) is tuple
            for item in category
        )
        or not _FILESYSTEM_UUID_PATTERN.fullmatch(uuid_aliases[0].get("name", ""))
        or filesystem.get("filesystem_uuid") != uuid_aliases[0].get("name")
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The filesystem UUID or stable device aliases are incomplete."
        )
    if partition_uuid is not None and (
        type(partuuid_aliases) is not tuple
        or len(partuuid_aliases) != 1
        or partuuid_aliases[0].get("name") != partition_uuid
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The stable partition alias does not match the live PARTUUID."
        )
    filesystem_type = filesystem.get("filesystem_type")
    required_feature_fields = {
        "feature_compat",
        "feature_incompat",
        "feature_ro_compat",
        "filesystem_uuid",
    }
    if filesystem_type == "ext4":
        required_feature_fields.update(
            {
                "checksum_seed",
                "descriptor_size",
                "hash_seed",
                "jbd2",
                "journal_uuid",
                "journal_device",
                "journal_device_format",
                "journal_has_internal",
                "journal_inode",
                "journal_inode_identity",
                "journal_needs_recovery",
                "mkfs_time",
                "revision",
                "volume_name_hex",
            }
        )
        jbd2 = filesystem.get("jbd2")
        journal_inode_identity = filesystem.get("journal_inode_identity")
        if (
            type(filesystem.get("feature_compat")) is not int
            or filesystem.get("feature_compat", 0) & _EXT4_HAS_JOURNAL == 0
            or filesystem.get("feature_compat", 0)
            & ~_EXT4_SUPPORTED_FEATURE_COMPAT
            or type(filesystem.get("feature_incompat")) is not int
            or filesystem.get("feature_incompat", 0) & _EXT4_JOURNAL_DEV
            or filesystem.get("feature_incompat", 0)
            & ~_EXT4_SUPPORTED_FEATURE_INCOMPAT
            or type(filesystem.get("feature_ro_compat")) is not int
            or filesystem.get("feature_ro_compat", 0)
            & ~_EXT4_SUPPORTED_FEATURE_RO_COMPAT
            or filesystem.get("journal_device") != 0
            or filesystem.get("journal_device_format") is not False
            or filesystem.get("journal_has_internal") is not True
            or type(filesystem.get("journal_inode")) is not int
            or filesystem.get("journal_inode", 0) <= 0
            or filesystem.get("journal_uuid") is not None
            or type(journal_inode_identity) is not dict
            or journal_inode_identity.get("inode")
            != filesystem.get("journal_inode")
            or type(journal_inode_identity.get("size")) is not int
            or journal_inode_identity.get("size", 0) <= 0
            or type(filesystem.get("block_size")) is not int
            or filesystem.get("block_size", 0) <= 0
            or type(jbd2) is not dict
            or set(jbd2) != _JBD2_IDENTITY_FIELDS
            or jbd2.get("magic") != _JBD2_MAGIC
            or jbd2.get("block_type") != _JBD2_SUPERBLOCK_V2
            or jbd2.get("block_size") != filesystem.get("block_size")
            or type(jbd2.get("maximum_length")) is not int
            or not (
                _JBD2_MIN_JOURNAL_BLOCKS
                <= jbd2.get("maximum_length", 0)
                <= journal_inode_identity.get("size", 0)
                // filesystem.get("block_size", 1)
            )
            or type(jbd2.get("fast_commit_blocks")) is not int
            or type(jbd2.get("normal_blocks")) is not int
            or jbd2.get("normal_blocks")
            != jbd2.get("maximum_length", 0)
            - jbd2.get("fast_commit_blocks", 0)
            or jbd2.get("normal_blocks", 0) < _JBD2_MIN_JOURNAL_BLOCKS
            or type(jbd2.get("first")) is not int
            or not 1 <= jbd2.get("first", 0) < jbd2.get("normal_blocks", 0)
            or jbd2.get("uuid") != filesystem.get("filesystem_uuid")
            or jbd2.get("users") != (filesystem.get("filesystem_uuid"),)
            or jbd2.get("users_count") != 1
            or jbd2.get("checksum_type") != _JBD2_CHECKSUM_TYPE_CRC32C
            or jbd2.get("checksum_semantics")
            != "crc32c-seed-ffffffff-zeroed-offset-00fc-full-1024"
            or jbd2.get("journal_superblock_bytes") != 1024
            or jbd2.get("feature_compat") != 0
            or type(jbd2.get("feature_incompat")) is not int
            or jbd2.get("feature_incompat", 0)
            & ~_JBD2_SUPPORTED_FEATURE_INCOMPAT
            or jbd2.get("feature_incompat", 0)
            & (
                _JBD2_FEATURE_INCOMPAT_CSUM_V2
                | _JBD2_FEATURE_INCOMPAT_CSUM_V3
            )
            not in {
                _JBD2_FEATURE_INCOMPAT_CSUM_V2,
                _JBD2_FEATURE_INCOMPAT_CSUM_V3,
            }
            or bool(
                jbd2.get("feature_incompat", 0)
                & _JBD2_FEATURE_INCOMPAT_FAST_COMMIT
            )
            != (jbd2.get("fast_commit_blocks", 0) > 0)
            or type(jbd2.get("dynamic_superblock")) is not int
            or not (
                jbd2.get("dynamic_superblock") == 0
                or jbd2.get("first", 0)
                <= jbd2.get("dynamic_superblock", 0)
                < jbd2.get("normal_blocks", 0)
            )
            or type(jbd2.get("maximum_transaction")) is not int
            or not 0
            <= jbd2.get("maximum_transaction", -1)
            <= jbd2.get("normal_blocks", 0)
            or type(jbd2.get("maximum_transaction_data")) is not int
            or not 0
            <= jbd2.get("maximum_transaction_data", -1)
            <= jbd2.get("normal_blocks", 0)
            or jbd2.get("feature_ro_compat") != 0
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The ext4 persistence journal is external or inconsistent."
            )
    elif filesystem_type == "xfs":
        required_feature_fields.update(
            {
                "feature_log_incompat",
                "features2",
                "log_start",
                "metadata_uuid",
                "realtime_blocks",
                "realtime_bitmap_blocks",
                "realtime_extent_size",
                "realtime_extents",
                "version",
                "volume_name_hex",
            }
        )
        if (
            type(filesystem.get("log_start")) is not int
            or filesystem.get("log_start", 0) <= 0
            or filesystem.get("realtime_blocks") != 0
            or filesystem.get("realtime_extents") != 0
            or filesystem.get("realtime_bitmap_blocks") != 0
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The XFS persistence log or realtime device is external."
            )
    if (
        filesystem_type not in _PRODUCTION_FILESYSTEM_TYPES
        or not required_feature_fields.issubset(filesystem)
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The live filesystem feature identity is incomplete."
        )
    kernel_release = snapshot.get("kernel_release")
    if (
        snapshot.get("schema")
        != "true-family/direct-linux-storage-stack-binding/v7"
        or type(kernel_release) is not str
        or not kernel_release
        or not _MOUNT_OPTION_PATTERN.fullmatch(kernel_release)
    ):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The production kernel identity is unavailable."
        )


def _storage_stack_binding_data(identity: _FilesystemIdentity) -> dict[str, Any]:
    if not os.path.isabs(identity.record.mount_source):
        raise ReferenceJournalUnsupportedFilesystemError(
            "The production mount source is not an exact block-device path."
        )
    try:
        source_stat = os.stat(identity.record.mount_source)
    except OSError as err:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The production mount source block device is unavailable."
        ) from err
    source_device = _device_key_from_stat(source_stat)
    if source_device != identity.device:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The mount source and mounted filesystem device do not match exactly."
        )

    root = _production_block_node(identity.device)
    root_type = root["uevent"].get("DEVTYPE")
    partition_parent: str | None = None
    nodes = {identity.device: root}
    if root_type == "partition":
        root_path = _sysfs_node_path(identity.device)
        partition_parent = _sysfs_device_key(os.path.dirname(root_path))
        if partition_parent == identity.device:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The partition parent identity is recursive."
            )
        nodes[partition_parent] = _production_block_node(partition_parent)

    partition_uuid = root["uevent"].get("PARTUUID")
    aliases, uuid_alias_path = _stable_device_aliases(
        identity.device,
        partition_uuid,
    )
    filesystem_uuid = aliases["by-uuid"][0]["name"]
    filesystem = _filesystem_feature_identity(
        identity.filesystem_type,
        identity.device,
        uuid_alias_path,
        filesystem_uuid,
    )
    physical = nodes[partition_parent] if partition_parent is not None else root
    transport_identity = _recognized_direct_transport(physical)
    hardware_evidence = _mandatory_hardware_evidence(
        physical,
        transport_identity,
    )
    snapshot = {
        "filesystem": filesystem,
        "hardware_evidence": hardware_evidence,
        "kernel_release": _kernel_release_identity(),
        "mount_source_device": source_device,
        "nodes": nodes,
        "partition_parent": partition_parent,
        "root_device": identity.device,
        "schema": "true-family/direct-linux-storage-stack-binding/v7",
        "stable_aliases": aliases,
        "transport_identity": transport_identity,
    }
    _validate_production_storage_snapshot(snapshot)
    return snapshot


def _storage_stack_binding_digest(identity: _FilesystemIdentity) -> str:
    """Digest two equal complete direct-device identity snapshots."""

    before = _storage_stack_binding_data(identity)
    after = _storage_stack_binding_data(identity)
    if before != after:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The deployed block-stack graph changed while it was inspected."
        )

    raw = json.dumps(
        after,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _validate_production_certification(
    certification: DurableFilesystemCertification,
    identity: _FilesystemIdentity,
    policy: DurableFilesystemPolicy,
) -> tuple[str, str]:
    certification.__post_init__(
        _TEST_CERTIFICATION_SEAL
        if certification.test_only
        else _PRODUCTION_CERTIFICATION_SEAL
    )
    if certification.test_only:
        raise ReferenceJournalCertificationError(
            "Test-only evidence cannot certify a production filesystem policy."
        )
    if certification.covered_persistence_primitive != PERSISTENCE_PRIMITIVE_ID:
        raise ReferenceJournalCertificationError(
            "External certification covers a different persistence primitive."
        )
    mount_binding = _mount_binding_digest(identity, policy)
    if certification.mount_binding_digest != mount_binding:
        raise ReferenceJournalCertificationError(
            "External certification does not match the live qualified mount."
        )
    storage_stack_binding = _storage_stack_binding_digest(identity)
    if certification.deployed_storage_stack_digest != storage_stack_binding:
        raise ReferenceJournalCertificationError(
            "External certification does not match the live deployed storage stack."
        )
    return mount_binding, storage_stack_binding


def _open_config_directory_chain(config_dir: str) -> list[tuple[str, int]]:
    try:
        root_fd = _retry_eintr(os.open, "/", _DIRECTORY_FLAGS)
    except OSError as err:
        raise _translate_os_error(
            "The filesystem root could not be opened safely.", err
        ) from err
    chain: list[tuple[str, int]] = [("/", root_fd)]
    if config_dir == "/":
        return chain
    current_path = ""
    try:
        for component in config_dir.split("/")[1:]:
            if not component or component in {".", ".."}:
                raise ReferenceJournalSecurityError(
                    "The trusted config path contains a noncanonical component."
                )
            parent_fd = chain[-1][1]
            before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            descriptor = _retry_eintr(
                os.open,
                component,
                _DIRECTORY_FLAGS,
                dir_fd=parent_fd,
            )
            after = os.fstat(descriptor)
            if not stat.S_ISDIR(before.st_mode) or not _same_inode(before, after):
                os.close(descriptor)
                raise ReferenceJournalSecurityError(
                    "A trusted config path component changed while opening."
                )
            current_path = f"{current_path}/{component}"
            chain.append((current_path, descriptor))
        return chain
    except BaseException:
        for _path, descriptor in reversed(chain):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _fsync_config_anchor(
    chain: list[tuple[str, int]],
    config_identity: _FilesystemIdentity,
    failpoint: FailpointCallback | None,
) -> None:
    mount_point = config_identity.mount_point
    mount_indexes = [
        index for index, (path, _fd) in enumerate(chain) if path == mount_point
    ]
    if len(mount_indexes) != 1:
        raise ReferenceJournalUnsupportedFilesystemError(
            "The config mount root is not an exact opened path component."
        )
    mount_index = mount_indexes[0]
    records = _read_mountinfo()
    for _path, descriptor in chain[mount_index:]:
        identity = _filesystem_identity_for_fd(descriptor, records)
        if identity.record != config_identity.record:
            raise ReferenceJournalUnsupportedFilesystemError(
                "The config anchor crosses an unexpected nested mount."
            )
    _fsync_boundary(chain[-1][1], failpoint, "config_directory_fsync")
    for ordinal, (_path, descriptor) in enumerate(
        reversed(chain[mount_index:-1])
    ):
        name = (
            "config_anchor_parent_fsync"
            if ordinal == 0
            else f"config_anchor_ancestor_{ordinal}_fsync"
        )
        _fsync_boundary(descriptor, failpoint, name)


def _validate_json_tree(value: Any) -> None:
    if type(value) is not dict:
        raise ReferenceJournalCorruptionError(
            "Reference journal JSON root must be a built-in mapping."
        )
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ReferenceJournalCorruptionError(
                "Reference journal JSON exceeds the node-count bound."
            )
        if depth > MAX_JSON_DEPTH:
            raise ReferenceJournalCorruptionError(
                "Reference journal JSON exceeds the nesting-depth bound."
            )
        if type(current) is dict:
            nodes += len(current)
            if nodes > MAX_JSON_NODES:
                raise ReferenceJournalCorruptionError(
                    "Reference journal JSON exceeds the node-count bound."
                )
            for key, item in current.items():
                if type(key) is not str:
                    raise ReferenceJournalCorruptionError(
                        "Reference journal JSON contains a non-string mapping key."
                    )
                if len(key) > MAX_JSON_STRING_BYTES:
                    raise ReferenceJournalCorruptionError(
                        "Reference journal mapping key exceeds the string bound."
                    )
                stack.append((item, depth + 1))
            continue
        if type(current) is list:
            stack.extend((item, depth + 1) for item in current)
            continue
        if type(current) is str:
            if len(current) > MAX_JSON_STRING_BYTES:
                raise ReferenceJournalCorruptionError(
                    "Reference journal string exceeds the string bound."
                )
            continue
        if current is None or type(current) is bool:
            continue
        if type(current) is int:
            if current.bit_length() > 426:
                raise ReferenceJournalCorruptionError(
                    "Reference journal integer exceeds the digit bound."
                )
            if len(str(abs(current))) > MAX_INTEGER_DIGITS:
                raise ReferenceJournalCorruptionError(
                    "Reference journal integer exceeds the digit bound."
                )
            continue
        if type(current) is float:
            if not math.isfinite(current):
                raise ReferenceJournalCorruptionError(
                    "Reference journal JSON contains a non-finite number."
                )
            continue
        raise ReferenceJournalCorruptionError(
            "Reference journal JSON contains an unsupported value type."
        )


class _DuplicateJSONKey(ValueError):
    pass


class _NonFiniteJSONNumber(ValueError):
    pass


def _json_lexical_preflight(raw: bytes, max_bytes: int) -> None:
    """Bound lexical allocation before Python's JSON decoder sees the root."""

    if len(raw) > max_bytes:
        raise ReferenceJournalCorruptionError(
            "Reference journal JSON exceeds the configured byte bound."
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ReferenceJournalCorruptionError(
            "Reference journal JSON must not contain a UTF-8 BOM."
        )
    stack: list[int] = []
    nodes = 0
    index = 0
    while index < len(raw):
        byte = raw[index]
        if byte >= 0x80:
            raise ReferenceJournalCorruptionError(
                "Canonical reference journal JSON must be ASCII escaped."
            )
        if byte <= 0x20:
            raise ReferenceJournalCorruptionError(
                "Canonical reference journal JSON must not contain whitespace."
            )
        if byte == 0x22:
            start = index
            index += 1
            while index < len(raw):
                current = raw[index]
                if current >= 0x80 or current < 0x20:
                    raise ReferenceJournalCorruptionError(
                        "Reference journal string contains noncanonical bytes."
                    )
                if current == 0x22:
                    index += 1
                    break
                if current == 0x5C:
                    index += 1
                    if index >= len(raw) or raw[index] not in b'"\\/bfnrtu':
                        raise ReferenceJournalCorruptionError(
                            "Reference journal string contains an invalid escape."
                        )
                    if raw[index] == 0x75:
                        if index + 4 >= len(raw) or any(
                            value not in b"0123456789abcdefABCDEF"
                            for value in raw[index + 1 : index + 5]
                        ):
                            raise ReferenceJournalCorruptionError(
                                "Reference journal string contains an invalid Unicode escape."
                            )
                        index += 4
                index += 1
                if index - start > MAX_JSON_STRING_BYTES:
                    raise ReferenceJournalCorruptionError(
                        "Reference journal string token exceeds the lexical bound."
                    )
            else:
                raise ReferenceJournalCorruptionError(
                    "Reference journal JSON contains an unterminated string."
                )
            nodes += 1
        elif byte in {0x7B, 0x5B}:
            stack.append(0x7D if byte == 0x7B else 0x5D)
            if len(stack) > MAX_JSON_DEPTH:
                raise ReferenceJournalCorruptionError(
                    "Reference journal JSON exceeds the nesting-depth bound."
                )
            nodes += 1
            index += 1
        elif byte in {0x7D, 0x5D}:
            if not stack or stack.pop() != byte:
                raise ReferenceJournalCorruptionError(
                    "Reference journal JSON has mismatched containers."
                )
            index += 1
        elif byte in {0x2C, 0x3A}:
            index += 1
        else:
            start = index
            if byte in b"-0123456789":
                while index < len(raw) and raw[index] in b"-+0123456789.eE":
                    index += 1
            elif byte in b"tfn":
                while index < len(raw) and 0x61 <= raw[index] <= 0x7A:
                    index += 1
                if raw[start:index] not in {b"true", b"false", b"null"}:
                    raise ReferenceJournalCorruptionError(
                        "Reference journal JSON contains an unknown literal."
                    )
            else:
                raise ReferenceJournalCorruptionError(
                    "Reference journal JSON contains an invalid token."
                )
            if index == start or index - start > MAX_JSON_TOKEN_BYTES:
                raise ReferenceJournalCorruptionError(
                    "Reference journal token exceeds the lexical bound."
                )
            nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ReferenceJournalCorruptionError(
                "Reference journal JSON exceeds the node-count bound."
            )
    if stack:
        raise ReferenceJournalCorruptionError(
            "Reference journal JSON contains an unterminated container."
        )


def _json_encoder() -> json.JSONEncoder:
    return json.JSONEncoder(
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_encode(data: dict[str, Any], max_bytes: int) -> bytes:
    _validate_json_tree(data)
    try:
        rendered = bytearray()
        for chunk in _json_encoder().iterencode(data):
            encoded = chunk.encode("utf-8")
            if len(rendered) + len(encoded) > max_bytes:
                raise ReferenceJournalCorruptionError(
                    "Reference journal JSON exceeds the configured byte bound."
                )
            rendered.extend(encoded)
        canonical = bytes(rendered)
    except ReferenceJournalCorruptionError:
        raise
    except (TypeError, ValueError) as err:
        raise ReferenceJournalCorruptionError(
            "Reference journal data cannot be encoded as canonical JSON."
        ) from err
    return canonical


def _matches_canonical_encoding(
    data: dict[str, Any],
    raw: bytes,
    max_bytes: int,
) -> bool:
    offset = 0
    try:
        for chunk in _json_encoder().iterencode(data):
            encoded = chunk.encode("utf-8")
            offset += len(encoded)
            if offset > max_bytes or raw[offset - len(encoded) : offset] != encoded:
                return False
    except (TypeError, ValueError):
        return False
    return offset == len(raw)


def _canonical_decode(raw: bytes, max_bytes: int) -> dict[str, Any]:
    _json_lexical_preflight(raw, max_bytes)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise ReferenceJournalCorruptionError(
            "Reference journal bytes are not strict UTF-8."
        ) from err

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateJSONKey(key)
            result[key] = value
        return result

    def parse_integer(value: str) -> int:
        digits = value[1:] if value.startswith("-") else value
        if len(digits) > MAX_INTEGER_DIGITS:
            raise ReferenceJournalCorruptionError(
                "Reference journal integer exceeds the digit bound."
            )
        return int(value)

    def parse_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise _NonFiniteJSONNumber(value)
        return parsed

    def reject_constant(value: str) -> None:
        raise _NonFiniteJSONNumber(value)

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
            parse_float=parse_float,
            parse_int=parse_integer,
        )
    except ReferenceJournalCorruptionError:
        raise
    except (
        _DuplicateJSONKey,
        _NonFiniteJSONNumber,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as err:
        raise ReferenceJournalCorruptionError(
            "Reference journal JSON is malformed."
        ) from err
    _validate_json_tree(decoded)
    normalized = cast(dict[str, Any], decoded)
    if not _matches_canonical_encoding(normalized, raw, max_bytes):
        raise ReferenceJournalCorruptionError(
            "Reference journal bytes are not exact canonical JSON."
        )
    return normalized


def _generation(data: dict[str, Any]) -> int:
    value = data.get("generation")
    if type(value) is not int or value < 0:
        raise ReferenceJournalCorruptionError(
            "Reference journal generation must be a nonnegative built-in integer."
        )
    return value


def _read_all(descriptor: int, max_bytes: int) -> bytes:
    raw = bytearray()
    while True:
        try:
            chunk = _retry_eintr(_raw_read, descriptor, _READ_CHUNK_SIZE)
        except OSError as err:
            raise ReferenceJournalIOError(
                "Reference journal bytes could not be read."
            ) from err
        if not chunk:
            return bytes(raw)
        raw.extend(chunk)
        if len(raw) > max_bytes:
            raise ReferenceJournalCorruptionError(
                "Reference journal JSON exceeds the configured byte bound."
            )


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    offset = 0
    while offset < len(view):
        try:
            written = _retry_eintr(_raw_write, descriptor, view[offset:])
        except OSError as err:
            raise ReferenceJournalIOError(
                "Reference journal temporary bytes could not be written."
            ) from err
        if written <= 0 or written > len(view) - offset:
            raise ReferenceJournalIOError(
                "Reference journal temporary write made invalid progress."
            )
        offset += written


def _read_lock_protocol(descriptor: int, expected_size: int) -> bytes:
    try:
        return _read_all(descriptor, expected_size + 1)
    except ReferenceJournalCorruptionError as err:
        raise ReferenceJournalSecurityError(
            "The persisted reference journal lock protocol exceeds its exact bound."
        ) from err


async def _await_owned_future(
    future: asyncio.Future[_T],
) -> tuple[_T, asyncio.CancelledError | None]:
    cancelled: asyncio.CancelledError | None = None
    while True:
        try:
            return await asyncio.shield(future), cancelled
        except asyncio.CancelledError as err:
            if future.cancelled():
                raise
            if cancelled is None:
                cancelled = err


class CrashDurableReferenceJournalStore:
    """One cross-process locked, generation-CAS reference journal backend.

    Every supported instance verifies the persisted lock protocol before doing
    journal I/O.  Same-EUID/root code that ignores that advisory protocol or
    races namespace entries is outside the supported-writer boundary.
    """

    def __init__(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        executor: ThreadPoolExecutor,
        resources: _OpenedResources,
        filesystem_policy: DurableFilesystemPolicy,
        filesystem_certification: DurableFilesystemCertification | None,
        config_dir: str,
        journal_id: str,
        max_bytes: int,
        failpoint: FailpointCallback | None,
    ) -> None:
        self._loop = loop
        self._executor = executor
        self._resources = resources
        self._config_fd = resources.config_fd
        self._directory_fd = resources.directory_fd
        self._lock_fd = resources.lock_fd
        self._filesystem = resources.filesystem
        self._filesystem_policy = filesystem_policy
        self._filesystem_certification = filesystem_certification
        self._mount_binding_digest = resources.mount_binding_digest
        self._storage_stack_binding_digest = resources.block_stack_binding_digest
        self._config_dir = config_dir
        self._config_identity = resources.config_identity
        self._directory_identity = resources.directory_identity
        self._lock_identity = resources.lock_identity
        self._final_name, self._temp_name, self._lock_name = _file_names(journal_id)
        self._lock_protocol = _lock_protocol_bytes(journal_id)
        self._max_bytes = max_bytes
        self._failpoint = failpoint
        self._pid = os.getpid()
        self._state_lock = threading.Lock()
        self._closing = False
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None
        self._snapshot: _Snapshot | None = None
        self._save_ready = False
        self._commit_stamp: _CommitStamp | None = None
        self._sequence = 0
        self._poison_type: type[ReferenceJournalPoisonedError] | None = None
        self._poison_message: str | None = None
        self._durability_proof: (
            ReferenceJournalDurabilityProof
            | ReferenceJournalTestDurabilityProof
            | None
        ) = None

    @classmethod
    async def async_open(
        cls,
        *,
        config_dir: str,
        journal_id: str,
        filesystem_policy: DurableFilesystemPolicy | None = None,
        filesystem_certification: DurableFilesystemCertification | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        failpoint: FailpointCallback | None = None,
    ) -> Self:
        """Open one journal with explicit production power-cut certification.

        A qualified production mount is necessary but insufficient.  Its caller
        must supply external evidence for the exact live mount, storage stack,
        and persistence primitive before this method can create journal state.
        """

        if sys.platform != "linux" or not all(
            (_O_CLOEXEC, _O_DIRECTORY, _O_NOFOLLOW, _O_NONBLOCK)
        ):
            raise ReferenceJournalUnsupportedFilesystemError(
                "The crash-durable journal backend requires Linux openat flags."
            )
        if (
            type(config_dir) is not str
            or not os.path.isabs(config_dir)
            or os.path.normpath(config_dir) != config_dir
        ):
            raise ReferenceJournalSecurityError(
                "The trusted config directory must be a canonical absolute path."
            )
        canonical_journal_id = journal_id
        reference_journal_basename(canonical_journal_id)
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_CONFIGURED_BYTES:
            raise ValueError("max_bytes is outside the supported bounded range.")
        policy = (
            _SEALED_PRODUCTION_DURABLE_FILESYSTEM_POLICY
            if filesystem_policy is None
            else filesystem_policy
        )
        if type(policy) is not DurableFilesystemPolicy:
            raise TypeError("A DurableFilesystemPolicy instance is required.")
        certification = filesystem_certification
        if (
            certification is not None
            and type(certification) is not DurableFilesystemCertification
        ):
            raise TypeError("A DurableFilesystemCertification instance is required.")
        if policy.test_only:
            if certification is not None:
                certification.__post_init__(
                    _TEST_CERTIFICATION_SEAL
                    if certification.test_only
                    else _PRODUCTION_CERTIFICATION_SEAL
                )
                if not certification.test_only:
                    raise ReferenceJournalCertificationError(
                        "Production certification cannot be consumed by a "
                        "test-only policy."
                    )
        else:
            if certification is None:
                raise ReferenceJournalCertificationError(
                    "Production journal storage requires explicit external "
                    "power-cut certification."
                )
            certification.__post_init__(
                _TEST_CERTIFICATION_SEAL
                if certification.test_only
                else _PRODUCTION_CERTIFICATION_SEAL
            )
            if certification.test_only:
                raise ReferenceJournalCertificationError(
                    "Test-only evidence cannot certify production journal storage."
                )
            if (
                certification.covered_persistence_primitive
                != PERSISTENCE_PRIMITIVE_ID
            ):
                raise ReferenceJournalCertificationError(
                    "External certification covers a different persistence primitive."
                )
        if failpoint is not None and not callable(failpoint):
            raise TypeError("failpoint must be callable.")

        loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="true-family-reference-journal-file",
        )
        future = loop.run_in_executor(
            executor,
            cls._open_sync,
            config_dir,
            canonical_journal_id,
            policy,
            certification,
            failpoint,
        )
        try:
            resources, cancelled = await _await_owned_future(future)
        except BaseException:
            executor.shutdown(wait=False, cancel_futures=False)
            raise
        if cancelled is not None:
            cleanup = loop.run_in_executor(
                executor,
                cls._close_opened_resources,
                resources,
                True,
            )
            try:
                await _await_owned_future(cleanup)
            finally:
                executor.shutdown(wait=False, cancel_futures=False)
            raise cancelled
        return cls(
            loop=loop,
            executor=executor,
            resources=resources,
            filesystem_policy=policy,
            filesystem_certification=certification,
            config_dir=config_dir,
            journal_id=canonical_journal_id,
            max_bytes=max_bytes,
            failpoint=failpoint,
        )

    @staticmethod
    def _open_sync(
        config_dir: str,
        journal_id: str,
        policy: DurableFilesystemPolicy,
        certification: DurableFilesystemCertification | None,
        failpoint: FailpointCallback | None,
    ) -> _OpenedResources:
        with _FORK_OPERATION_LOCK:
            return CrashDurableReferenceJournalStore._open_sync_locked(
                config_dir,
                journal_id,
                policy,
                certification,
                failpoint,
            )

    @staticmethod
    def _open_sync_locked(
        config_dir: str,
        journal_id: str,
        policy: DurableFilesystemPolicy,
        certification: DurableFilesystemCertification | None,
        failpoint: FailpointCallback | None,
    ) -> _OpenedResources:
        config_fd = -1
        directory_fd = -1
        lock_fd = -1
        lock_held = False
        config_chain: list[tuple[str, int]] = []
        try:
            try:
                config_chain = _open_config_directory_chain(config_dir)
                path_stat = _retry_eintr(os.lstat, config_dir)
                config_fd = config_chain[-1][1]
            except OSError as err:
                raise _translate_os_error(
                    "The trusted config directory could not be opened safely.", err
                ) from err
            descriptor_stat = os.fstat(config_fd)
            _validate_config_directory(path_stat)
            _validate_config_directory(descriptor_stat)
            if not _same_inode(path_stat, descriptor_stat):
                raise ReferenceJournalSecurityError(
                    "The trusted config directory changed while opening."
                )

            mount_records = _read_mountinfo()
            config_filesystem = _filesystem_identity_for_fd(config_fd, mount_records)
            if config_filesystem.descriptor_path != config_dir:
                raise ReferenceJournalSecurityError(
                    "The securely traversed config path changed while opening."
                )
            _qualify_filesystem(config_filesystem, policy)
            if policy.test_only:
                mount_binding = _mount_binding_digest(config_filesystem, policy)
                storage_stack_binding = None
            else:
                if certification is None:
                    raise ReferenceJournalCertificationError(
                        "Production power-cut certification disappeared before validation."
                    )
                mount_binding, storage_stack_binding = (
                    _validate_production_certification(
                        certification,
                        config_filesystem,
                        policy,
                    )
                )

            created_directory = False
            try:
                directory_fd = _retry_eintr(
                    os.open,
                    REFERENCE_JOURNAL_DIRECTORY_NAME,
                    _DIRECTORY_FLAGS,
                    dir_fd=config_fd,
                )
            except OSError as err:
                if err.errno != errno.ENOENT:
                    raise _translate_os_error(
                        "The reference journal directory could not be opened safely.",
                        err,
                    ) from err
                _hit(failpoint, "before_store_directory_create")
                try:
                    _retry_eintr(
                        os.mkdir,
                        REFERENCE_JOURNAL_DIRECTORY_NAME,
                        0o700,
                        dir_fd=config_fd,
                    )
                    created_directory = True
                except OSError as mkdir_err:
                    if mkdir_err.errno != errno.EEXIST:
                        raise _translate_os_error(
                            "The reference journal directory could not be created.",
                            mkdir_err,
                        ) from mkdir_err
                try:
                    directory_fd = _retry_eintr(
                        os.open,
                        REFERENCE_JOURNAL_DIRECTORY_NAME,
                        _DIRECTORY_FLAGS,
                        dir_fd=config_fd,
                    )
                except OSError as open_err:
                    raise _translate_os_error(
                        "The created reference journal directory is unsafe.",
                        open_err,
                    ) from open_err
                if created_directory:
                    os.fchmod(directory_fd, 0o700)
                    _hit(failpoint, "after_store_directory_create")

            directory_stat = os.fstat(directory_fd)
            _validate_store_directory(
                directory_stat,
                config_device=descriptor_stat.st_dev,
            )
            named_directory_stat = os.stat(
                REFERENCE_JOURNAL_DIRECTORY_NAME,
                dir_fd=config_fd,
                follow_symlinks=False,
            )
            if not _same_inode(directory_stat, named_directory_stat):
                raise ReferenceJournalSecurityError(
                    "The reference journal directory changed while opening."
                )

            directory_filesystem = _filesystem_identity_for_fd(
                directory_fd,
                mount_records,
            )
            if directory_filesystem.record != config_filesystem.record:
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The journal child is an unexpected nested or substituted mount."
                )
            _qualify_filesystem(directory_filesystem, policy)
            # Re-fsync even an existing child so an interrupted earlier
            # provisioning attempt cannot be mistaken for durable creation.
            _fsync_boundary(
                directory_fd,
                failpoint,
                "store_directory_fsync",
            )
            _fsync_config_anchor(config_chain, config_filesystem, failpoint)
            for _path, ancestor_fd in reversed(config_chain[:-1]):
                os.close(ancestor_fd)
            config_chain = []

            _final_name, temp_name, lock_name = _file_names(journal_id)
            created_lock = False
            try:
                _hit(failpoint, "before_lock_create")
                lock_fd = _retry_eintr(
                    os.open,
                    lock_name,
                    _WRITE_FILE_FLAGS | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
                created_lock = True
                os.fchmod(lock_fd, 0o600)
                _hit(failpoint, "after_lock_create")
            except OSError as err:
                if err.errno != errno.EEXIST:
                    raise _translate_os_error(
                        "The reference journal lock could not be created safely.", err
                    ) from err
                try:
                    lock_fd = _retry_eintr(
                        os.open,
                        lock_name,
                        _WRITE_FILE_FLAGS,
                        dir_fd=directory_fd,
                    )
                except OSError as open_err:
                    raise _translate_os_error(
                        "The existing reference journal lock is unsafe.", open_err
                    ) from open_err

            lock_stat = os.fstat(lock_fd)
            _validate_regular_file(
                lock_stat,
                directory_device=directory_stat.st_dev,
                label="Reference journal lock",
            )
            try:
                _retry_eintr(fcntl.flock, lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_held = True
            except OSError as err:
                if err.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise ReferenceJournalBusyError(
                        "Another backend owns the reference journal lock."
                    ) from err
                raise _translate_os_error(
                    "The reference journal lock could not be acquired.", err
                ) from err
            expected_lock_protocol = _lock_protocol_bytes(journal_id)
            initialize_lock_protocol = created_lock
            if not created_lock:
                _retry_eintr(os.lseek, lock_fd, 0, os.SEEK_SET)
                persisted_lock_protocol = _read_lock_protocol(
                    lock_fd,
                    len(expected_lock_protocol),
                )
                if not persisted_lock_protocol:
                    initialize_lock_protocol = True
                elif persisted_lock_protocol != expected_lock_protocol:
                    raise ReferenceJournalSecurityError(
                        "The persisted reference journal lock protocol is invalid."
                    )
            if initialize_lock_protocol:
                _hit(failpoint, "before_lock_protocol_write")
                _retry_eintr(os.lseek, lock_fd, 0, os.SEEK_SET)
                _write_all(lock_fd, expected_lock_protocol)
                _retry_eintr(os.ftruncate, lock_fd, len(expected_lock_protocol))
                _hit(failpoint, "after_lock_protocol_write")
            named_lock_stat = os.stat(
                lock_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            _validate_regular_file(
                named_lock_stat,
                directory_device=directory_stat.st_dev,
                label="Named reference journal lock",
            )
            if not _same_inode(lock_stat, named_lock_stat):
                raise ReferenceJournalSecurityError(
                    "The reference journal lock changed while opening."
                )
            # The same restart rule applies to a lock left by a failed opener.
            _fsync_boundary(lock_fd, failpoint, "lock_file_fsync")
            _fsync_boundary(directory_fd, failpoint, "lock_directory_fsync")
            lock_stat = os.fstat(lock_fd)
            if lock_stat.st_size != len(expected_lock_protocol):
                raise ReferenceJournalSecurityError(
                    "The reference journal lock protocol size changed unexpectedly."
                )

            CrashDurableReferenceJournalStore._remove_stale_temp_sync(
                directory_fd,
                directory_stat.st_dev,
                temp_name,
                failpoint,
            )
            resources = _OpenedResources(
                config_fd=config_fd,
                directory_fd=directory_fd,
                lock_fd=lock_fd,
                filesystem=directory_filesystem,
                mount_binding_digest=mount_binding,
                block_stack_binding_digest=storage_stack_binding,
                config_identity=(descriptor_stat.st_dev, descriptor_stat.st_ino),
                directory_identity=(directory_stat.st_dev, directory_stat.st_ino),
                lock_identity=(lock_stat.st_dev, lock_stat.st_ino),
            )
            _track_resources(resources)
            return resources
        except BaseException as err:
            closed: set[int] = set()
            for _path, descriptor in reversed(config_chain):
                if descriptor >= 0 and descriptor not in closed:
                    closed.add(descriptor)
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            for descriptor in (directory_fd, config_fd):
                if descriptor >= 0 and descriptor not in closed:
                    closed.add(descriptor)
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if lock_fd >= 0:
                if lock_held:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                try:
                    os.close(lock_fd)
                except OSError:
                    pass
            if isinstance(err, ReferenceJournalFileError):
                raise
            if isinstance(err, OSError):
                raise _translate_os_error(
                    "The reference journal backend could not be opened.", err
                ) from err
            if isinstance(err, Exception):
                raise ReferenceJournalPoisonedError(
                    "A journal provisioning persistence boundary failed."
                ) from err
            raise

    @staticmethod
    def _remove_stale_temp_sync(
        directory_fd: int,
        directory_device: int,
        temp_name: str,
        failpoint: FailpointCallback | None,
    ) -> None:
        try:
            named_stat = os.stat(
                temp_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as err:
            if err.errno == errno.ENOENT:
                return
            raise _translate_os_error(
                "The stale journal temporary path could not be inspected.", err
            ) from err
        _validate_regular_file(
            named_stat,
            directory_device=directory_device,
            label="Stale reference journal temporary file",
        )
        try:
            descriptor = _retry_eintr(
                os.open,
                temp_name,
                _WRITE_FILE_FLAGS,
                dir_fd=directory_fd,
            )
        except OSError as err:
            raise _translate_os_error(
                "The stale journal temporary file could not be opened safely.", err
            ) from err
        try:
            descriptor_stat = os.fstat(descriptor)
            _validate_regular_file(
                descriptor_stat,
                directory_device=directory_device,
                label="Opened stale reference journal temporary file",
            )
            repeated_stat = os.stat(
                temp_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if not _same_inode(named_stat, descriptor_stat) or not _same_inode(
                descriptor_stat, repeated_stat
            ):
                raise ReferenceJournalSecurityError(
                    "The stale journal temporary file changed during inspection."
                )
            _hit(failpoint, "before_stale_temp_unlink")
            _retry_eintr(os.unlink, temp_name, dir_fd=directory_fd)
            _hit(failpoint, "after_stale_temp_unlink")
        finally:
            os.close(descriptor)
        _fsync_boundary(
            directory_fd,
            failpoint,
            "stale_temp_directory_fsync",
        )

    @staticmethod
    def _close_opened_resources(
        resources: _OpenedResources,
        lock_held: bool = True,
    ) -> None:
        with _FORK_OPERATION_LOCK:
            _untrack_resources(resources)
            config_fd = resources.config_fd
            directory_fd = resources.directory_fd
            lock_fd = resources.lock_fd
            transient_fd = resources.transient_temp_fd
            resources.config_fd = -1
            resources.directory_fd = -1
            resources.lock_fd = -1
            resources.transient_temp_fd = -1
            for descriptor in (transient_fd, config_fd, directory_fd):
                if descriptor < 0:
                    continue
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if lock_fd >= 0:
                if lock_held:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                try:
                    os.close(lock_fd)
                except OSError:
                    pass

    @property
    def durability_proof(
        self,
    ) -> ReferenceJournalDurabilityProof | ReferenceJournalTestDurabilityProof:
        """Return a test-only claim or externally certified production proof."""

        self._require_pid()
        with self._state_lock:
            if self._durability_proof is None:
                from .reference_migration_ha import (
                    _issue_file_reference_journal_durability_proof,
                )

                if self._filesystem_policy.test_only:
                    root_digest = hashlib.sha256(
                        os.fsencode(self._filesystem.root)
                    ).hexdigest()[:16]
                    provider_id = (
                        "tf/test-only-linux-reference-journal/v3;"
                        f"p={self._filesystem_policy.policy_id};"
                        f"m={self._filesystem.mount_id};"
                        f"r={root_digest};"
                        f"f={self._filesystem.filesystem_type};"
                        f"d={self._filesystem.device};"
                        f"q={self._mount_binding_digest};"
                        f"l={_LOCK_PROTOCOL_PROOF_ID};"
                        "s=lock-respecting"
                    )
                else:
                    certification = self._filesystem_certification
                    storage_stack_binding = self._storage_stack_binding_digest
                    if (
                        certification is None
                        or certification.test_only
                        or storage_stack_binding is None
                    ):
                        raise ReferenceJournalCertificationError(
                            "Production durability proof lacks validated external evidence."
                        )
                    proof_binding = hashlib.sha256(
                        json.dumps(
                            {
                                "certification_digest": certification.certification_digest,
                                "cooperative_lock_scope": "lock-respecting-writers-only",
                                "covered_persistence_primitive": PERSISTENCE_PRIMITIVE_ID,
                                "lock_protocol": _LOCK_PROTOCOL_ID,
                                "mount_binding_digest": self._mount_binding_digest,
                                "policy_id": self._filesystem_policy.policy_id,
                                "storage_stack_binding_digest": storage_stack_binding,
                            },
                            allow_nan=False,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode("ascii")
                    ).hexdigest()
                    provider_id = (
                        "tf/certified-linux-reference-journal/v8;"
                        f"p={self._filesystem_policy.policy_id};"
                        f"m={self._filesystem.mount_id};"
                        f"c={certification.certification_digest};"
                        f"x={proof_binding};"
                        f"l={_LOCK_PROTOCOL_PROOF_ID};"
                        "s=lock-respecting"
                    )
                self._durability_proof = (
                    _issue_file_reference_journal_durability_proof(
                        self,
                        provider_id,
                    )
                )
            return self._durability_proof

    async def async_load(self) -> dict[str, Any] | None:
        """Load exact canonical bytes and establish the next save CAS snapshot."""

        return await self._async_submit(self._load_sync)

    async def async_save(self, data: dict[str, Any]) -> None:
        """CAS-replace exactly the next generation and record one commit stamp."""

        await self._async_submit(self._save_sync, data)

    async def async_barrier(self) -> None:
        """Reverify and consume the immediately preceding save's commit stamp."""

        await self._async_submit(self._barrier_sync)

    async def _async_submit(
        self,
        function: Callable[..., _T],
        *args: Any,
    ) -> _T:
        self._require_pid()
        if asyncio.get_running_loop() is not self._loop:
            raise ReferenceJournalProtocolError(
                "The journal backend must remain on its opening event loop."
            )
        with self._state_lock:
            if self._closing or self._closed:
                raise ReferenceJournalClosedError(
                    "The reference journal backend is closing or closed."
                )
            future = self._loop.run_in_executor(
                self._executor,
                self._run_fork_safe,
                function,
                *args,
            )
        result, cancelled = await _await_owned_future(future)
        if cancelled is not None:
            raise cancelled
        return result

    @staticmethod
    def _run_fork_safe(function: Callable[..., _T], *args: Any) -> _T:
        with _FORK_OPERATION_LOCK:
            return function(*args)

    def _require_pid(self) -> None:
        if os.getpid() != self._pid:
            raise ReferenceJournalForkError(
                "A reference journal backend cannot be used after fork."
            )

    def _raise_if_poisoned(self) -> None:
        if self._poison_type is not None and self._poison_message is not None:
            raise self._poison_type(self._poison_message)

    def _poison(
        self,
        err: BaseException,
        *,
        ambiguous: bool,
    ) -> ReferenceJournalPoisonedError:
        if ambiguous:
            poison_type: type[ReferenceJournalPoisonedError] = (
                ReferenceJournalAmbiguousDurabilityError
            )
            message = (
                "Reference journal durability is ambiguous after atomic replacement; "
                "close, reopen, and reconcile exact durable bytes."
            )
        else:
            poison_type = ReferenceJournalPoisonedError
            message = (
                "Reference journal save failed before a durable commit; this object "
                "is poisoned and must be reopened."
            )
        self._poison_type = poison_type
        self._poison_message = message
        return poison_type(message)

    def _verify_open_state(self) -> None:
        """Revalidate every held and named security identity before I/O."""

        try:
            path_stat = _retry_eintr(os.lstat, self._config_dir)
            config_stat = os.fstat(self._config_fd)
            _validate_config_directory(path_stat)
            _validate_config_directory(config_stat)
            if (
                (config_stat.st_dev, config_stat.st_ino) != self._config_identity
                or not _same_inode(path_stat, config_stat)
            ):
                raise ReferenceJournalSecurityError(
                    "The trusted config directory identity changed after open."
                )

            directory_stat = os.fstat(self._directory_fd)
            _validate_store_directory(
                directory_stat,
                config_device=config_stat.st_dev,
            )
            named_directory = os.stat(
                REFERENCE_JOURNAL_DIRECTORY_NAME,
                dir_fd=self._config_fd,
                follow_symlinks=False,
            )
            if (
                (directory_stat.st_dev, directory_stat.st_ino)
                != self._directory_identity
                or not _same_inode(directory_stat, named_directory)
            ):
                raise ReferenceJournalSecurityError(
                    "The reference journal directory identity changed after open."
                )

            lock_stat = os.fstat(self._lock_fd)
            named_lock = os.stat(
                self._lock_name,
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
            _validate_regular_file(
                lock_stat,
                directory_device=directory_stat.st_dev,
                label="Held reference journal lock",
            )
            _validate_regular_file(
                named_lock,
                directory_device=directory_stat.st_dev,
                label="Named reference journal lock",
            )
            if (
                (lock_stat.st_dev, lock_stat.st_ino) != self._lock_identity
                or not _same_inode(lock_stat, named_lock)
            ):
                raise ReferenceJournalSecurityError(
                    "The reference journal lock identity changed after open."
                )

            expected_lock_protocol = self._lock_protocol
            if lock_stat.st_size != len(expected_lock_protocol):
                raise ReferenceJournalSecurityError(
                    "The persisted lock protocol size changed after open."
                )
            _retry_eintr(os.lseek, self._lock_fd, 0, os.SEEK_SET)
            if _read_lock_protocol(
                self._lock_fd,
                len(expected_lock_protocol),
            ) != expected_lock_protocol:
                raise ReferenceJournalSecurityError(
                    "The persisted lock protocol changed after open."
                )

            current_filesystem = _filesystem_identity_for_fd(self._directory_fd)
            if current_filesystem != self._filesystem:
                raise ReferenceJournalUnsupportedFilesystemError(
                    "The reference journal mount identity changed after open."
                )
            _qualify_filesystem(current_filesystem, self._filesystem_policy)
            current_mount_binding = _mount_binding_digest(
                current_filesystem,
                self._filesystem_policy,
            )
            if current_mount_binding != self._mount_binding_digest:
                raise ReferenceJournalCertificationError(
                    "The qualified mount no longer matches its opening binding."
                )
            if not self._filesystem_policy.test_only:
                current_storage_stack = _storage_stack_binding_digest(
                    current_filesystem
                )
                if current_storage_stack != self._storage_stack_binding_digest:
                    raise ReferenceJournalCertificationError(
                        "The deployed storage stack changed after certification validation."
                    )
        except ReferenceJournalFileError:
            raise
        except OSError as err:
            raise _translate_os_error(
                "A held reference journal security identity could not be revalidated.",
                err,
            ) from err

    def _read_named_final(self) -> _ReadResult | None:
        try:
            return self._read_named_final_unwrapped()
        except ReferenceJournalFileError:
            raise
        except OSError as err:
            raise _translate_os_error(
                "The reference journal final inode could not be verified.", err
            ) from err

    def _read_named_final_unwrapped(self) -> _ReadResult | None:
        directory_stat = os.fstat(self._directory_fd)
        try:
            named_before = os.stat(
                self._final_name,
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
        except OSError as err:
            if err.errno == errno.ENOENT:
                return None
            raise _translate_os_error(
                "The reference journal final path could not be inspected.", err
            ) from err
        _validate_regular_file(
            named_before,
            directory_device=directory_stat.st_dev,
            label="Reference journal final file",
        )
        if named_before.st_size > self._max_bytes:
            raise ReferenceJournalCorruptionError(
                "Reference journal JSON exceeds the configured byte bound."
            )
        try:
            descriptor = _retry_eintr(
                os.open,
                self._final_name,
                _READ_FILE_FLAGS,
                dir_fd=self._directory_fd,
            )
        except OSError as err:
            if err.errno == errno.ENOENT:
                try:
                    os.stat(
                        self._final_name,
                        dir_fd=self._directory_fd,
                        follow_symlinks=False,
                    )
                except OSError as repeated_err:
                    if repeated_err.errno == errno.ENOENT:
                        return None
                raise ReferenceJournalConflictError(
                    "The reference journal final path changed while opening."
                ) from err
            raise _translate_os_error(
                "The reference journal final file could not be opened safely.", err
            ) from err
        try:
            opened_before = os.fstat(descriptor)
            _validate_regular_file(
                opened_before,
                directory_device=directory_stat.st_dev,
                label="Opened reference journal final file",
            )
            if not _same_inode(named_before, opened_before):
                raise ReferenceJournalConflictError(
                    "The reference journal final inode changed while opening."
                )
            raw = _read_all(descriptor, self._max_bytes)
            opened_after = os.fstat(descriptor)
            if _stat_signature(opened_before) != _stat_signature(opened_after):
                raise ReferenceJournalConflictError(
                    "The reference journal final inode changed while reading."
                )
            if len(raw) != opened_after.st_size:
                raise ReferenceJournalConflictError(
                    "The reference journal byte count did not match its inode size."
                )
            named_after = os.stat(
                self._final_name,
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
            _validate_regular_file(
                named_after,
                directory_device=directory_stat.st_dev,
                label="Reverified reference journal final file",
            )
            if not _same_inode(opened_after, named_after):
                raise ReferenceJournalConflictError(
                    "The reference journal final path changed while reading."
                )
        finally:
            os.close(descriptor)
        data = _canonical_decode(raw, self._max_bytes)
        generation = _generation(data)
        return _ReadResult(
            data=data,
            snapshot=_Snapshot(
                raw=raw,
                device=opened_after.st_dev,
                inode=opened_after.st_ino,
                generation=generation,
            ),
        )

    @staticmethod
    def _snapshots_match(first: _Snapshot, second: _Snapshot) -> bool:
        return first == second

    def _load_sync(self) -> dict[str, Any] | None:
        self._require_pid()
        self._raise_if_poisoned()
        if self._commit_stamp is not None:
            raise ReferenceJournalProtocolError(
                "A committed save must be barriered before another load."
            )
        try:
            self._verify_open_state()
            loaded = self._read_named_final()
        except ReferenceJournalFileError as err:
            self._poison_type = ReferenceJournalPoisonedError
            self._poison_message = (
                "Reference journal load failed closed; reopen after repairing "
                "the durable file."
            )
            raise err
        self._sequence += 1
        if loaded is None:
            self._snapshot = _Snapshot.absent()
            self._save_ready = True
            return None
        self._snapshot = loaded.snapshot
        self._save_ready = True
        return loaded.data

    def _create_temp(self) -> int:
        _hit(self._failpoint, "before_temp_create")
        try:
            descriptor = _retry_eintr(
                os.open,
                self._temp_name,
                _WRITE_FILE_FLAGS | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=self._directory_fd,
            )
        except OSError as err:
            if err.errno == errno.EEXIST:
                raise ReferenceJournalSecurityError(
                    "A journal temporary file appeared while the lock was held."
                ) from err
            raise _translate_os_error(
                "The journal temporary file could not be created safely.", err
            ) from err
        self._resources.transient_temp_fd = descriptor
        try:
            os.fchmod(descriptor, 0o600)
            descriptor_stat = os.fstat(descriptor)
            _validate_regular_file(
                descriptor_stat,
                directory_device=os.fstat(self._directory_fd).st_dev,
                label="New reference journal temporary file",
            )
            _hit(self._failpoint, "after_temp_create")
            return descriptor
        except BaseException:
            self._resources.transient_temp_fd = -1
            os.close(descriptor)
            raise

    def _save_sync(self, data: dict[str, Any]) -> None:
        self._require_pid()
        self._raise_if_poisoned()
        if self._commit_stamp is not None:
            raise ReferenceJournalProtocolError(
                "A committed save must be barriered before another save."
            )
        if not self._save_ready or self._snapshot is None:
            raise ReferenceJournalProtocolError(
                "Reference journal save requires a preceding successful load."
            )

        replace_attempted = False
        renamed = False
        temp_fd = -1
        try:
            self._verify_open_state()
            raw = _canonical_encode(data, self._max_bytes)
            candidate = _canonical_decode(raw, self._max_bytes)
            candidate_generation = _generation(candidate)
            expected_generation = (
                0
                if self._snapshot.raw is None
                else cast(int, self._snapshot.generation) + 1
            )
            if candidate_generation != expected_generation:
                raise ReferenceJournalConflictError(
                    "Reference journal save is not exactly the next generation."
                )

            current = self._read_named_final()
            current_snapshot = (
                _Snapshot.absent() if current is None else current.snapshot
            )
            if not self._snapshots_match(self._snapshot, current_snapshot):
                raise ReferenceJournalConflictError(
                    "Reference journal inode-and-byte compare-and-swap failed."
                )

            temp_fd = self._create_temp()
            _hit(self._failpoint, "before_temp_write")
            _write_all(temp_fd, raw)
            _hit(self._failpoint, "after_temp_write")
            _fsync_boundary(temp_fd, self._failpoint, "temp_file_fsync")
            _retry_eintr(os.lseek, temp_fd, 0, os.SEEK_SET)
            if _read_all(temp_fd, self._max_bytes) != raw:
                raise ReferenceJournalIOError(
                    "Reference journal temporary read-back did not match exactly."
                )
            temp_stat = os.fstat(temp_fd)
            _validate_regular_file(
                temp_stat,
                directory_device=os.fstat(self._directory_fd).st_dev,
                label="Fsynced reference journal temporary file",
            )
            named_temp_stat = os.stat(
                self._temp_name,
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
            if not _same_inode(temp_stat, named_temp_stat):
                raise ReferenceJournalSecurityError(
                    "The journal temporary inode changed before replacement."
                )

            _hit(self._failpoint, "before_replace")
            replace_attempted = True
            _retry_eintr(
                _raw_replace,
                self._temp_name,
                self._final_name,
                src_dir_fd=self._directory_fd,
                dst_dir_fd=self._directory_fd,
            )
            renamed = True
            _hit(self._failpoint, "after_replace")

            replaced = self._read_named_final()
            if (
                replaced is None
                or replaced.snapshot.raw != raw
                or replaced.snapshot.device != temp_stat.st_dev
                or replaced.snapshot.inode != temp_stat.st_ino
                or replaced.snapshot.generation != candidate_generation
            ):
                raise ReferenceJournalConflictError(
                    "Atomic replacement did not produce the exact temporary inode."
                )
            _fsync_boundary(
                self._directory_fd,
                self._failpoint,
                "commit_directory_fsync",
            )
            reopened = self._read_named_final()
            if reopened is None or not self._snapshots_match(
                replaced.snapshot, reopened.snapshot
            ):
                raise ReferenceJournalConflictError(
                    "Durable reference journal reopen verification failed."
                )
            descriptor_to_close = temp_fd
            temp_fd = -1
            self._resources.transient_temp_fd = -1
            _raw_temp_close(descriptor_to_close)

            self._sequence += 1
            self._snapshot = reopened.snapshot
            self._save_ready = False
            self._commit_stamp = _CommitStamp(
                snapshot=reopened.snapshot,
                sequence=self._sequence,
            )
        except BaseException as err:
            if temp_fd >= 0:
                descriptor_to_close = temp_fd
                temp_fd = -1
                self._resources.transient_temp_fd = -1
                try:
                    _raw_temp_close(descriptor_to_close)
                except OSError:
                    pass
            if isinstance(err, (KeyboardInterrupt, SystemExit)):
                raise
            raise self._poison(
                err,
                ambiguous=replace_attempted or renamed,
            ) from err

    def _barrier_sync(self) -> None:
        self._require_pid()
        self._raise_if_poisoned()
        stamp = self._commit_stamp
        if stamp is None or stamp.sequence != self._sequence:
            raise ReferenceJournalProtocolError(
                "Durability barrier requires one unconsumed immediately preceding save."
            )
        try:
            self._verify_open_state()
            before = self._read_named_final()
            if before is None or not self._snapshots_match(
                stamp.snapshot, before.snapshot
            ):
                raise ReferenceJournalConflictError(
                    "Reference journal changed before its durability barrier."
                )
            _fsync_boundary(
                self._directory_fd,
                self._failpoint,
                "barrier_directory_fsync",
            )
            after = self._read_named_final()
            if after is None or not self._snapshots_match(
                stamp.snapshot, after.snapshot
            ):
                raise ReferenceJournalConflictError(
                    "Reference journal changed across its durability barrier."
                )
        except BaseException as err:
            if isinstance(err, (KeyboardInterrupt, SystemExit)):
                raise
            raise self._poison(err, ambiguous=True) from err
        self._sequence += 1
        self._commit_stamp = None

    async def async_close(self) -> None:
        """Drain accepted work, close descriptors, then release the lifetime lock."""

        if os.getpid() != self._pid:
            self._close_after_fork()
            raise ReferenceJournalForkError(
                "A fork child discarded its inherited journal descriptors."
            )
        if asyncio.get_running_loop() is not self._loop:
            raise ReferenceJournalProtocolError(
                "The journal backend must close on its opening event loop."
            )
        with self._state_lock:
            if self._closed:
                return
            if self._close_task is None:
                self._closing = True
                self._close_task = self._loop.create_task(self._finish_close())
            close_task = self._close_task
        _result, cancelled = await _await_owned_future(close_task)
        if cancelled is not None:
            raise cancelled

    async def _finish_close(self) -> None:
        future = self._loop.run_in_executor(
            self._executor,
            self._run_fork_safe,
            self._close_sync,
        )
        try:
            await _await_owned_future(future)
        finally:
            self._executor.shutdown(wait=False, cancel_futures=False)
            with self._state_lock:
                self._closed = True

    def _close_sync(self) -> None:
        errors: list[OSError] = []
        _untrack_resources(self._resources)
        transient_fd = self._resources.transient_temp_fd
        self._resources.transient_temp_fd = -1
        if transient_fd >= 0:
            try:
                os.close(transient_fd)
            except OSError as err:
                errors.append(err)
        for attribute, resource_attribute in (
            ("_config_fd", "config_fd"),
            ("_directory_fd", "directory_fd"),
        ):
            descriptor = cast(int, getattr(self, attribute))
            setattr(self, attribute, -1)
            setattr(self._resources, resource_attribute, -1)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as err:
                    errors.append(err)
        if self._lock_fd >= 0:
            lock_fd = self._lock_fd
            self._lock_fd = -1
            self._resources.lock_fd = -1
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError as err:
                errors.append(err)
            try:
                os.close(lock_fd)
            except OSError as err:
                errors.append(err)
        if errors:
            raise ReferenceJournalIOError(
                "One or more reference journal descriptors failed to close."
            ) from errors[0]

    def _close_after_fork(self) -> None:
        # register_at_fork closed inherited descriptors before child user code.
        if self._closed:
            return
        self._closing = True
        self._config_fd = -1
        self._directory_fd = -1
        self._lock_fd = -1
        self._closed = True
