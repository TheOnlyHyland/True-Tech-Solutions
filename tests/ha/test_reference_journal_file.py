"""Real-filesystem tests for the crash-durable reference journal backend.

Child-process crashes prove process-level convergence, not hardware power-loss
behavior; that remains a sealed-policy and external-certification requirement.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import FrozenInstanceError
import errno
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable
import warnings

from homeassistant.core import HomeAssistant
import pytest

from custom_components.true_family import reference_journal_file as journal_file
from custom_components.true_family import reference_migration as migration
from custom_components.true_family import reference_migration_ha as journal_ha


JOURNAL_ID = "true-family-reference-journal-file-test"


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    """Create one exact-owner, non-writable trusted config directory."""

    directory = tmp_path / "trusted-config"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
        os.fsync(parent_fd)
    finally:
        os.close(directory_fd)
        os.close(parent_fd)
    return directory


def policy_for(path: Path) -> journal_file.DurableFilesystemPolicy:
    """Build an explicit one-filesystem test policy for this disposable path."""

    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        filesystem = journal_file._filesystem_identity_for_fd(descriptor)
    finally:
        os.close(descriptor)
    return journal_file.DurableFilesystemPolicy.for_test_filesystems(
        frozenset({filesystem.filesystem_type})
    )


def filesystem_identity_for(path: Path) -> journal_file._FilesystemIdentity:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        return journal_file._filesystem_identity_for_fd(descriptor)
    finally:
        os.close(descriptor)


def fake_external_certification_for_live_mount(
    path: Path,
    *,
    mount_binding_digest: str | None = None,
    deployed_storage_stack_digest: str | None = None,
    power_cut_report_digest: str = "a" * 64,
    covered_persistence_primitive: str = journal_file.PERSISTENCE_PRIMITIVE_ID,
    certification_digest: str | None = None,
    report_digest_in_identity: str | None = None,
) -> journal_file.DurableFilesystemCertification:
    """Fabricate external-shaped evidence only for this real test mount."""

    policy = journal_file.PRODUCTION_DURABLE_FILESYSTEM_POLICY
    identity = filesystem_identity_for(path)
    journal_file._qualify_filesystem(identity, policy)
    mount_binding = (
        journal_file._mount_binding_digest(identity, policy)
        if mount_binding_digest is None
        else mount_binding_digest
    )
    stack_binding = (
        "c" * 64
        if deployed_storage_stack_digest is None
        else deployed_storage_stack_digest
    )
    authority = "independent-power-cut-lab/v1"
    embedded_report_digest = (
        power_cut_report_digest
        if report_digest_in_identity is None
        else report_digest_in_identity
    )
    report_identity = (
        f"{authority}/reference-journal-report-2026-001"
        f"@sha256:{embedded_report_digest}"
    )
    digest = (
        journal_file._certification_digest(
            certification_authority_identity=authority,
            certification_report_identity=report_identity,
            mount_binding_digest=mount_binding,
            deployed_storage_stack_digest=stack_binding,
            power_cut_report_digest=power_cut_report_digest,
            covered_persistence_primitive=covered_persistence_primitive,
            test_only=False,
        )
        if certification_digest is None
        else certification_digest
    )
    return (
        journal_file.DurableFilesystemCertification.from_external_power_cut_report(
            certification_authority_identity=authority,
            certification_report_identity=report_identity,
            mount_binding_digest=mount_binding,
            deployed_storage_stack_digest=stack_binding,
            power_cut_report_digest=power_cut_report_digest,
            covered_persistence_primitive=covered_persistence_primitive,
            certification_digest=digest,
        )
    )


def fake_filesystem_identity(
    filesystem_type: str = "ext4",
    *,
    mount_options: tuple[str, ...] = ("rw", "relatime"),
    super_options: tuple[str, ...] = ("rw",),
) -> journal_file._FilesystemIdentity:
    return journal_file._FilesystemIdentity(
        descriptor_path="/trusted/config",
        record=journal_file._MountRecord(
            mount_id=42,
            parent_mount_id=1,
            device="8:1",
            root="/qualified-root",
            mount_point="/trusted",
            mount_options=mount_options,
            optional_fields=("shared:1",),
            filesystem_type=filesystem_type,
            mount_source="/dev/qualified",
            super_options=super_options,
        ),
    )


def complete_production_storage_snapshot() -> dict[str, Any]:
    filesystem_uuid = "11111111-2222-3333-4444-555555555555"
    partition_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    physical_queue = {
        field: "1" for field in journal_file._MANDATORY_QUEUE_FIELDS
    }
    physical_queue.update(
        {
            "queue/scheduler": "mq-deadline none",
            "queue/write_cache": "write back",
        }
    )
    root = {
        "device": "8:1",
        "device_identity": {},
        "driver_stack": [
            {"node": "pci/nvme/nvme0n1/nvme0n1p1", "subsystem": "class/block"},
        ],
        "fields": {"dev": "8:1", "partition": "1", "size": "1000000"},
        "holders": (),
        "queue": {},
        "slaves": None,
        "sysfs_identity": "pci/nvme/nvme0n1/nvme0n1p1",
        "uevent": {
            "DEVNAME": "nvme0n1p1",
            "DEVTYPE": "partition",
            "MAJOR": "8",
            "MINOR": "1",
            "PARTN": "1",
            "PARTUUID": partition_uuid,
        },
    }
    physical = {
        "device": "8:0",
        "device_identity": {
            "device/firmware_rev": "5B2QGXA7",
            "device/model": "Samsung SSD 980 PRO 1TB",
            "device/serial": "S5GXNS0R123456A",
            "device/transport": "pcie",
            "device/device/vendor": "0x144d",
            "device/wwid": "eui.002538b221112233",
            "eui": "00 25 38 b2 21 11 22 33",
            "wwid": "eui.002538b221112233",
        },
        "driver_stack": [
            {
                "device_id": "0x2711",
                "driver": "bus/pci/drivers/pcieport",
                "node": "pci/0000:00:00.0",
                "revision": "0x21",
                "subsystem": "bus/pci",
                "vendor_id": "0x14e4",
            },
            {
                "device_id": "0xa80a",
                "driver": "bus/pci/drivers/nvme",
                "node": "pci/0000:01:00.0",
                "revision": "0x01",
                "subsystem": "bus/pci",
                "vendor_id": "0x144d",
            },
            {"node": "pci/nvme/nvme0", "subsystem": "class/nvme"},
            {"node": "pci/nvme/nvme0n1", "subsystem": "class/block"},
        ],
        "fields": {"dev": "8:0", "removable": "0", "size": "2000000"},
        "holders": (),
        "queue": physical_queue,
        "slaves": (),
        "sysfs_identity": "pci/nvme/nvme0n1",
        "uevent": {
            "DEVNAME": "nvme0n1",
            "DEVTYPE": "disk",
            "MAJOR": "8",
            "MINOR": "0",
        },
    }
    return {
        "filesystem": {
            "block_size": 4096,
            "blocks_per_group": 2048,
            "checksum_seed": 7,
            "creator_os": 0,
            "descriptor_size": 32,
            "feature_compat": 4,
            "feature_incompat": 66,
            "feature_ro_compat": 0,
            "first_data_block": 0,
            "filesystem_type": "ext4",
            "filesystem_uuid": filesystem_uuid,
            "hash_seed": "01" * 16,
            "inode_size": 256,
            "inodes_count": 64,
            "inodes_per_group": 64,
            "jbd2": {
                "block_size": 4096,
                "block_type": 4,
                "checksum_semantics": (
                    "crc32c-seed-ffffffff-zeroed-offset-00fc-full-1024"
                ),
                "checksum_type": 4,
                "dynamic_superblock": 0,
                "fast_commit_blocks": 0,
                "feature_compat": 0,
                "feature_incompat": 17,
                "feature_ro_compat": 0,
                "first": 1,
                "journal_superblock_bytes": 1024,
                "magic": 3225106840,
                "maximum_length": 1024,
                "maximum_transaction": 0,
                "maximum_transaction_data": 0,
                "normal_blocks": 1024,
                "users": (filesystem_uuid,),
                "users_count": 1,
                "uuid": filesystem_uuid,
            },
            "journal_device": 0,
            "journal_device_format": False,
            "journal_has_internal": True,
            "journal_inode": 8,
            "journal_inode_identity": {
                "blocks_512": 8192,
                "flags": 524288,
                "generation": 1,
                "group": 0,
                "inode": 8,
                "links": 1,
                "mapping": {
                    "depth": 0,
                    "extents": [
                        {"length": 1024, "logical": 0, "physical": 100},
                    ],
                    "format": "extents",
                    "nodes": [
                        {
                            "depth": 0,
                            "entries": 1,
                            "generation": 0,
                            "maximum": 4,
                            "raw_digest": "03" * 32,
                            "source_block": None,
                        },
                    ],
                },
                "mode": 33152,
                "raw_digest": "04" * 32,
                "size": 4194304,
            },
            "journal_needs_recovery": False,
            "journal_uuid": None,
            "mkfs_time": 123456,
            "revision": 1,
            "volume_name_hex": "00" * 16,
        },
        "hardware_evidence": {
            "endpoint": {
                "device_id": "0xa80a",
                "revision": "0x01",
                "vendor_id": "0x144d",
            },
            "firmware": "5B2QGXA7",
            "model": "Samsung SSD 980 PRO 1TB",
            "serial": "S5GXNS0R123456A",
            "transport": "pcie",
            "transport_identity": "nvme-pcie-direct",
            "vendor": "0x144d",
            "wwid": [
                "00 25 38 b2 21 11 22 33",
                "eui.002538b221112233",
            ],
        },
        "kernel_release": "6.18.34-certified",
        "mount_source_device": "8:1",
        "nodes": {"8:0": physical, "8:1": root},
        "partition_parent": "8:0",
        "root_device": "8:1",
        "schema": "true-family/direct-linux-storage-stack-binding/v7",
        "stable_aliases": {
            "by-id": (
                {"device": "8:1", "name": "nvme-Samsung_980_PRO-part1"},
            ),
            "by-partuuid": (
                {"device": "8:1", "name": partition_uuid},
            ),
            "by-uuid": (
                {"device": "8:1", "name": filesystem_uuid},
            ),
        },
        "transport_identity": "nvme-pcie-direct",
    }


def configure_nonproduction_mmc_snapshot(snapshot: dict[str, Any]) -> None:
    root = snapshot["nodes"]["8:1"]
    physical = snapshot["nodes"]["8:0"]
    root["uevent"]["DEVNAME"] = "mmcblk0p1"
    root["sysfs_identity"] = "platform/mmc/mmc0/mmc0:0001/block/mmcblk0p1"
    physical["uevent"]["DEVNAME"] = "mmcblk0"
    physical["sysfs_identity"] = "platform/mmc/mmc0/mmc0:0001/block/mmcblk0"
    physical["device_identity"] = {
        "device/cid": "03534453443634478012345678016f00",
        "device/fwrev": "0x1",
        "device/hwrev": "0x2",
        "device/manfid": "0x000003",
        "device/name": "SD64G",
        "device/oemid": "0x5344",
        "device/serial": "0x12345678",
    }
    physical["driver_stack"] = [
        {
            "driver": "bus/mmc/drivers/mmcblk",
            "node": "platform/mmc/mmc0/mmc0:0001",
            "subsystem": "bus/mmc",
        },
        {
            "driver": "bus/platform/drivers/sdhci",
            "node": "platform/mmc",
            "subsystem": "bus/mmc",
        },
        {"node": "platform/mmc/block/mmcblk0", "subsystem": "class/block"},
    ]
    snapshot["stable_aliases"]["by-id"] = (
        {"device": "8:1", "name": "mmc-SD64G_12345678-part1"},
    )
    snapshot["transport_identity"] = "mmc-direct"
    snapshot["hardware_evidence"] = {}


def configure_nonproduction_sata_snapshot(snapshot: dict[str, Any]) -> None:
    root = snapshot["nodes"]["8:1"]
    physical = snapshot["nodes"]["8:0"]
    root["uevent"]["DEVNAME"] = "sda1"
    root["sysfs_identity"] = "pci/ata1/host0/target0:0:0/0:0:0:0/block/sda/sda1"
    physical["uevent"]["DEVNAME"] = "sda"
    physical["sysfs_identity"] = "pci/ata1/host0/target0:0:0/0:0:0:0/block/sda"
    physical["device_identity"] = {
        "device/model": "Samsung SSD 870 EVO 1TB",
        "device/rev": "SVT02B6Q",
        "device/serial": "S6PTNS0R123456A",
        "device/vendor": "ATA",
        "device/wwid": "t10.ATA_Samsung_SSD_870_EVO_1TB",
        "wwid": "t10.ATA_Samsung_SSD_870_EVO_1TB",
    }
    physical["driver_stack"] = [
        {
            "driver": "bus/pci/drivers/ahci",
            "node": "pci/0000:02:00.0",
            "subsystem": "bus/pci",
        },
        {"node": "pci/0000:02:00.0/ata1", "subsystem": "bus/ata"},
        {
            "driver": "bus/scsi/drivers/sd",
            "node": "pci/0000:02:00.0/ata1/host0/target0:0:0/0:0:0:0",
            "subsystem": "bus/scsi",
        },
        {"node": "pci/ata1/block/sda", "subsystem": "class/block"},
    ]
    snapshot["stable_aliases"]["by-id"] = (
        {"device": "8:1", "name": "ata-Samsung_SSD_870_EVO-part1"},
    )
    snapshot["transport_identity"] = "sata-ata-direct"
    snapshot["hardware_evidence"] = {}


def configure_realistic_nvme_snapshot(snapshot: dict[str, Any]) -> None:
    root = snapshot["nodes"]["8:1"]
    physical = snapshot["nodes"]["8:0"]
    root["uevent"]["DEVNAME"] = "nvme0n1p1"
    root["sysfs_identity"] = "pci/nvme/nvme0/nvme0n1/nvme0n1p1"
    physical["uevent"]["DEVNAME"] = "nvme0n1"
    physical["sysfs_identity"] = "pci/nvme/nvme0/nvme0n1"
    physical["device_identity"] = {
        "device/firmware_rev": "5B2QGXA7",
        "device/model": "Samsung SSD 980 PRO 1TB",
        "device/serial": "S5GXNS0R123456A",
        "device/transport": "pcie",
        "device/device/vendor": "0x144d",
        "device/wwid": "eui.002538b221112233",
        "eui": "00 25 38 b2 21 11 22 33",
        "wwid": "eui.002538b221112233",
    }
    physical["driver_stack"] = [
        {
            "device_id": "0xa80a",
            "driver": "bus/pci/drivers/nvme",
            "node": "pci/nvme0",
            "revision": "0x01",
            "subsystem": "bus/pci",
            "vendor_id": "0x144d",
        },
        {"node": "pci/nvme0/class", "subsystem": "class/nvme"},
        {"node": "pci/nvme0/block", "subsystem": "class/block"},
    ]
    snapshot["stable_aliases"]["by-id"] = (
        {"device": "8:1", "name": "nvme-Samsung_SSD_980_PRO-part1"},
    )
    transport = journal_file._recognized_direct_transport(physical)
    snapshot["transport_identity"] = transport
    snapshot["hardware_evidence"] = journal_file._mandatory_hardware_evidence(
        physical,
        transport,
    )


def synthetic_ext4_jbd2_image(
    *,
    extent_depth: int | None = 0,
    fast_commit_blocks: int = 0,
) -> bytearray:
    block_size = 4096
    total_blocks = 2048
    journal_blocks = (
        12
        if extent_depth is None
        else journal_file._JBD2_MIN_JOURNAL_BLOCKS + fast_commit_blocks
    )
    filesystem_uuid = bytes.fromhex("11111111222233334444555555555555")
    image = bytearray(block_size * total_blocks)
    superblock = memoryview(image)[1024:2048]
    superblock[0:4] = (64).to_bytes(4, "little")
    superblock[4:8] = total_blocks.to_bytes(4, "little")
    superblock[20:24] = (0).to_bytes(4, "little")
    superblock[24:28] = (2).to_bytes(4, "little")
    superblock[28:32] = (2).to_bytes(4, "little")
    superblock[32:36] = total_blocks.to_bytes(4, "little")
    superblock[40:44] = (64).to_bytes(4, "little")
    superblock[56:58] = (0xEF53).to_bytes(2, "little")
    superblock[72:76] = (0).to_bytes(4, "little")
    superblock[76:80] = (1).to_bytes(4, "little")
    superblock[88:90] = (256).to_bytes(2, "little")
    superblock[92:96] = (0x4).to_bytes(4, "little")
    superblock[96:100] = (0x42).to_bytes(4, "little")
    superblock[100:104] = (0).to_bytes(4, "little")
    superblock[104:120] = filesystem_uuid
    superblock[224:228] = (8).to_bytes(4, "little")
    superblock[228:232] = (0).to_bytes(4, "little")
    superblock[254:256] = (32).to_bytes(2, "little")

    group_descriptor = memoryview(image)[block_size : block_size + 32]
    group_descriptor[0:4] = (8).to_bytes(4, "little")
    group_descriptor[4:8] = (9).to_bytes(4, "little")
    group_descriptor[8:12] = (2).to_bytes(4, "little")

    inode_offset = block_size * 2 + 7 * 256
    inode = memoryview(image)[inode_offset : inode_offset + 256]
    inode[0:2] = (0x8180).to_bytes(2, "little")
    inode[4:8] = (journal_blocks * block_size).to_bytes(4, "little")
    inode[26:28] = (1).to_bytes(2, "little")
    inode[28:32] = (journal_blocks * block_size // 512).to_bytes(4, "little")
    inode[100:104] = (1).to_bytes(4, "little")
    extent_root = inode[40:100]
    if extent_depth is None:
        for ordinal in range(journal_blocks):
            offset = ordinal * 4
            extent_root[offset : offset + 4] = (100 + ordinal).to_bytes(
                4,
                "little",
            )
    else:
        inode[32:36] = journal_file._EXT4_EXTENTS_INODE_FLAG.to_bytes(4, "little")
        extent_root[0:2] = journal_file._EXT4_EXTENT_MAGIC.to_bytes(2, "little")
        extent_root[2:4] = (1).to_bytes(2, "little")
        extent_root[4:6] = (4).to_bytes(2, "little")
        extent_root[6:8] = extent_depth.to_bytes(2, "little")
    if extent_depth == 0:
        extent_root[12:16] = (0).to_bytes(4, "little")
        extent_root[16:18] = journal_blocks.to_bytes(2, "little")
        extent_root[18:20] = (0).to_bytes(2, "little")
        extent_root[20:24] = (100).to_bytes(4, "little")
    elif extent_depth == 1:
        extent_root[12:16] = (0).to_bytes(4, "little")
        extent_root[16:20] = (6).to_bytes(4, "little")
        leaf = memoryview(image)[block_size * 6 : block_size * 7]
        leaf[0:2] = journal_file._EXT4_EXTENT_MAGIC.to_bytes(2, "little")
        leaf[2:4] = (1).to_bytes(2, "little")
        leaf[4:6] = ((block_size - 12) // 12).to_bytes(2, "little")
        leaf[6:8] = (0).to_bytes(2, "little")
        leaf[12:16] = (0).to_bytes(4, "little")
        leaf[16:18] = journal_blocks.to_bytes(2, "little")
        leaf[18:20] = (0).to_bytes(2, "little")
        leaf[20:24] = (100).to_bytes(4, "little")

    jbd2_offset = block_size * 100
    jbd2 = memoryview(image)[jbd2_offset : jbd2_offset + block_size]
    jbd2[0:4] = journal_file._JBD2_MAGIC.to_bytes(4, "big")
    jbd2[4:8] = journal_file._JBD2_SUPERBLOCK_V2.to_bytes(4, "big")
    jbd2[8:12] = (0).to_bytes(4, "big")
    jbd2[12:16] = block_size.to_bytes(4, "big")
    jbd2[16:20] = journal_blocks.to_bytes(4, "big")
    jbd2[20:24] = (1).to_bytes(4, "big")
    jbd2[24:28] = (7).to_bytes(4, "big")
    jbd2[28:32] = (0).to_bytes(4, "big")
    jbd2[36:40] = (0).to_bytes(4, "big")
    feature_incompat = 0x11
    if fast_commit_blocks:
        feature_incompat |= journal_file._JBD2_FEATURE_INCOMPAT_FAST_COMMIT
    jbd2[40:44] = feature_incompat.to_bytes(4, "big")
    jbd2[44:48] = (0).to_bytes(4, "big")
    jbd2[48:64] = filesystem_uuid
    jbd2[64:68] = (1).to_bytes(4, "big")
    jbd2[80] = journal_file._JBD2_CHECKSUM_TYPE_CRC32C
    jbd2[84:88] = fast_commit_blocks.to_bytes(4, "big")
    jbd2[88:92] = (2).to_bytes(4, "big")
    jbd2[256:272] = filesystem_uuid
    checksum_input = bytearray(jbd2[:1024])
    checksum_input[252:256] = bytes(4)
    jbd2[252:256] = journal_file._crc32c(bytes(checksum_input)).to_bytes(4, "big")
    return image


def synthetic_block_reader(
    image: bytearray,
    reads: list[tuple[int, int]],
) -> Callable[[str, str, int, int], bytes]:
    def read(
        _alias_path: str,
        _device: str,
        offset: int,
        size: int,
    ) -> bytes:
        reads.append((offset, size))
        return bytes(image[offset : offset + size])

    return read


def refresh_synthetic_jbd2_checksum(image: bytearray) -> None:
    offset = 4096 * 100
    checksum_input = bytearray(image[offset : offset + 1024])
    checksum_input[252:256] = bytes(4)
    image[offset + 252 : offset + 256] = journal_file._crc32c(
        bytes(checksum_input)
    ).to_bytes(4, "big")


async def open_store(
    config_dir: Path,
    *,
    journal_id: str = JOURNAL_ID,
    failpoint=None,
    max_bytes: int = journal_file.DEFAULT_MAX_BYTES,
) -> journal_file.CrashDurableReferenceJournalStore:
    return await journal_file.CrashDurableReferenceJournalStore.async_open(
        config_dir=str(config_dir),
        journal_id=journal_id,
        filesystem_policy=policy_for(config_dir),
        failpoint=failpoint,
        max_bytes=max_bytes,
    )


def names(
    config_dir: Path,
    journal_id: str = JOURNAL_ID,
) -> tuple[Path, Path, Path, Path]:
    directory = config_dir / journal_file.REFERENCE_JOURNAL_DIRECTORY_NAME
    basename = journal_file.reference_journal_basename(journal_id)
    return (
        directory,
        directory / f"{basename}.json",
        directory / f"{basename}.tmp",
        directory / f"{basename}.lock",
    )


def canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def write_bytes(path: Path, raw: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fork_without_warning() -> int:
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r"This process .* is multi-threaded, use of fork\(\) may lead",
            category=DeprecationWarning,
        )
        return os.fork()


async def wait_for_child(child_pid: int, timeout: float = 10) -> int:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        waited_pid, status = os.waitpid(child_pid, os.WNOHANG)
        if waited_pid == child_pid:
            return status
        await asyncio.sleep(0.002)
    os.kill(child_pid, signal.SIGKILL)
    _waited_pid, status = os.waitpid(child_pid, 0)
    raise AssertionError(
        f"Child process timed out with status {os.waitstatus_to_exitcode(status)}."
    )


async def read_pipe_until(
    descriptor: int,
    marker: bytes,
    timeout: float = 10,
) -> bytes:
    os.set_blocking(descriptor, False)
    deadline = asyncio.get_running_loop().time() + timeout
    output = bytearray()
    while asyncio.get_running_loop().time() < deadline:
        try:
            chunk = os.read(descriptor, 4096)
        except BlockingIOError:
            chunk = b""
        if chunk:
            output.extend(chunk)
            if marker in output:
                return bytes(output)
        await asyncio.sleep(0.002)
    raise AssertionError(f"Pipe did not produce marker {marker!r}: {bytes(output)!r}")


async def provision_structure(config_dir: Path) -> None:
    store = await open_store(config_dir)
    await store.async_close()


async def test_provision_save_barrier_reopen_and_proof_identity(
    config_dir: Path,
) -> None:
    events: list[str] = []
    store = await open_store(config_dir, failpoint=events.append)
    assert store._durability_proof is None
    proof = store.durability_proof
    assert isinstance(proof, journal_ha.ReferenceJournalDurabilityProof)
    assert proof.provider_id.startswith("tf/test-only-linux-reference-journal/v3;")
    assert ";p=test-only-" in proof.provider_id
    assert re.search(r";m=[0-9]+;", proof.provider_id)
    assert re.search(r";f=[a-z0-9_.+-]+;d=[0-9]+:[0-9]+;", proof.provider_id)
    assert ";q=" in proof.provider_id
    assert proof.provider_id.endswith(";l=flock-v1;s=lock-respecting")

    assert await store.async_load() is None
    generation_zero = {"generation": 0, "payload": {"room": "kitchen"}}
    await store.async_save(generation_zero)
    await store.async_barrier()
    await store.async_close()
    await store.async_close()

    directory, final_path, _temp_path, lock_path = names(config_dir)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(final_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600
    assert final_path.read_bytes() == canonical(generation_zero)
    assert lock_path.read_bytes() == journal_file._lock_protocol_bytes(JOURNAL_ID)
    assert events.index("before_store_directory_fsync") < events.index(
        "before_config_directory_fsync"
    )
    assert events.index("before_config_directory_fsync") < events.index(
        "before_config_anchor_parent_fsync"
    )
    assert "before_lock_file_fsync" in events
    assert "before_lock_directory_fsync" in events

    reopened = await open_store(config_dir)
    assert reopened.durability_proof == proof
    assert await reopened.async_load() == generation_zero
    generation_one = {"generation": 1, "payload": {"room": "kitchen", "set": 21}}
    await reopened.async_save(generation_one)
    await reopened.async_barrier()
    await reopened.async_close()

    final = await open_store(config_dir)
    assert await final.async_load() == generation_one
    await final.async_close()


async def test_existing_parent_store_and_barrier_injection_contract(
    hass: HomeAssistant,
    config_dir: Path,
) -> None:
    backend = await open_store(config_dir)
    await journal_ha.async_provision_reference_journal(
        hass,
        journal_id=JOURNAL_ID,
        store=backend,
        durability_barrier=backend,
    )
    journal = await journal_ha.HomeAssistantReferenceJournal.async_create(
        hass,
        journal_id=JOURNAL_ID,
        store=backend,
        durability_barrier=backend,
    )
    plan_id = f"tf-reference-{'9' * 24}"
    await journal.async_run(
        journal.set_state,
        plan_id,
        migration.MigrationState.PLANNED,
    )
    await journal.async_close()
    await backend.async_close()

    reopened = await open_store(config_dir)
    durable = await reopened.async_load()
    assert durable is not None
    decoded = journal_ha.decode_reference_journal_data(
        durable,
        expected_journal_id=JOURNAL_ID,
    )
    assert decoded["generation"] == 1
    assert decoded["content"]["states"][plan_id] == {
        "state": migration.MigrationState.PLANNED.value,
        "reason": None,
    }
    await reopened.async_close()


def test_mount_identity_uses_exact_fdinfo_record_and_rejects_ambiguity(
    config_dir: Path,
) -> None:
    descriptor = os.open(
        config_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        records = journal_file._read_mountinfo()
        identity = journal_file._filesystem_identity_for_fd(descriptor, records)
        assert identity.mount_id == journal_file._read_fdinfo_mount_id(descriptor)
        assert identity.record.root
        assert identity.record.mount_options
        assert identity.record.super_options
        assert identity.record.canonical_data["mount_id"] == identity.mount_id
        with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
            journal_file._filesystem_identity_for_fd(
                descriptor,
                records + (identity.record,),
            )
    finally:
        os.close(descriptor)


def test_sysfs_device_entry_distinguishes_path_symlink_and_regular_pci_id(
    tmp_path: Path,
) -> None:
    node = tmp_path / "sysfs-node"
    node.mkdir()
    device = node / "device"
    device.write_text("0xa828\n", encoding="ascii")
    assert journal_file._sysfs_device_entry_identity(str(node)) == (
        "device_id",
        "0xa828",
    )

    device.unlink()
    device.symlink_to("/sys/devices")
    assert journal_file._sysfs_device_entry_identity(str(node)) == (
        "device_path",
        "devices",
    )


def test_live_driver_stack_captures_sysfs_device_path_identity(
    config_dir: Path,
) -> None:
    identity = filesystem_identity_for(config_dir)
    path = journal_file._sysfs_node_path(identity.device)
    driver_stack = journal_file._driver_stack_identity(path)

    assert any("device_path" in item for item in driver_stack)


def test_sysfs_device_symlink_escape_and_race_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = tmp_path / "sysfs-node"
    node.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    device = node / "device"
    device.symlink_to(outside)
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._sysfs_device_entry_identity(str(node))

    device.unlink()
    device.symlink_to("/sys/devices")
    original_realpath = os.path.realpath
    calls = 0

    def racing_realpath(path: str) -> str:
        nonlocal calls
        if path == str(device):
            calls += 1
            return "/sys/devices" if calls == 1 else "/sys/class"
        return original_realpath(path)

    monkeypatch.setattr(os.path, "realpath", racing_realpath)
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._sysfs_device_entry_identity(str(node))


def test_sealed_production_mount_policy_and_test_only_branding() -> None:
    production = journal_file.PRODUCTION_DURABLE_FILESYSTEM_POLICY
    assert production.test_only is False
    assert production.policy_id == "sealed-nvme-ext4-xfs-linux-v7"
    assert (
        journal_file._CERTIFICATION_SCHEMA
        == "true-family/durable-filesystem-certification/v6"
    )
    assert production.allowed_filesystem_types == frozenset(
        {"ext4", "xfs"}
    )
    journal_file._qualify_filesystem(fake_filesystem_identity(), production)
    journal_file._qualify_filesystem(
        fake_filesystem_identity("xfs"),
        production,
    )

    for filesystem_type in (
        "btrfs",
        "overlay",
        "tmpfs",
        "ext2",
        "nfs",
        "fuse.sshfs",
    ):
        with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
            journal_file._qualify_filesystem(
                fake_filesystem_identity(filesystem_type),
                production,
            )
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._qualify_filesystem(
            fake_filesystem_identity(mount_options=("ro", "relatime")),
            production,
        )
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._qualify_filesystem(
            fake_filesystem_identity(super_options=("rw", "nobarrier")),
            production,
        )
    for external_device_option in (
        "journal_dev=/dev/external-journal",
        "logdev=/dev/external-log",
        "rtdev=/dev/external-realtime",
        "sb=32768",
    ):
        with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
            journal_file._qualify_filesystem(
                fake_filesystem_identity(
                    super_options=("rw", external_device_option)
                ),
                production,
            )
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._qualify_filesystem(
            fake_filesystem_identity(
                mount_options=("rw", "relatime", "sb=32768")
            ),
            production,
        )

    test_only = journal_file.DurableFilesystemPolicy.for_test_filesystems(
        frozenset({"overlay"})
    )
    assert test_only.test_only is True
    assert test_only.policy_id.startswith("test-only-")
    journal_file._qualify_filesystem(
        fake_filesystem_identity("overlay"),
        test_only,
    )
    btrfs_test_only = journal_file.DurableFilesystemPolicy.for_test_filesystems(
        frozenset({"btrfs"})
    )
    journal_file._qualify_filesystem(
        fake_filesystem_identity("btrfs"),
        btrfs_test_only,
    )
    assert journal_file._SEALED_PRODUCTION_DURABLE_FILESYSTEM_POLICY is production


async def test_production_open_without_certificate_has_no_child_side_effect(
    config_dir: Path,
) -> None:
    events: list[str] = []
    directory, _final_path, _temp_path, _lock_path = names(config_dir)

    with pytest.raises(journal_file.ReferenceJournalCertificationError):
        await journal_file.CrashDurableReferenceJournalStore.async_open(
            config_dir=str(config_dir),
            journal_id=JOURNAL_ID,
            failpoint=events.append,
        )

    assert not directory.exists()
    assert events == []


def test_certification_forms_are_strict_immutable_and_report_bound(
    config_dir: Path,
) -> None:
    production = fake_external_certification_for_live_mount(config_dir)
    identity = filesystem_identity_for(config_dir)
    policy = journal_file.PRODUCTION_DURABLE_FILESYSTEM_POLICY
    mount_binding = journal_file._mount_binding_digest(identity, policy)
    test_only = journal_file.DurableFilesystemCertification.for_test_evidence(
        mount_binding_digest=mount_binding,
        deployed_storage_stack_digest="c" * 64,
    )

    assert production.test_only is False
    assert test_only.test_only is True
    assert test_only.certification_authority_identity.startswith("test-only/")
    with pytest.raises(FrozenInstanceError):
        production.certification_digest = "0" * 64  # type: ignore[misc]
    with pytest.raises(ValueError, match="Certification digest"):
        fake_external_certification_for_live_mount(
            config_dir,
            certification_digest="0" * 64,
        )
    with pytest.raises(ValueError, match="report identity"):
        fake_external_certification_for_live_mount(
            config_dir,
            report_digest_in_identity="b" * 64,
        )


async def test_exact_external_certification_emits_bound_production_proof(
    config_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        journal_file,
        "_storage_stack_binding_digest",
        lambda _identity: "c" * 64,
    )
    certification = fake_external_certification_for_live_mount(config_dir)
    store = await journal_file.CrashDurableReferenceJournalStore.async_open(
        config_dir=str(config_dir),
        journal_id=JOURNAL_ID,
        filesystem_policy=journal_file.PRODUCTION_DURABLE_FILESYSTEM_POLICY,
        filesystem_certification=certification,
    )

    proof = store.durability_proof
    assert proof.provider_id.startswith("tf/certified-linux-reference-journal/v8;")
    assert f";c={certification.certification_digest};" in proof.provider_id
    assert ";x=" in proof.provider_id
    assert proof.provider_id.endswith(";l=flock-v1;s=lock-respecting")
    assert certification.certification_report_identity not in proof.provider_id
    assert certification.certification_authority_identity not in proof.provider_id
    assert certification.power_cut_report_digest not in proof.provider_id
    assert str(config_dir) not in proof.provider_id
    assert await store.async_load() is None
    await store.async_save({"generation": 0, "certified": True})
    await store.async_barrier()
    await store.async_close()

    reopened = await journal_file.CrashDurableReferenceJournalStore.async_open(
        config_dir=str(config_dir),
        journal_id=JOURNAL_ID,
        filesystem_policy=journal_file.PRODUCTION_DURABLE_FILESYSTEM_POLICY,
        filesystem_certification=certification,
    )
    assert await reopened.async_load() == {"generation": 0, "certified": True}
    await reopened.async_close()


@pytest.mark.parametrize(
    ("override", "value"),
    (
        ("mount_binding_digest", "0" * 64),
        ("deployed_storage_stack_digest", "b" * 64),
        (
            "covered_persistence_primitive",
            "true-family/reference-journal/different-primitive/v1",
        ),
    ),
)
async def test_stale_mount_stack_and_wrong_primitive_certification_fail_closed(
    config_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: str,
    value: str,
) -> None:
    monkeypatch.setattr(
        journal_file,
        "_storage_stack_binding_digest",
        lambda _identity: "c" * 64,
    )
    certification = fake_external_certification_for_live_mount(
        config_dir,
        **{override: value},
    )
    directory, _final_path, _temp_path, _lock_path = names(config_dir)

    with pytest.raises(journal_file.ReferenceJournalCertificationError):
        await journal_file.CrashDurableReferenceJournalStore.async_open(
            config_dir=str(config_dir),
            journal_id=JOURNAL_ID,
            filesystem_policy=journal_file.PRODUCTION_DURABLE_FILESYSTEM_POLICY,
            filesystem_certification=certification,
        )

    assert not directory.exists()


async def test_test_only_certificate_cannot_cross_into_production(
    config_dir: Path,
) -> None:
    identity = filesystem_identity_for(config_dir)
    policy = journal_file.PRODUCTION_DURABLE_FILESYSTEM_POLICY
    certification = journal_file.DurableFilesystemCertification.for_test_evidence(
        mount_binding_digest=journal_file._mount_binding_digest(identity, policy),
        deployed_storage_stack_digest="c" * 64,
    )
    directory, _final_path, _temp_path, _lock_path = names(config_dir)

    with pytest.raises(journal_file.ReferenceJournalCertificationError):
        await journal_file.CrashDurableReferenceJournalStore.async_open(
            config_dir=str(config_dir),
            journal_id=JOURNAL_ID,
            filesystem_policy=policy,
            filesystem_certification=certification,
        )

    assert not directory.exists()


@pytest.mark.parametrize(
    "case",
    (
        "device_mapper",
        "md_raid",
        "loop",
        "network_transport",
        "multi_root",
        "multi_slave",
        "holder_dependency",
    ),
)
def test_production_snapshot_rejects_composite_and_mutable_stacks(
    case: str,
) -> None:
    snapshot = complete_production_storage_snapshot()
    root = snapshot["nodes"]["8:1"]
    physical = snapshot["nodes"]["8:0"]
    if case == "device_mapper":
        root["uevent"]["DEVNAME"] = "dm-0"
    elif case == "md_raid":
        root["uevent"]["DEVNAME"] = "md0"
    elif case == "loop":
        root["uevent"]["DEVNAME"] = "loop0"
    elif case == "network_transport":
        physical["device_identity"]["device/transport"] = "tcp"
    elif case == "multi_root":
        snapshot["nodes"]["8:2"] = deepcopy(physical)
    elif case == "multi_slave":
        physical["slaves"] = ("8:2", "8:3")
    else:
        physical["holders"] = ("253:0",)

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


@pytest.mark.parametrize(
    ("case", "driver", "transport", "subsystem"),
    (
        ("hyper_v", "hv_storvsc", "scsi", "bus/vmbus"),
        ("megaraid", "megaraid_sas", "sas", "bus/pci"),
        ("virtio", "virtio_blk", "virtio", "bus/virtio"),
        ("xen", "xen-blkfront", "xen", "bus/xen"),
        ("unknown_driver", "mystery_storage", "sata", "bus/pci"),
        ("unknown_transport", "ahci", "quantum", "bus/pci"),
        ("noncanonical_transport", "ahci", "SATA", "bus/pci"),
        ("sas_removed", "isci", "sas", "bus/pci"),
        ("usb_removed", "usb-storage", "usb", "bus/usb"),
    ),
)
def test_production_transport_allowlist_has_no_unknown_fallback(
    case: str,
    driver: str,
    transport: str,
    subsystem: str,
) -> None:
    snapshot = complete_production_storage_snapshot()
    physical = snapshot["nodes"]["8:0"]
    physical["driver_stack"][0] = {
        "driver": f"drivers/{driver}",
        "node": f"transport/{case}",
        "subsystem": subsystem,
    }
    physical["device_identity"]["device/transport"] = transport

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


def test_metadata_only_driver_ancestor_without_subsystem_rejects() -> None:
    snapshot = complete_production_storage_snapshot()
    snapshot["nodes"]["8:0"]["driver_stack"].append(
        {
            "modalias": "platform:metadata-only",
            "node": "platform/unknown-storage-parent",
        }
    )

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)

    unknown_subsystem = complete_production_storage_snapshot()
    unknown_subsystem["nodes"]["8:0"]["driver_stack"].append(
        {
            "modalias": "platform:metadata-only",
            "node": "platform/unknown-storage-parent",
            "subsystem": "bus/unknown",
        }
    )
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(unknown_subsystem)


def test_only_live_shaped_direct_pcie_nvme_qualifies() -> None:
    snapshot = complete_production_storage_snapshot()
    physical = snapshot["nodes"]["8:0"]
    recognized = journal_file._recognized_direct_transport(physical)
    snapshot["transport_identity"] = recognized
    snapshot["hardware_evidence"] = journal_file._mandatory_hardware_evidence(
        physical,
        recognized,
    )

    assert recognized == "nvme-pcie-direct"
    assert set(journal_file._DIRECT_TRANSPORT_MODELS) == {"nvme-pcie-direct"}
    journal_file._validate_production_storage_snapshot(snapshot)


@pytest.mark.parametrize("transport_model", ("mmc", "sata"))
def test_mmc_and_sata_are_not_production_models(transport_model: str) -> None:
    snapshot = complete_production_storage_snapshot()
    if transport_model == "mmc":
        configure_nonproduction_mmc_snapshot(snapshot)
    else:
        configure_nonproduction_sata_snapshot(snapshot)

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._recognized_direct_transport(snapshot["nodes"]["8:0"])
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


def test_qemu_evidence_rejects_allowlisted_nvme_shape() -> None:
    snapshot = complete_production_storage_snapshot()
    physical = snapshot["nodes"]["8:0"]
    physical["device_identity"]["device/vendor"] = "QEMU"
    physical["device_identity"]["device/model"] = "QEMU HARDDISK"
    physical["device_identity"]["device/firmware_rev"] = "QEMU 1.0"
    physical["driver_stack"][0]["modalias"] = "pci:v00001B36d00000010"
    physical["driver_stack"][0]["vendor_id"] = "0x1b36"

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("device/model", "VMware Virtual disk"),
        ("device/vendor", "Microsoft Virtual Storage"),
        ("device/firmware_rev", "VirtualBox emulation"),
        ("device/model", "Hardware RAID Volume"),
    ),
)
def test_virtualization_and_logical_volume_signatures_reject(
    field: str,
    value: str,
) -> None:
    snapshot = complete_production_storage_snapshot()
    snapshot["nodes"]["8:0"]["device_identity"][field] = value

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


@pytest.mark.parametrize("vendor_id", ("0x1414", "0x15ad", "0x1af4", "0x80ee"))
def test_virtualization_pci_vendor_ids_reject(vendor_id: str) -> None:
    snapshot = complete_production_storage_snapshot()
    snapshot["nodes"]["8:0"]["driver_stack"][0]["vendor_id"] = vendor_id

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


@pytest.mark.parametrize(
    "case",
    (
        "vmware_serial",
        "logical_volume_wwid",
        "raid_node",
        "virtual_sysfs_path",
        "virtual_alias",
        "virtual_device_path",
    ),
)
def test_recursive_prohibited_evidence_covers_every_canonical_string(
    case: str,
) -> None:
    snapshot = complete_production_storage_snapshot()
    physical = snapshot["nodes"]["8:0"]
    if case == "vmware_serial":
        physical["device_identity"]["device/serial"] = "VMware-42-00"
    elif case == "logical_volume_wwid":
        physical["device_identity"]["device/wwid"] = "logical-volume-001"
    elif case == "raid_node":
        physical["driver_stack"][0]["node"] = "pci/RAID/controller"
    elif case == "virtual_sysfs_path":
        physical["sysfs_identity"] = "devices/virtual/block/sda"
    elif case == "virtual_alias":
        snapshot["stable_aliases"]["by-id"] = (
            {"device": "8:1", "name": "ata-Virtual_Disk-part1"},
        )
    else:
        physical["driver_stack"][0]["device_path"] = "devices/virtual/pci"

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


def test_pi5_simple_pm_bus_nvme_ancestry_is_exact_and_closed() -> None:
    snapshot = complete_production_storage_snapshot()
    configure_realistic_nvme_snapshot(snapshot)
    physical = snapshot["nodes"]["8:0"]
    pci_path = (
        "platform/axi/1000110000.pcie/pci0000:00/0000:00:00.0/"
        "0000:01:00.0"
    )
    physical["sysfs_identity"] = f"{pci_path}/nvme/nvme0/nvme0n1"
    root = snapshot["nodes"]["8:1"]
    root["uevent"]["DEVNAME"] = "nvme0n1p8"
    root["sysfs_identity"] = f"{pci_path}/nvme/nvme0/nvme0n1/nvme0n1p8"
    physical["driver_stack"] = [
        {
            "driver": "bus/platform/drivers/simple-pm-bus",
            "modalias": "of:NaxiT(null)Csimple-bus",
            "node": "platform/axi",
            "subsystem": "bus/platform",
        },
        {
            "driver": "bus/platform/drivers/brcm-pcie",
            "modalias": "of:NpcieT(null)Cbrcm,bcm2712-pcie",
            "node": "platform/axi/1000110000.pcie",
            "subsystem": "bus/platform",
        },
        {
            "driver": "bus/pci/drivers/pcieport",
            "modalias": "pci:v000014E4d00002711sv000014E4sd00000000bc06sc04i00",
            "node": (
                "platform/axi/1000110000.pcie/pci0000:00/0000:00:00.0"
            ),
            "revision": "0x21",
            "subsystem": "bus/pci",
            "vendor_id": "0x14e4",
        },
        {
            "device_id": "0xa80a",
            "driver": "bus/pci/drivers/nvme",
            "modalias": "pci:v0000144Dd0000A80Asv0000144Dsd0000A801bc01sc08i02",
            "node": pci_path,
            "revision": "0x01",
            "subsystem": "bus/pci",
            "vendor_id": "0x144d",
        },
        {"node": f"{pci_path}/nvme/nvme0", "subsystem": "class/nvme"},
        {
            "node": f"{pci_path}/nvme/nvme0/nvme0n1",
            "subsystem": "class/block",
        },
    ]
    recognized = journal_file._recognized_direct_transport(physical)
    snapshot["transport_identity"] = recognized
    snapshot["hardware_evidence"] = journal_file._mandatory_hardware_evidence(
        physical,
        recognized,
    )
    assert recognized == "nvme-pcie-direct"
    journal_file._validate_production_storage_snapshot(snapshot)

    unknown_platform = deepcopy(snapshot)
    unknown_platform["nodes"]["8:0"]["driver_stack"].append(
        {
            "driver": "bus/platform/drivers/unknown-platform-storage",
            "node": "platform/axi/unknown",
            "subsystem": "bus/platform",
        }
    )
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(unknown_platform)

    wrong_context = deepcopy(snapshot)
    wrong_context["nodes"]["8:0"]["driver_stack"][0]["node"] = "platform/soc"
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(wrong_context)

    generic_simple_bus = deepcopy(snapshot)
    generic_simple_bus["nodes"]["8:0"]["driver_stack"][0].pop("driver")
    generic_simple_bus["nodes"]["8:0"]["driver_stack"][0]["modalias"] = (
        "of:NsocT(null)Csimple-bus"
    )
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(generic_simple_bus)


@pytest.mark.parametrize(
    "case",
    (
        "filesystem_uuid",
        "filesystem_features",
        "partition_uuid",
        "stable_by_id",
        "stable_partuuid",
        "vendor",
        "model",
        "firmware",
        "revision",
        "serial",
        "wwid",
        "transport",
        "driver_identity",
        "subsystem_identity",
        "queue_semantics",
    ),
)
def test_production_snapshot_rejects_missing_stable_identity(case: str) -> None:
    snapshot = complete_production_storage_snapshot()
    if case == "filesystem_uuid":
        snapshot["stable_aliases"]["by-uuid"] = ()
    elif case == "filesystem_features":
        del snapshot["filesystem"]["feature_incompat"]
    elif case == "partition_uuid":
        del snapshot["nodes"]["8:1"]["uevent"]["PARTUUID"]
    elif case == "stable_by_id":
        snapshot["stable_aliases"]["by-id"] = ()
    elif case == "stable_partuuid":
        snapshot["stable_aliases"]["by-partuuid"] = ()
    elif case == "vendor":
        snapshot["nodes"]["8:0"]["device_identity"].pop(
            "device/device/vendor"
        )
    elif case == "model":
        snapshot["nodes"]["8:0"]["device_identity"].pop("device/model")
    elif case == "firmware":
        snapshot["nodes"]["8:0"]["device_identity"].pop("device/firmware_rev")
    elif case == "revision":
        snapshot["nodes"]["8:0"]["driver_stack"][1].pop("revision")
    elif case == "serial":
        snapshot["nodes"]["8:0"]["device_identity"].pop("device/serial")
    elif case == "wwid":
        physical_identity = snapshot["nodes"]["8:0"]["device_identity"]
        for field in ("device/wwid", "eui", "wwid"):
            physical_identity.pop(field, None)
    elif case == "transport":
        snapshot["nodes"]["8:0"]["device_identity"].pop("device/transport")
    elif case == "driver_identity":
        for item in snapshot["nodes"]["8:0"]["driver_stack"]:
            item.pop("driver", None)
    elif case == "subsystem_identity":
        for item in snapshot["nodes"]["8:0"]["driver_stack"]:
            item.pop("subsystem", None)
    else:
        del snapshot["nodes"]["8:0"]["queue"]["queue/write_cache"]

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


@pytest.mark.parametrize(
    "case",
    (
        "endpoint_device",
        "endpoint_revision",
        "endpoint_vendor",
        "firmware",
        "model",
        "namespace_vendor",
        "serial",
        "transport",
        "wwid",
    ),
)
def test_realistic_nvme_identity_rejects_each_missing_field(case: str) -> None:
    snapshot = complete_production_storage_snapshot()
    configure_realistic_nvme_snapshot(snapshot)
    physical = snapshot["nodes"]["8:0"]
    endpoint = physical["driver_stack"][0]
    if case == "endpoint_device":
        endpoint.pop("device_id")
    elif case == "endpoint_revision":
        endpoint.pop("revision")
    elif case == "endpoint_vendor":
        endpoint.pop("vendor_id")
    elif case == "firmware":
        physical["device_identity"].pop("device/firmware_rev")
    elif case == "model":
        physical["device_identity"].pop("device/model")
    elif case == "namespace_vendor":
        physical["device_identity"].pop("device/device/vendor")
    elif case == "serial":
        physical["device_identity"].pop("device/serial")
    elif case == "transport":
        physical["device_identity"].pop("device/transport")
    else:
        for field in ("device/wwid", "eui", "wwid"):
            physical["device_identity"].pop(field)

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._validate_production_storage_snapshot(snapshot)


@pytest.mark.parametrize("field", ("device_id", "revision", "vendor_id"))
def test_nvme_endpoint_fields_cannot_be_substituted_by_pcie_bridge(
    field: str,
) -> None:
    snapshot = complete_production_storage_snapshot()
    configure_realistic_nvme_snapshot(snapshot)
    physical = snapshot["nodes"]["8:0"]
    endpoint = physical["driver_stack"][0]
    bridge = {
        "device_id": "0x2711",
        "driver": "bus/pci/drivers/pcieport",
        "node": "pci/0000:00:00.0",
        "revision": "0x21",
        "subsystem": "bus/pci",
        "vendor_id": "0x14e4",
    }
    endpoint.pop(field)
    physical["driver_stack"].insert(0, bridge)

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._mandatory_hardware_evidence(
            physical,
            "nvme-pcie-direct",
        )


def test_multiple_pci_nvme_endpoints_are_ambiguous() -> None:
    snapshot = complete_production_storage_snapshot()
    physical = snapshot["nodes"]["8:0"]
    physical["driver_stack"].append(deepcopy(physical["driver_stack"][1]))

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._mandatory_hardware_evidence(
            physical,
            "nvme-pcie-direct",
        )


@pytest.mark.parametrize(
    "category",
    (
        "kernel_release",
        "driver",
        "driver_vendor_id",
        "modalias",
        "subsystem",
        "firmware",
        "revision",
        "vendor",
        "model",
        "serial",
        "wwid",
        "transport",
        "queue",
        "partition_uuid",
        "stable_alias",
        "filesystem_features",
        "filesystem_uuid",
        "internal_journal",
        "journal_feature_flags",
    ),
)
def test_storage_digest_binds_every_production_identity_category(
    monkeypatch: pytest.MonkeyPatch,
    category: str,
) -> None:
    holder = {"snapshot": complete_production_storage_snapshot()}
    monkeypatch.setattr(
        journal_file,
        "_storage_stack_binding_data",
        lambda _identity: deepcopy(holder["snapshot"]),
    )
    identity = fake_filesystem_identity()
    baseline = journal_file._storage_stack_binding_digest(identity)
    changed = deepcopy(holder["snapshot"])
    physical = changed["nodes"]["8:0"]
    if category == "kernel_release":
        changed["kernel_release"] = "6.18.35-certified"
    elif category == "driver":
        physical["driver_stack"][1]["driver"] = "bus/pci/drivers/new-nvme"
    elif category == "driver_vendor_id":
        physical["driver_stack"][1]["vendor_id"] = "0x8086"
    elif category == "modalias":
        physical["driver_stack"][1]["modalias"] = "pci:v00008086d00001234"
    elif category == "subsystem":
        physical["driver_stack"][0]["subsystem"] = "bus/platform"
    elif category == "firmware":
        physical["device_identity"]["device/firmware_rev"] = "5B2QGXA8"
    elif category == "revision":
        physical["driver_stack"][1]["revision"] = "0x02"
    elif category == "vendor":
        physical["device_identity"]["device/device/vendor"] = "0x8086"
    elif category == "model":
        physical["device_identity"]["device/model"] = "MODEL2"
    elif category == "serial":
        physical["device_identity"]["device/serial"] = "SERIAL2"
    elif category == "wwid":
        physical["device_identity"]["device/wwid"] = "WWID2"
    elif category == "transport":
        physical["device_identity"]["device/transport"] = "ata"
    elif category == "queue":
        physical["queue"]["queue/write_cache"] = "write through"
    elif category == "partition_uuid":
        new_uuid = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
        changed["nodes"]["8:1"]["uevent"]["PARTUUID"] = new_uuid
        changed["stable_aliases"]["by-partuuid"] = (
            {"device": "8:1", "name": new_uuid},
        )
    elif category == "stable_alias":
        changed["stable_aliases"]["by-id"] = (
            {"device": "8:1", "name": "nvme-Samsung_980_PRO-new-part1"},
        )
    elif category == "filesystem_features":
        changed["filesystem"]["feature_incompat"] = 4
    elif category == "internal_journal":
        changed["filesystem"]["journal_inode"] = 9
    elif category == "journal_feature_flags":
        changed["filesystem"]["jbd2"]["feature_incompat"] = 25
    else:
        new_uuid = "99999999-8888-7777-6666-555555555555"
        changed["filesystem"]["filesystem_uuid"] = new_uuid
        changed["stable_aliases"]["by-uuid"] = (
            {"device": "8:1", "name": new_uuid},
        )
    holder["snapshot"] = changed

    assert journal_file._storage_stack_binding_digest(identity) != baseline


@pytest.mark.parametrize("field", tuple(sorted(journal_file._JBD2_IDENTITY_FIELDS)))
def test_storage_digest_binds_every_jbd2_identity_field(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    holder = {"snapshot": complete_production_storage_snapshot()}
    monkeypatch.setattr(
        journal_file,
        "_storage_stack_binding_data",
        lambda _identity: deepcopy(holder["snapshot"]),
    )
    identity = fake_filesystem_identity()
    baseline = journal_file._storage_stack_binding_digest(identity)
    value = holder["snapshot"]["filesystem"]["jbd2"][field]
    if type(value) is int:
        holder["snapshot"]["filesystem"]["jbd2"][field] = value + 1
    elif type(value) is str:
        holder["snapshot"]["filesystem"]["jbd2"][field] = f"{value}x"
    else:
        holder["snapshot"]["filesystem"]["jbd2"][field] = value + (
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )

    assert journal_file._storage_stack_binding_digest(identity) != baseline


def test_storage_digest_binds_xfs_internal_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = {"snapshot": complete_production_storage_snapshot()}
    holder["snapshot"]["filesystem"] = {
        "bad_features2": 0,
        "feature_compat": 0,
        "feature_incompat": 0,
        "feature_log_incompat": 0,
        "feature_ro_compat": 0,
        "features2": 0,
        "filesystem_type": "xfs",
        "filesystem_uuid": "11111111-2222-3333-4444-555555555555",
        "log_start": 1024,
        "metadata_uuid": None,
        "realtime_bitmap_blocks": 0,
        "realtime_blocks": 0,
        "realtime_extent_size": 0,
        "realtime_extents": 0,
        "version": 5,
        "volume_name_hex": "00" * 12,
    }
    monkeypatch.setattr(
        journal_file,
        "_storage_stack_binding_data",
        lambda _identity: deepcopy(holder["snapshot"]),
    )
    identity = fake_filesystem_identity("xfs")
    baseline = journal_file._storage_stack_binding_digest(identity)
    holder["snapshot"]["filesystem"]["log_start"] = 2048

    assert journal_file._storage_stack_binding_digest(identity) != baseline


@pytest.mark.parametrize(
    ("extent_depth", "fast_commit_blocks"),
    ((0, 0), (1, 0), (0, 128)),
)
def test_supported_ext4_internal_jbd2_identity_is_exact_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
    extent_depth: int,
    fast_commit_blocks: int,
) -> None:
    expected_uuid = "11111111-2222-3333-4444-555555555555"
    image = synthetic_ext4_jbd2_image(
        extent_depth=extent_depth,
        fast_commit_blocks=fast_commit_blocks,
    )
    reads: list[tuple[int, int]] = []
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        synthetic_block_reader(image, reads),
    )

    feature_identity = journal_file._filesystem_feature_identity(
        "ext4",
        "8:1",
        "/dev/disk/by-uuid/example",
        expected_uuid,
    )
    assert feature_identity["filesystem_uuid"] == expected_uuid
    assert feature_identity["filesystem_type"] == "ext4"
    assert feature_identity["journal_has_internal"] is True
    mapping = feature_identity["journal_inode_identity"]["mapping"]
    assert mapping["format"] == "extents"
    assert mapping["depth"] == extent_depth
    assert feature_identity["jbd2"]["uuid"] == expected_uuid
    assert feature_identity["jbd2"]["fast_commit_blocks"] == fast_commit_blocks
    assert not {
        "checksum",
        "error",
        "head",
        "header_sequence",
        "raw_digest",
        "sequence",
        "start",
    }.intersection(feature_identity["jbd2"])
    expected_reads = [(1024, 1024), (4096, 4096), (8192, 4096)]
    if extent_depth == 1:
        expected_reads.append((24576, 4096))
    expected_reads.extend(((409600, 4096), (1024, 1024)))
    assert reads == expected_reads
    assert all(
        offset % 512 == 0 and size in {1024, 4096}
        for offset, size in reads
    )
    snapshot = complete_production_storage_snapshot()
    snapshot["filesystem"] = feature_identity
    journal_file._validate_production_storage_snapshot(snapshot)


@pytest.mark.parametrize(
    ("field", "offset", "value"),
    (
        ("header_sequence", 8, 11),
        ("sequence", 24, 12),
        ("start", 28, 3),
        ("error", 32, 13),
        ("head", 88, 4),
        ("checksum", 8, 14),
    ),
)
def test_volatile_jbd2_changes_validate_without_staling_identity_or_digest(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    offset: int,
    value: int,
) -> None:
    expected_uuid = "11111111-2222-3333-4444-555555555555"
    image = synthetic_ext4_jbd2_image()
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        synthetic_block_reader(image, []),
    )
    baseline_identity = journal_file._filesystem_feature_identity(
        "ext4",
        "8:1",
        "/dev/disk/by-uuid/example",
        expected_uuid,
    )
    jbd2_offset = 4096 * 100
    baseline_checksum = bytes(image[jbd2_offset + 252 : jbd2_offset + 256])
    image[jbd2_offset + offset : jbd2_offset + offset + 4] = value.to_bytes(
        4,
        "big",
    )
    refresh_synthetic_jbd2_checksum(image)
    changed_identity = journal_file._filesystem_feature_identity(
        "ext4",
        "8:1",
        "/dev/disk/by-uuid/example",
        expected_uuid,
    )
    assert bytes(image[jbd2_offset + 252 : jbd2_offset + 256]) != (
        baseline_checksum
    ), field
    assert changed_identity == baseline_identity

    holder = {"snapshot": complete_production_storage_snapshot()}
    holder["snapshot"]["filesystem"] = baseline_identity
    monkeypatch.setattr(
        journal_file,
        "_storage_stack_binding_data",
        lambda _identity: deepcopy(holder["snapshot"]),
    )
    filesystem = fake_filesystem_identity()
    baseline_digest = journal_file._storage_stack_binding_digest(filesystem)
    holder["snapshot"]["filesystem"] = changed_identity
    assert journal_file._storage_stack_binding_digest(filesystem) == baseline_digest


@pytest.mark.parametrize(
    ("field", "offset", "value"),
    (
        ("dynamic_superblock", 68, 2),
        ("feature_incompat", 40, 0x9),
        ("first", 20, 2),
        ("maximum_transaction", 72, 10),
        ("maximum_transaction_data", 76, 10),
    ),
)
def test_static_jbd2_changes_stale_identity_and_digest(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    offset: int,
    value: int,
) -> None:
    expected_uuid = "11111111-2222-3333-4444-555555555555"
    image = synthetic_ext4_jbd2_image()
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        synthetic_block_reader(image, []),
    )
    baseline_identity = journal_file._filesystem_feature_identity(
        "ext4",
        "8:1",
        "/dev/disk/by-uuid/example",
        expected_uuid,
    )
    jbd2_offset = 4096 * 100
    image[jbd2_offset + offset : jbd2_offset + offset + 4] = value.to_bytes(
        4,
        "big",
    )
    refresh_synthetic_jbd2_checksum(image)
    changed_identity = journal_file._filesystem_feature_identity(
        "ext4",
        "8:1",
        "/dev/disk/by-uuid/example",
        expected_uuid,
    )
    assert changed_identity != baseline_identity, field

    holder = {"snapshot": complete_production_storage_snapshot()}
    holder["snapshot"]["filesystem"] = baseline_identity
    monkeypatch.setattr(
        journal_file,
        "_storage_stack_binding_data",
        lambda _identity: deepcopy(holder["snapshot"]),
    )
    filesystem = fake_filesystem_identity()
    baseline_digest = journal_file._storage_stack_binding_digest(filesystem)
    holder["snapshot"]["filesystem"] = changed_identity
    assert journal_file._storage_stack_binding_digest(filesystem) != baseline_digest


def test_twelve_direct_blocks_cannot_qualify_jbd2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = synthetic_ext4_jbd2_image(extent_depth=None)
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        synthetic_block_reader(image, []),
    )

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._filesystem_feature_identity(
            "ext4",
            "8:1",
            "/dev/disk/by-uuid/example",
            "11111111-2222-3333-4444-555555555555",
        )


def test_xfs_superblock_feature_identity_is_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_uuid = "11111111-2222-3333-4444-555555555555"
    raw = bytearray(512)
    raw[:4] = b"XFSB"
    raw[32:48] = bytes.fromhex(expected_uuid.replace("-", ""))
    raw[48:56] = (1).to_bytes(8, "big")
    raw[100:102] = (5).to_bytes(2, "big")
    raw[200:204] = (1).to_bytes(4, "big")
    raw[208:212] = (2).to_bytes(4, "big")
    raw[212:216] = (3).to_bytes(4, "big")
    raw[216:220] = (4).to_bytes(4, "big")
    raw[220:224] = (5).to_bytes(4, "big")
    reads: list[tuple[int, int]] = []

    def read_superblock(
        _alias_path: str,
        _device: str,
        offset: int,
        size: int,
    ) -> bytes:
        reads.append((offset, size))
        return bytes(raw)

    monkeypatch.setattr(journal_file, "_read_exact_block_range", read_superblock)
    feature_identity = journal_file._filesystem_feature_identity(
        "xfs",
        "8:1",
        "/dev/disk/by-uuid/example",
        expected_uuid,
    )
    assert feature_identity["filesystem_uuid"] == expected_uuid
    assert reads == [(0, 512)]

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._filesystem_feature_identity(
            "btrfs",
            "8:1",
            "/dev/disk/by-uuid/example",
            expected_uuid,
        )


@pytest.mark.parametrize(
    "case",
    (
        "external_journal",
        "external_journal_uuid",
        "journal_device_format",
        "missing_internal_journal",
        "zero_journal_inode",
    ),
)
def test_ext4_journal_less_and_external_layouts_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    expected_uuid = "11111111-2222-3333-4444-555555555555"
    image = synthetic_ext4_jbd2_image()
    superblock = memoryview(image)[1024:2048]
    if case == "external_journal":
        superblock[228:232] = (1).to_bytes(4, "little")
    elif case == "external_journal_uuid":
        superblock[208:224] = bytes.fromhex(expected_uuid.replace("-", ""))
    elif case == "journal_device_format":
        superblock[96:100] = (0x4A).to_bytes(4, "little")
    elif case == "missing_internal_journal":
        superblock[92:96] = (0).to_bytes(4, "little")
    else:
        superblock[224:228] = (0).to_bytes(4, "little")
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        synthetic_block_reader(image, []),
    )

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._filesystem_feature_identity(
            "ext4",
            "8:1",
            "/dev/disk/by-uuid/example",
            expected_uuid,
        )


@pytest.mark.parametrize(
    "case",
    (
        "bad_checksum",
        "bad_magic",
        "bad_type",
        "bad_block_size",
        "bad_user_uuid",
        "checksum_features_both",
        "checksum_features_none",
        "checksum_type_1",
        "fast_commit_reservation",
        "first_at_total",
        "first_zero",
        "full_checksum_span",
        "head_out_of_range",
        "inode_mapping_too_short",
        "minimum_length",
        "padding_51",
        "padding_5c",
        "reserved_bytes",
        "unknown_features",
        "uuid_mismatch",
    ),
)
def test_malformed_or_unmodeled_jbd2_superblock_rejects(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    image = synthetic_ext4_jbd2_image()
    offset = 4096 * 100
    if case == "bad_checksum":
        image[offset + 252] ^= 1
    elif case == "bad_magic":
        image[offset : offset + 4] = (0).to_bytes(4, "big")
    elif case == "bad_type":
        image[offset + 4 : offset + 8] = (3).to_bytes(4, "big")
    elif case == "bad_block_size":
        image[offset + 12 : offset + 16] = (1024).to_bytes(4, "big")
    elif case == "bad_user_uuid":
        image[offset + 256 : offset + 272] = bytes.fromhex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        refresh_synthetic_jbd2_checksum(image)
    elif case == "checksum_features_both":
        image[offset + 40 : offset + 44] = (0x19).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    elif case == "checksum_features_none":
        image[offset + 40 : offset + 44] = (0x1).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    elif case == "checksum_type_1":
        image[offset + 80] = 1
        refresh_synthetic_jbd2_checksum(image)
    elif case == "fast_commit_reservation":
        image[offset + 40 : offset + 44] = (0x31).to_bytes(4, "big")
        image[offset + 84 : offset + 88] = (1).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    elif case == "first_at_total":
        image[offset + 20 : offset + 24] = (1024).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    elif case == "first_zero":
        image[offset + 20 : offset + 24] = (0).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    elif case == "full_checksum_span":
        image[offset + 24 : offset + 28] = (8).to_bytes(4, "big")
    elif case == "head_out_of_range":
        image[offset + 88 : offset + 92] = (1024).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    elif case == "inode_mapping_too_short":
        image[offset + 16 : offset + 20] = (1025).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    elif case == "minimum_length":
        image[offset + 16 : offset + 20] = (1023).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    elif case == "padding_51":
        image[offset + 81] = 1
        refresh_synthetic_jbd2_checksum(image)
    elif case == "padding_5c":
        image[offset + 92] = 1
        refresh_synthetic_jbd2_checksum(image)
    elif case == "reserved_bytes":
        image[offset + 273] = 1
        refresh_synthetic_jbd2_checksum(image)
    elif case == "unknown_features":
        image[offset + 40 : offset + 44] = (0x51).to_bytes(4, "big")
        refresh_synthetic_jbd2_checksum(image)
    else:
        image[offset + 48 : offset + 64] = bytes.fromhex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        refresh_synthetic_jbd2_checksum(image)
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        synthetic_block_reader(image, []),
    )

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._filesystem_feature_identity(
            "ext4",
            "8:1",
            "/dev/disk/by-uuid/example",
            "11111111-2222-3333-4444-555555555555",
        )


@pytest.mark.parametrize(
    "case",
    (
        "bigalloc",
        "direct_indirect",
        "encryption",
        "extent_depth",
        "inline_data",
        "meta_bg",
        "metadata_overlap",
        "unwritten_extent",
    ),
)
def test_unsupported_ext4_inode_layout_depth_and_features_reject(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    image = synthetic_ext4_jbd2_image()
    superblock = memoryview(image)[1024:2048]
    inode_offset = 4096 * 2 + 7 * 256
    inode = memoryview(image)[inode_offset : inode_offset + 256]
    if case == "bigalloc":
        superblock[100:104] = (0x200).to_bytes(4, "little")
    elif case == "direct_indirect":
        inode[32:36] = (0).to_bytes(4, "little")
        inode[40:100] = bytes(60)
        inode[40:44] = (10).to_bytes(4, "little")
        inode[88:92] = (20).to_bytes(4, "little")
    elif case == "encryption":
        superblock[96:100] = (0x10042).to_bytes(4, "little")
    elif case == "extent_depth":
        inode[46:48] = (3).to_bytes(2, "little")
    elif case == "inline_data":
        superblock[96:100] = (0x8042).to_bytes(4, "little")
    elif case == "meta_bg":
        superblock[96:100] = (0x52).to_bytes(4, "little")
    elif case == "metadata_overlap":
        inode[60:64] = (2).to_bytes(4, "little")
    else:
        inode[56:58] = (0x8001).to_bytes(2, "little")
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        synthetic_block_reader(image, []),
    )

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._filesystem_feature_identity(
            "ext4",
            "8:1",
            "/dev/disk/by-uuid/example",
            "11111111-2222-3333-4444-555555555555",
        )


def test_unreadable_ext4_journal_inode_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = synthetic_ext4_jbd2_image()

    def unreadable_inode(
        alias_path: str,
        device: str,
        offset: int,
        size: int,
    ) -> bytes:
        if offset == 8192:
            raise journal_file.ReferenceJournalUnsupportedFilesystemError(
                "synthetic unreadable inode"
            )
        return synthetic_block_reader(image, [])(
            alias_path,
            device,
            offset,
            size,
        )

    monkeypatch.setattr(journal_file, "_read_exact_block_range", unreadable_inode)
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._filesystem_feature_identity(
            "ext4",
            "8:1",
            "/dev/disk/by-uuid/example",
            "11111111-2222-3333-4444-555555555555",
        )


def test_crc32c_and_raw_read_range_bounds() -> None:
    assert journal_file._JBD2_CHECKSUM_TYPE_CRC32C == 4
    assert journal_file._crc32c(b"") == 0xFFFFFFFF
    assert journal_file._crc32c(b"abc") == 0xC9B4C048
    assert journal_file._crc32c(b"123456789") == 0x1CF96D7C
    for offset, size in (
        (-512, 512),
        (1, 512),
        (512, 1024),
        (0, 3),
        (0, 131072),
    ):
        with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
            journal_file._read_exact_block_range(
                "/not-opened",
                "8:1",
                offset,
                size,
            )


def test_jbd2_checksum_covers_the_full_1024_byte_superblock() -> None:
    image = synthetic_ext4_jbd2_image()
    offset = 4096 * 100
    baseline = int.from_bytes(image[offset + 252 : offset + 256], "big")
    changed = bytearray(image[offset : offset + 1024])
    changed[300] = 1
    changed[252:256] = bytes(4)

    assert journal_file._crc32c(bytes(changed)) != baseline
    assert journal_file._crc32c(bytes(changed[:252])) == journal_file._crc32c(
        bytes(image[offset : offset + 252])
    )


def test_jbd2_bytes_beyond_the_1024_byte_structure_are_not_certified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = synthetic_ext4_jbd2_image()
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        synthetic_block_reader(image, []),
    )
    baseline = journal_file._filesystem_feature_identity(
        "ext4",
        "8:1",
        "/dev/disk/by-uuid/example",
        "11111111-2222-3333-4444-555555555555",
    )
    image[4096 * 100 + 1100] = 1

    assert (
        journal_file._filesystem_feature_identity(
            "ext4",
            "8:1",
            "/dev/disk/by-uuid/example",
            "11111111-2222-3333-4444-555555555555",
        )
        == baseline
    )


@pytest.mark.parametrize(
    "case",
    ("external_log", "realtime_blocks", "realtime_extents", "realtime_bitmap"),
)
def test_xfs_external_log_and_realtime_devices_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    expected_uuid = "11111111-2222-3333-4444-555555555555"
    raw = bytearray(512)
    raw[:4] = b"XFSB"
    raw[32:48] = bytes.fromhex(expected_uuid.replace("-", ""))
    raw[48:56] = (1).to_bytes(8, "big")
    if case == "external_log":
        raw[48:56] = (0).to_bytes(8, "big")
    elif case == "realtime_blocks":
        raw[16:24] = (1).to_bytes(8, "big")
    elif case == "realtime_extents":
        raw[24:32] = (1).to_bytes(8, "big")
    else:
        raw[92:96] = (1).to_bytes(4, "big")
    monkeypatch.setattr(
        journal_file,
        "_read_exact_block_range",
        lambda *_args: bytes(raw),
    )

    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        journal_file._filesystem_feature_identity(
            "xfs",
            "8:1",
            "/dev/disk/by-uuid/example",
            expected_uuid,
        )


async def test_generation_rules_and_inode_byte_cas(config_dir: Path) -> None:
    store = await open_store(config_dir)
    assert await store.async_load() is None
    with pytest.raises(journal_file.ReferenceJournalPoisonedError) as wrong_generation:
        await store.async_save({"generation": 1})
    assert isinstance(
        wrong_generation.value.__cause__,
        journal_file.ReferenceJournalConflictError,
    )
    with pytest.raises(journal_file.ReferenceJournalPoisonedError):
        await store.async_load()
    await store.async_close()

    initial = await open_store(config_dir)
    assert await initial.async_load() is None
    generation_zero = {"generation": 0, "value": "initial"}
    await initial.async_save(generation_zero)
    await initial.async_barrier()
    await initial.async_close()

    locked = await open_store(config_dir)
    assert await locked.async_load() == generation_zero
    directory, final_path, _temp_path, _lock_path = names(config_dir)
    replacement = directory / "external-cas-replacement"
    write_bytes(replacement, canonical(generation_zero))
    os.replace(replacement, final_path)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)

    with pytest.raises(journal_file.ReferenceJournalPoisonedError) as cas_failure:
        await locked.async_save({"generation": 1, "value": "next"})
    assert isinstance(cas_failure.value.__cause__, journal_file.ReferenceJournalConflictError)
    await locked.async_close()


@pytest.mark.parametrize(
    "raw",
    (
        b' {"generation":0}',
        b'{"generation":0}\n',
        b'{"generation": 0}',
        b'{"z":1,"generation":0}',
        '{"generation":0,"name":"caf\u00e9"}'.encode("utf-8"),
        b'{"generation":0,"name":"\\u0061"}',
        b'{"generation":0,"value":1e0}',
        b'\xef\xbb\xbf{"generation":0}',
        b'{"generation":0,"value":"\xff"}',
    ),
)
async def test_noncanonical_raw_byte_matrix_is_rejected(
    config_dir: Path,
    raw: bytes,
) -> None:
    await provision_structure(config_dir)
    _directory, final_path, _temp_path, _lock_path = names(config_dir)
    write_bytes(final_path, raw)

    store = await open_store(config_dir)
    with pytest.raises(journal_file.ReferenceJournalCorruptionError):
        await store.async_load()
    with pytest.raises(journal_file.ReferenceJournalPoisonedError):
        await store.async_load()
    await store.async_close()


@pytest.mark.parametrize(
    "raw",
    (
        b'{"generation":0,"generation":0}',
        b'{"generation":NaN}',
        b'{"generation":Infinity}',
        b'{"generation":-Infinity}',
        b'{"generation":' + b"1" + (b"0" * journal_file.MAX_INTEGER_DIGITS) + b"}",
    ),
)
async def test_duplicate_nonfinite_and_oversized_integer_are_rejected(
    config_dir: Path,
    raw: bytes,
) -> None:
    await provision_structure(config_dir)
    _directory, final_path, _temp_path, _lock_path = names(config_dir)
    write_bytes(final_path, raw)
    store = await open_store(config_dir)
    with pytest.raises(journal_file.ReferenceJournalCorruptionError):
        await store.async_load()
    await store.async_close()


async def test_byte_depth_and_node_bounds_are_enforced(config_dir: Path) -> None:
    await provision_structure(config_dir)
    _directory, final_path, _temp_path, _lock_path = names(config_dir)
    write_bytes(final_path, b"x" * 65)
    bounded = await open_store(config_dir, max_bytes=64)
    with pytest.raises(journal_file.ReferenceJournalCorruptionError):
        await bounded.async_load()
    await bounded.async_close()

    final_path.unlink()
    nested: Any = 0
    for _index in range(journal_file.MAX_JSON_DEPTH):
        nested = [nested]
    write_bytes(final_path, canonical({"generation": 0, "nested": nested}))
    deep = await open_store(config_dir)
    with pytest.raises(journal_file.ReferenceJournalCorruptionError):
        await deep.async_load()
    await deep.async_close()

    final_path.unlink()
    crowded = {
        "generation": 0,
        "nodes": [0] * journal_file.MAX_JSON_NODES,
    }
    write_bytes(final_path, canonical(crowded))
    many = await open_store(config_dir)
    with pytest.raises(journal_file.ReferenceJournalCorruptionError):
        await many.async_load()
    await many.async_close()


def test_lexical_preflight_rejects_before_json_decoder_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoder_called = False

    def forbidden_decoder(*_args, **_kwargs):
        nonlocal decoder_called
        decoder_called = True
        raise AssertionError("json.loads must not receive hostile lexical input")

    monkeypatch.setattr(journal_file.json, "loads", forbidden_decoder)
    oversized_string = (
        b'{"generation":0,"value":"'
        + (b"x" * (journal_file.MAX_JSON_STRING_BYTES + 1))
        + b'"}'
    )
    too_many_nodes = (
        b'{"generation":0,"nodes":['
        + (b"0," * journal_file.MAX_JSON_NODES)
        + b"0]}"
    )
    for raw in (oversized_string, too_many_nodes):
        with pytest.raises(journal_file.ReferenceJournalCorruptionError):
            journal_file._canonical_decode(raw, journal_file.DEFAULT_MAX_BYTES)
    assert decoder_called is False


def test_hostile_json_preflight_under_subprocess_memory_limit() -> None:
    module_path = str(Path(journal_file.__file__).resolve())
    script = f"""
import importlib.util
import resource
import sys

spec = importlib.util.spec_from_file_location("isolated_reference_journal_file", {module_path!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
limit = 160 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

def forbidden_decoder(*args, **kwargs):
    raise AssertionError("decoder reached")

module.json.loads = forbidden_decoder
payloads = (
    b'{{"generation":0,"value":"' + b'x' * (module.MAX_JSON_STRING_BYTES + 1) + b'"}}',
    b'{{"generation":0,"nodes":[' + b'0,' * module.MAX_JSON_NODES + b'0]}}',
)
for payload in payloads:
    try:
        module._canonical_decode(payload, module.DEFAULT_MAX_BYTES)
    except module.ReferenceJournalCorruptionError:
        pass
    else:
        raise AssertionError("hostile JSON was accepted")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr


async def test_save_rejects_nonfinite_data_and_poison_is_sticky(
    config_dir: Path,
) -> None:
    store = await open_store(config_dir)
    assert await store.async_load() is None
    with pytest.raises(journal_file.ReferenceJournalPoisonedError) as invalid:
        await store.async_save({"generation": 0, "value": math.nan})
    assert isinstance(
        invalid.value.__cause__,
        journal_file.ReferenceJournalCorruptionError,
    )
    with pytest.raises(journal_file.ReferenceJournalPoisonedError):
        await store.async_barrier()
    await store.async_close()


async def test_valid_stale_temp_is_removed_and_directory_fsynced(
    config_dir: Path,
) -> None:
    await provision_structure(config_dir)
    _directory, _final_path, temp_path, _lock_path = names(config_dir)
    write_bytes(temp_path, b"incomplete")
    events: list[str] = []
    store = await open_store(config_dir, failpoint=events.append)
    assert not temp_path.exists()
    assert "before_stale_temp_unlink" in events
    assert "after_stale_temp_unlink" in events
    assert "before_stale_temp_directory_fsync" in events
    assert "after_stale_temp_directory_fsync" in events
    await store.async_close()


def plant_malicious_entry(kind: str, path: Path, outside: Path) -> None:
    write_bytes(outside, b"outside")
    if kind == "symlink":
        path.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
        path.chmod(0o600)
    elif kind == "wrong_mode":
        write_bytes(path, b"unsafe", mode=0o640)
    else:
        raise AssertionError(kind)


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "fifo", "wrong_mode"))
async def test_unsafe_stale_temp_blocks_without_removal(
    config_dir: Path,
    kind: str,
) -> None:
    await provision_structure(config_dir)
    _directory, _final_path, temp_path, _lock_path = names(config_dir)
    outside = config_dir / f"outside-temp-{kind}"
    plant_malicious_entry(kind, temp_path, outside)
    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await open_store(config_dir)
    assert os.path.lexists(temp_path)


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "fifo", "wrong_mode"))
async def test_unsafe_final_file_fails_closed_without_hanging(
    config_dir: Path,
    kind: str,
) -> None:
    await provision_structure(config_dir)
    _directory, final_path, _temp_path, _lock_path = names(config_dir)
    outside = config_dir / f"outside-final-{kind}"
    plant_malicious_entry(kind, final_path, outside)
    store = await open_store(config_dir)
    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await asyncio.wait_for(store.async_load(), timeout=2)
    await store.async_close()


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "fifo", "wrong_mode"))
async def test_unsafe_lock_file_blocks_open(
    config_dir: Path,
    kind: str,
) -> None:
    await provision_structure(config_dir)
    _directory, _final_path, _temp_path, lock_path = names(config_dir)
    lock_path.unlink()
    outside = config_dir / f"outside-lock-{kind}"
    plant_malicious_entry(kind, lock_path, outside)
    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await asyncio.wait_for(open_store(config_dir), timeout=2)


async def test_config_and_child_directory_security_checks(config_dir: Path) -> None:
    policy = policy_for(config_dir)
    config_dir.chmod(0o720)
    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await journal_file.CrashDurableReferenceJournalStore.async_open(
            config_dir=str(config_dir),
            journal_id=JOURNAL_ID,
            filesystem_policy=policy,
        )
    config_dir.chmod(0o700)

    await provision_structure(config_dir)
    directory, _final_path, _temp_path, _lock_path = names(config_dir)
    directory.chmod(0o750)
    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await open_store(config_dir)


async def test_config_symlink_and_relative_path_are_rejected(
    config_dir: Path,
    tmp_path: Path,
) -> None:
    symlink = tmp_path / "config-link"
    symlink.symlink_to(config_dir, target_is_directory=True)
    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await journal_file.CrashDurableReferenceJournalStore.async_open(
            config_dir=str(symlink),
            journal_id=JOURNAL_ID,
            filesystem_policy=policy_for(config_dir),
        )
    ancestor_symlink = tmp_path / "ancestor-link"
    ancestor_symlink.symlink_to(config_dir.parent, target_is_directory=True)
    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await journal_file.CrashDurableReferenceJournalStore.async_open(
            config_dir=str(ancestor_symlink / config_dir.name),
            journal_id=JOURNAL_ID,
            filesystem_policy=policy_for(config_dir),
        )
    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await journal_file.CrashDurableReferenceJournalStore.async_open(
            config_dir="relative-config",
            journal_id=JOURNAL_ID,
            filesystem_policy=policy_for(config_dir),
        )


async def test_second_backend_is_busy_until_close_releases_lock(
    config_dir: Path,
) -> None:
    first = await open_store(config_dir)
    with pytest.raises(journal_file.ReferenceJournalBusyError):
        await open_store(config_dir)
    await first.async_close()

    second = await open_store(config_dir)
    assert await second.async_load() is None
    await second.async_close()


async def test_simultaneous_first_open_has_one_flock_owner(config_dir: Path) -> None:
    results = await asyncio.gather(
        open_store(config_dir),
        open_store(config_dir),
        return_exceptions=True,
    )
    owners = [
        result
        for result in results
        if isinstance(result, journal_file.CrashDurableReferenceJournalStore)
    ]
    busy = [
        result
        for result in results
        if isinstance(result, journal_file.ReferenceJournalBusyError)
    ]
    assert len(owners) == 1
    assert len(busy) == 1
    assert await owners[0].async_load() is None
    await owners[0].async_close()

    reopened = await open_store(config_dir)
    await reopened.async_close()


async def test_held_lock_name_and_inode_are_revalidated(config_dir: Path) -> None:
    store = await open_store(config_dir)
    _directory, _final_path, _temp_path, lock_path = names(config_dir)
    lock_path.unlink()
    write_bytes(lock_path, b"replacement-lock")

    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await store.async_load()
    with pytest.raises(journal_file.ReferenceJournalPoisonedError):
        await store.async_load()
    await store.async_close()

    with pytest.raises(journal_file.ReferenceJournalSecurityError):
        await open_store(config_dir)
    lock_path.unlink()
    reopened = await open_store(config_dir)
    assert await reopened.async_load() is None
    await reopened.async_close()


async def test_short_writes_and_eintr_complete_exactly(
    config_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await open_store(config_dir)
    assert await store.async_load() is None
    original_write = journal_file._raw_write
    calls = 0

    def interrupted_short_write(descriptor: int, data) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InterruptedError(errno.EINTR, "injected EINTR")
        amount = max(1, min(len(data), 7))
        return original_write(descriptor, data[:amount])

    monkeypatch.setattr(journal_file, "_raw_write", interrupted_short_write)
    payload = {"generation": 0, "payload": "x" * 4096}
    await store.async_save(payload)
    await store.async_barrier()
    assert calls > 10
    await store.async_close()

    _directory, final_path, _temp_path, _lock_path = names(config_dir)
    assert final_path.read_bytes() == canonical(payload)


class RaiseOnce:
    def __init__(self, event: str) -> None:
        self.event = event
        self.raised = False

    def __call__(self, event: str) -> None:
        if event == self.event and not self.raised:
            self.raised = True
            raise OSError(errno.EIO, f"injected {event}")


@pytest.mark.parametrize(
    ("event", "error_type", "replacement_visible"),
    (
        ("before_temp_file_fsync", journal_file.ReferenceJournalPoisonedError, False),
        ("before_replace", journal_file.ReferenceJournalPoisonedError, False),
        (
            "after_replace",
            journal_file.ReferenceJournalAmbiguousDurabilityError,
            True,
        ),
        (
            "before_commit_directory_fsync",
            journal_file.ReferenceJournalAmbiguousDurabilityError,
            True,
        ),
    ),
)
async def test_save_fault_poisoning_and_pre_post_replace_recovery(
    config_dir: Path,
    event: str,
    error_type: type[BaseException],
    replacement_visible: bool,
) -> None:
    failpoint = RaiseOnce(event)
    store = await open_store(config_dir, failpoint=failpoint)
    assert await store.async_load() is None
    payload = {"generation": 0, "event": event}
    with pytest.raises(error_type):
        await store.async_save(payload)
    assert failpoint.raised
    with pytest.raises(journal_file.ReferenceJournalPoisonedError):
        await store.async_load()
    await store.async_close()

    recovered = await open_store(config_dir)
    loaded = await recovered.async_load()
    assert loaded == payload if replacement_visible else loaded is None
    await recovered.async_close()


async def test_replace_syscall_fault_is_poisoned(
    config_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await open_store(config_dir)
    assert await store.async_load() is None

    def fail_replace(*_args, **_kwargs) -> None:
        raise OSError(errno.EIO, "injected replace failure")

    monkeypatch.setattr(journal_file, "_raw_replace", fail_replace)
    with pytest.raises(journal_file.ReferenceJournalAmbiguousDurabilityError):
        await store.async_save({"generation": 0})
    await store.async_close()


async def test_temp_close_error_cannot_double_close_a_reused_descriptor(
    config_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await open_store(config_dir)
    assert await store.async_load() is None
    original_close = journal_file._raw_temp_close
    reused_descriptors: list[int] = []

    def close_reuse_and_fail(descriptor: int) -> None:
        original_close(descriptor)
        reused = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        reused_descriptors.append(reused)
        assert reused == descriptor
        raise OSError(errno.EIO, "injected close-after-reuse failure")

    monkeypatch.setattr(journal_file, "_raw_temp_close", close_reuse_and_fail)
    payload = {"generation": 0, "value": "published-before-close-error"}
    with pytest.raises(journal_file.ReferenceJournalAmbiguousDurabilityError):
        await store.async_save(payload)
    assert len(reused_descriptors) == 1
    os.fstat(reused_descriptors[0])
    await store.async_close()
    os.fstat(reused_descriptors[0])
    os.close(reused_descriptors[0])

    recovered = await open_store(config_dir)
    assert await recovered.async_load() == payload
    await recovered.async_close()


async def test_barrier_is_coupled_and_one_shot(config_dir: Path) -> None:
    store = await open_store(config_dir)
    with pytest.raises(journal_file.ReferenceJournalProtocolError):
        await store.async_barrier()
    with pytest.raises(journal_file.ReferenceJournalProtocolError):
        await store.async_save({"generation": 0})

    assert await store.async_load() is None
    await store.async_save({"generation": 0})
    with pytest.raises(journal_file.ReferenceJournalProtocolError):
        await store.async_load()
    with pytest.raises(journal_file.ReferenceJournalProtocolError):
        await store.async_save({"generation": 1})
    await store.async_barrier()
    with pytest.raises(journal_file.ReferenceJournalProtocolError):
        await store.async_barrier()

    assert await store.async_load() == {"generation": 0}
    await store.async_save({"generation": 1})
    await store.async_barrier()
    await store.async_close()


async def test_barrier_fsync_fault_is_ambiguous_and_sticky(
    config_dir: Path,
) -> None:
    failpoint = RaiseOnce("before_barrier_directory_fsync")
    store = await open_store(config_dir, failpoint=failpoint)
    assert await store.async_load() is None
    await store.async_save({"generation": 0})
    with pytest.raises(journal_file.ReferenceJournalAmbiguousDurabilityError):
        await store.async_barrier()
    with pytest.raises(journal_file.ReferenceJournalAmbiguousDurabilityError):
        await store.async_load()
    await store.async_close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Linux fork is unavailable")
@pytest.mark.parametrize(
    ("event", "run_barrier", "crash_kind", "expected_value"),
    (
        ("after_temp_create", False, "exit", "old"),
        ("after_temp_write", False, "kill", "old"),
        ("after_temp_file_fsync", False, "exit", "old"),
        ("after_replace", False, "kill", "new"),
        ("after_commit_directory_fsync", False, "exit", "new"),
        ("after_barrier_directory_fsync", True, "kill", "new"),
    ),
)
async def test_process_crash_failpoint_families_recover_in_fresh_process(
    config_dir: Path,
    event: str,
    run_barrier: bool,
    crash_kind: str,
    expected_value: str,
) -> None:
    old = {"generation": 0, "value": "old"}
    new = {"generation": 1, "value": "new"}
    initial = await open_store(config_dir)
    assert await initial.async_load() is None
    await initial.async_save(old)
    await initial.async_barrier()
    await initial.async_close()
    policy = policy_for(config_dir)

    child_pid = fork_without_warning()
    if child_pid == 0:
        def crash_failpoint(name: str) -> None:
            if name != event:
                return
            if crash_kind == "kill":
                os.kill(os.getpid(), signal.SIGKILL)
            os._exit(73)

        async def crash_writer() -> None:
            backend = await journal_file.CrashDurableReferenceJournalStore.async_open(
                config_dir=str(config_dir),
                journal_id=JOURNAL_ID,
                filesystem_policy=policy,
                failpoint=crash_failpoint,
            )
            if await backend.async_load() != old:
                os._exit(91)
            await backend.async_save(new)
            if run_barrier:
                await backend.async_barrier()
            os._exit(92)

        try:
            asyncio.run(crash_writer())
        except BaseException:
            os._exit(93)
        os._exit(94)

    crash_status = await wait_for_child(child_pid)
    if crash_kind == "kill":
        assert os.WIFSIGNALED(crash_status)
        assert os.WTERMSIG(crash_status) == signal.SIGKILL
    else:
        assert os.waitstatus_to_exitcode(crash_status) == 73

    recovery_read, recovery_write = os.pipe()
    recovery_pid = fork_without_warning()
    if recovery_pid == 0:
        os.close(recovery_read)

        async def recover() -> dict[str, Any]:
            backend = await journal_file.CrashDurableReferenceJournalStore.async_open(
                config_dir=str(config_dir),
                journal_id=JOURNAL_ID,
                filesystem_policy=policy,
            )
            loaded = await backend.async_load()
            _directory, _final, temp_path, _lock = names(config_dir)
            temp_exists = os.path.lexists(temp_path)
            await backend.async_close()
            return {"loaded": loaded, "temp_exists": temp_exists}

        try:
            result = asyncio.run(recover())
            os.write(
                recovery_write,
                json.dumps(result, separators=(",", ":"), sort_keys=True).encode()
                + b"\n",
            )
            os.close(recovery_write)
            os._exit(0)
        except BaseException as err:
            os.write(
                recovery_write,
                f'{{"error":"{type(err).__name__}"}}\n'.encode(),
            )
            os.close(recovery_write)
            os._exit(1)

    os.close(recovery_write)
    try:
        recovery_raw = await read_pipe_until(recovery_read, b"\n")
        recovery_status = await wait_for_child(recovery_pid)
    finally:
        os.close(recovery_read)
    assert os.waitstatus_to_exitcode(recovery_status) == 0
    recovered = json.loads(recovery_raw)
    assert recovered == {
        "loaded": new if expected_value == "new" else old,
        "temp_exists": False,
    }
    _directory, _final, temp_path, _lock = names(config_dir)
    assert not os.path.lexists(temp_path)


async def wait_for_thread_event(event: threading.Event) -> None:
    for _index in range(1000):
        if event.is_set():
            return
        await asyncio.sleep(0.001)
    raise AssertionError("Worker failpoint was not reached.")


async def test_cancelled_save_drains_worker_and_loop_keeps_heartbeat(
    config_dir: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def failpoint(event: str) -> None:
        if event == "before_temp_file_fsync":
            entered.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signalled")

    store = await open_store(config_dir, failpoint=failpoint)
    assert await store.async_load() is None
    beats = 0
    running = True

    async def heartbeat() -> None:
        nonlocal beats
        while running:
            beats += 1
            await asyncio.sleep(0)

    heartbeat_task = asyncio.create_task(heartbeat())
    saving = asyncio.create_task(store.async_save({"generation": 0, "value": "saved"}))
    await wait_for_thread_event(entered)
    saving.cancel()
    await asyncio.sleep(0)
    saving.cancel()
    await asyncio.sleep(0.03)
    assert beats > 10
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await saving
    await store.async_barrier()
    running = False
    await heartbeat_task
    await store.async_close()

    reopened = await open_store(config_dir)
    assert await reopened.async_load() == {"generation": 0, "value": "saved"}
    await reopened.async_close()


async def test_cancelled_close_drains_before_releasing_flock(
    config_dir: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def failpoint(event: str) -> None:
        if event == "before_barrier_directory_fsync":
            entered.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signalled")

    store = await open_store(config_dir, failpoint=failpoint)
    assert await store.async_load() is None
    await store.async_save({"generation": 0})
    barrier = asyncio.create_task(store.async_barrier())
    await wait_for_thread_event(entered)
    closing = asyncio.create_task(store.async_close())
    await asyncio.sleep(0)
    closing.cancel()
    await asyncio.sleep(0)
    closing.cancel()

    with pytest.raises(journal_file.ReferenceJournalBusyError):
        await open_store(config_dir)
    release.set()
    await barrier
    with pytest.raises(asyncio.CancelledError):
        await closing
    await store.async_close()

    reopened = await open_store(config_dir)
    await reopened.async_close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Linux fork is unavailable")
async def test_fork_waits_until_transient_temp_sequence_finishes(
    config_dir: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def failpoint(event: str) -> None:
        if event == "before_temp_file_fsync":
            entered.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test release was not signalled")

    store = await open_store(config_dir, failpoint=failpoint)
    assert await store.async_load() is None
    saving = asyncio.create_task(store.async_save({"generation": 0}))
    await wait_for_thread_event(entered)
    timer = threading.Timer(0.1, release.set)
    timer.start()
    started = time.monotonic()
    child_pid = fork_without_warning()
    if child_pid == 0:
        os._exit(0)
    elapsed = time.monotonic() - started
    timer.join(timeout=2)
    assert not timer.is_alive()
    status = await wait_for_child(child_pid)
    assert os.waitstatus_to_exitcode(status) == 0
    assert elapsed >= 0.075
    await saving
    await store.async_barrier()
    await store.async_close()


async def test_pid_change_rejects_use_before_executor_submission(
    config_dir: Path,
) -> None:
    store = await open_store(config_dir)
    opening_pid = store._pid
    store._pid = opening_pid + 1
    with pytest.raises(journal_file.ReferenceJournalForkError):
        await store.async_load()
    with pytest.raises(journal_file.ReferenceJournalForkError):
        _ = store.durability_proof
    store._pid = opening_pid
    await store.async_close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Linux fork is unavailable")
async def test_atfork_closes_inherited_fds_and_cross_process_lock_serializes(
    config_dir: Path,
) -> None:
    store = await open_store(config_dir)
    policy = policy_for(config_dir)
    inherited_lock_fd = store._lock_fd
    child_read, parent_write = os.pipe()
    parent_read, child_write = os.pipe()
    child_pid = fork_without_warning()
    if child_pid == 0:
        os.close(parent_read)
        os.close(parent_write)
        try:
            inherited_closed = False
            try:
                os.fstat(inherited_lock_fd)
            except OSError as err:
                inherited_closed = err.errno == errno.EBADF

            async def first_attempt() -> bool:
                try:
                    contender = await journal_file.CrashDurableReferenceJournalStore.async_open(
                        config_dir=str(config_dir),
                        journal_id=JOURNAL_ID,
                        filesystem_policy=policy,
                    )
                except journal_file.ReferenceJournalBusyError:
                    return True
                await contender.async_close()
                return False

            busy = asyncio.run(first_attempt())
            immediate = (
                store._resources.forked_child
                and store._resources.config_fd == -1
                and store._resources.directory_fd == -1
                and store._resources.lock_fd == -1
                and inherited_closed
            )
            os.write(child_write, f"immediate={immediate};busy={busy}\n".encode())
            if os.read(child_read, 1) != b"r":
                raise RuntimeError("parent release signal was missing")

            async def second_attempt() -> None:
                acquired = await journal_file.CrashDurableReferenceJournalStore.async_open(
                    config_dir=str(config_dir),
                    journal_id=JOURNAL_ID,
                    filesystem_policy=policy,
                )
                if await acquired.async_load() is not None:
                    raise RuntimeError("unexpected existing journal")
                await acquired.async_save({"generation": 0, "writer": "child"})
                await acquired.async_barrier()
                await acquired.async_close()

            asyncio.run(second_attempt())
            os.write(child_write, b"acquired\n")
        except BaseException as err:
            os.write(child_write, f"error={type(err).__name__}:{err}\n".encode())
        finally:
            os.close(child_read)
            os.close(child_write)
            os._exit(0)

    os.close(child_read)
    os.close(child_write)
    status: int | None = None
    try:
        first = await read_pipe_until(parent_read, b"\n")
        assert first == b"immediate=True;busy=True\n"
        await store.async_close()
        os.write(parent_write, b"r")
        second = await read_pipe_until(parent_read, b"acquired\n")
        assert second == b"acquired\n"
        status = await wait_for_child(child_pid)
    finally:
        os.close(parent_read)
        os.close(parent_write)
        if status is None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _waited_pid, status = os.waitpid(child_pid, 0)
    assert status is not None
    assert os.waitstatus_to_exitcode(status) == 0
    verified = await open_store(config_dir)
    assert await verified.async_load() == {"generation": 0, "writer": "child"}
    await verified.async_close()


async def test_hashed_basename_contains_no_path_traversal(config_dir: Path) -> None:
    journal_id = "../../outside/opaque-journal"
    basename = journal_file.reference_journal_basename(journal_id)
    assert re.fullmatch(r"[0-9a-f]{64}", basename)
    assert journal_id not in basename
    assert "/" not in basename

    store = await open_store(config_dir, journal_id=journal_id)
    assert await store.async_load() is None
    await store.async_save({"generation": 0})
    await store.async_barrier()
    await store.async_close()

    directory, final_path, temp_path, lock_path = names(config_dir, journal_id)
    assert final_path.parent == directory
    assert lock_path.parent == directory
    assert not temp_path.exists()
    assert set(item.name for item in directory.iterdir()) == {
        f"{basename}.json",
        f"{basename}.lock",
    }


async def test_unsupported_filesystem_policy_fails_before_provisioning(
    config_dir: Path,
) -> None:
    blocked = journal_file.DurableFilesystemPolicy.for_test_filesystems(frozenset())
    with pytest.raises(journal_file.ReferenceJournalUnsupportedFilesystemError):
        await journal_file.CrashDurableReferenceJournalStore.async_open(
            config_dir=str(config_dir),
            journal_id=JOURNAL_ID,
            filesystem_policy=blocked,
        )
    assert not (config_dir / journal_file.REFERENCE_JOURNAL_DIRECTORY_NAME).exists()

    with pytest.raises(FrozenInstanceError):
        setattr(blocked, "allowed_filesystem_types", frozenset({"ext4"}))
    with pytest.raises(TypeError):
        journal_file.DurableFilesystemPolicy(frozenset({"ext4"}))  # type: ignore[call-arg]
