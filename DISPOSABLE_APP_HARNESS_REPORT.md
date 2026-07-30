# Disposable App Harness Report

Date: 2026-07-30

## Scope

This report records an external, project-only aarch64 App payload test. It did
not install anything through the household Supervisor and did not connect to
MQTT, Zigbee, Scheduler, dashboards, or heating.

## Build Evidence

- Imported official Home Assistant base `3.24` for aarch64.
- Installed the Dockerfile-declared `python3` and `py3-aiohttp` packages into a
  clean unpacked root filesystem.
- Copied the exact canonical `run.sh` and `server.py` payload.
- Assembled clean OCI tag `clean-app` with digest
  `sha256:6690a8a98b631f2c6e49943cb7e04c29a724930c871e7b7511358e18aad74ec2`.
- The clean image contains no `/data`, SQLite database, discovery record, mock
  host mapping, test probe, or household data.
- Metadata identifies aarch64, App version `0.1.0`, `/init` entrypoint,
  `/app/run.sh` command, `/app` working directory, and exposed port `8765/tcp`.
- Runtime package versions were Python 3.14.5, aiohttp 3.13.5, and SQLite 3.53.2.

The image was assembled with `skopeo`, `umoci`, and Alpine `apk` because nested
Docker/Podman mounting was denied inside the protected OpenCode App. It was not
built by Docker/BuildKit and was not installed by Supervisor. Only the
digest-scoped `clean-app` image is accepted; the earlier post-run artifact was
removed from the OCI layout.

## Runtime Evidence

- Ran the exact App payload in an Alpine chroot against a localhost Supervisor
  stub.
- The captured process remained UID/GID 0 but had zero effective, permitted,
  bounding, inheritable, and ambient Linux capabilities, with `NoNewPrivs=1`.
- `/healthz` returned the expected protocol response.
- The App posted `true_family` discovery with the expected host, port, protocol,
  per-boot identifier, and in-memory HMAC key.
- The real `RemoteReferenceJournalStore` client performed an absent load, save,
  durability barrier, and generation-zero read-back against the external App.
- A graceful stop removed WAL/SHM files and left a checkpointed SQLite database.
- A cold copy passed SQLite `quick_check` and retained the expected journal and
  durable receipt.
- Restart rotated both boot identity and HMAC key, reopened the existing journal,
  and rejected the stale key.

## Frozen Project Gate

- 563 pytest cases passed in the pinned Home Assistant 2026.7.4 harness.
- 151 pure unittest cases passed.
- 714 total tests passed, plus lock, Python, JSON, JavaScript, and shell checks.

## Real Supervisor App-Only Evidence

The user downloaded a full pre-change backup before this test. A temporary
private Git repository then exposed only the journal App to the household
Supervisor. The integration was not installed, and no MQTT, Zigbee, Scheduler,
dashboard, automation, or heating path was connected.

- Supervisor built and installed aarch64 App version `0.1.3` from canonical
  source after two fail-closed packaging probes identified unused S6 AppArmor
  execution requirements. The final image runs the single journal process
  directly instead of granting execute permission in writable `/run` paths.
- Supervisor reported protection mode and the custom AppArmor profile active,
  with host networking, full access, Docker API, Supervisor API, Home Assistant
  API, and published network mappings all disabled.
- Real private DNS resolved `8c22f541-true-family-journal`; `/healthz` returned
  the expected protocol response without a host port or ingress.
- The App replaced its real Supervisor `true_family` discovery registration and
  reached steady state without logging the discovery credential.
- A temporary external validation process used the real production client with
  only its in-process slug allowlist changed for the repository-hashed test slug.
  It completed signed save, barrier, generation-zero load, App restart, discovery
  rekey, stale-credential rejection, generation-one save, and read-back.
- A Supervisor-managed cold partial backup included only App version `0.1.3`.
  Supervisor restarted the App, discovery was rekeyed, and the client read back
  the identical generation-one root digest.
- Uninstall removed the App and its private data. The test backup, discovery
  registration, temporary Supervisor repository, local Git server, and repository
  files were also removed and their absence was verified.

The temporary repository hash changed the full App slug, so the App-only test did
not relax the then-local integration trust boundary. A later source-only release
gate bound version `0.2.0` to permanent repository prefix `8c9c720e`; that change
was not installed during this test.

## Remaining Supervisor Gate

- Publish and independently verify signed version `0.2.0`, then install and
  verify the already-bound `8c9c720e_true_family_journal` identity.
- Inspect real Supervisor-applied process capability sets and `NoNewPrivs`, and
  verify watchdog recovery explicitly.
- Exercise Supervisor-managed restore and Home Assistant config-entry discovery,
  reload, and recovery in a disposable environment.
- Add amd64 build/runtime evidence if that architecture remains supported.

This evidence remains process-crash-only. It does not certify arbitrary hardware
power loss and cannot authorize live host mutation.
