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

- 571 pytest cases passed in the pinned Home Assistant 2026.7.4 harness.
- 161 pure unittest cases passed.
- 732 total tests passed, plus lock, Python, JSON, YAML, JavaScript, and shell
  checks.

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

## Permanent Release App-Only Evidence

After public release, the user chose a tightly scoped App-only test on the
backed-up household Supervisor because no disposable HAOS instance was available.
The integration remained absent, and no MQTT, Zigbee, Scheduler, dashboard,
automation, or heating path was connected.

- Supervisor derived repository prefix `8c9c720e`, installed exact App slug
  `8c9c720e_true_family_journal`, and pulled public version `0.2.0` without a
  local build.
- Supervisor reported protection mode and the custom AppArmor profile active.
  Host networking, host PID, full access, devices, privileged capabilities,
  Docker API, Supervisor API, Home Assistant API, ingress, and published network
  mappings were all absent.
- Private hostname `8c9c720e-true-family-journal` resolved internally and
  `/healthz` returned the exact `true-family-journal-v1` response.
- Initial startup, explicit restart, cold backup restart, and partial restore
  restart each replaced discovery and returned to healthy steady state without
  logging the discovery credential.
- Cold partial backup `f418fd7f` contained only App version `0.2.0` and repository
  metadata. Authoritative Supervisor backup job
  `8409fea9f3f04f3c8d7d310e2fbe8fde` and restore job
  `1c76471d0a6a4168a37af1d75507cb00` both completed at 100 percent with empty
  error lists. The restored App retained its exact protected runtime metadata and
  health response.
- The App-only boundary prevented the external client from reading the
  Core-restricted discovery secret, so no signed journal payload or stale-key
  rejection was claimed for this release test. The backup therefore proved the
  Supervisor cold lifecycle, not provisioned journal-content preservation.
- Home Assistant Core logged `Integration 'true_family' not found` whenever App
  discovery fired because the integration was deliberately not installed. This
  is expected for the isolated test but is a real installation-order behavior.
- Supervisor installed the watchdog URL disabled. No watchdog-induced crash was
  attempted, and protected OpenCode access could not inspect actual process
  capability sets or `NoNewPrivs`.
- Uninstall removed the App and private data. The test backup and permanent
  repository entry were deleted, private health became unreachable, and the App,
  repository, backup, and `true_family` integration were all verified absent.

## Permanent Release Controlled Integration Evidence

The user then approved a controlled integration gate on the same backed-up
household Supervisor. The component was installed before the App, and the config
entry used isolated MQTT root `true_family_gate`; it never subscribed or
published under the household `zigbee2mqtt` root.

- The first real REST config flow exposed an HTTP 500 caused by placing custom
  `valid_base_topic` validation directly in the frontend-serialized Voluptuous
  schema. No entry or journal existed at failure time.
- The minimal fix uses serializable string fields, validates and normalizes after
  submission, and returns a translated field error. A regression test exercises
  Home Assistant's real serializer and wildcard rejection. The corrected project
  passes 568 Home Assistant tests plus 160 pure tests, 728 total.
- Corrected setup created one loaded config entry, exactly seven unbound revision
  zero climates, and no bootstrap or migration plan. Sanitized admin status
  reported no executor, no recovery token, and no writable provider path.
- Zigbee permit join remained off, Heating Mode remained Off, and no pairing,
  bootstrap, migration, Scheduler, dashboard, automation, or heating action was
  invoked.
- Explicit App restart and every cold-backup restart replaced discovery while the
  integration returned to `loaded`, proving automatic permanent-identity rekey
  and journal reopen behavior without persisting the discovery key.
- Pre-restore backup `ae3b2705` and post-restore backup `31444538` each contained
  one schema-v4 generation-zero journal, one durable provisioning receipt, and a
  SQLite database with `quick_check` equal to `ok`. In both copies, the stored
  revision matched canonical root digest
  `3538a8d3e1111a09cbb360078f8cd9c71e04c6b1d640684ffc14eeaf59cf8d79`.
- Supervisor backup job `1231f362fcce4b3a93afaa6363a809dc`, restore job
  `ae934438a0424a25a0aad0c84817ca0a`, and post-restore backup job
  `4002d6dc47cb4f7e82516eacbe30d256` all completed at 100 percent with empty error
  lists. Restore reinstalled the deliberately uninstalled App, restored private
  data, restarted it protected, and returned the entry to `loaded`.
- Restore emitted one harmless frontend warning while removing the prior unknown
  non-ingress App panel. No True Family setup, reload, journal, MQTT, or cleanup
  error occurred.
- Cleanup removed the config entry and seven climates before stopping the App,
  then removed App/private data, both backups, repository, live component, and
  downloaded backup material. Final Core restart reported the integration
  unloaded; climate count returned from 20 to 13, MQTT radiator states rehydrated,
  bridge connectivity returned on, permit join remained off, and Heating Mode
  remained Off.

## Remaining Supervisor Gate

- Inspect real Supervisor-applied process capability sets and `NoNewPrivs`, and
  verify watchdog recovery explicitly.
- Deliberately issue one stale signed request against the permanent App identity;
  automatic rekey recovery passed, but explicit stale-request rejection was not
  exercised in this live gate.
- Define and verify the supported integration distribution and install order so
  App discovery never precedes component availability.
- Repeat the combined App and integration lifecycle in a disposable environment
  when one becomes available.
- Add amd64 build/runtime evidence if that architecture remains supported.

This evidence remains process-crash-only. It does not certify arbitrary hardware
power loss and cannot authorize live host mutation.
