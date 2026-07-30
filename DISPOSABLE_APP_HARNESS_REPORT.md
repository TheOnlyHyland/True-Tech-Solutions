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

- 572 pytest cases passed in the pinned Home Assistant 2026.7.4 harness.
- 161 pure unittest cases passed.
- 733 total tests passed, plus lock, Python, JSON, YAML, JavaScript, and shell
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

## GitHub Custom-Repository Distribution Evidence

The public True Tech Solutions repository now provides the supported source
distribution path without granting the journal App access to Home Assistant's
configuration directory.

- The integration is installable directly from
  `https://github.com/TheOnlyHyland/True-Tech-Solutions` as a HACS custom
  repository. HACS is only the downloader and update manager; the proprietary
  project is not submitted to the default HACS catalogue.
- `hacs.json`, exact code ownership, support and documentation links, a local
  256-by-256 brand icon, repository description, issues, and Home Assistant/HACS
  topics are present. Both the integration and App require Home Assistant OS
  `2026.7.4` or newer.
- The documented order is integration download, Core restart, exact repository
  addition to the App Store, App start, then config-entry creation. App-first,
  stopped-App, uninstall, and restored-private-data recovery are documented
  without adding a privileged installer or persisting discovery credentials.
- A new generation-one recovery test proves empty App data fails closed with no
  replacement journal, then exact database restoration plus fresh discovery
  returns the same entry to `loaded`. A setup-state listener also prevents
  restored discovery being lost while an older setup attempt is unwinding.
- Manifest-level `single_config_entry` was deliberately rejected because Home
  Assistant applies it before Hass.io discovery and would block rekey/recovery.
  The existing unique-ID singleton remains in force while maintenance discovery
  can still reach `async_step_hassio`.
- Commit `a801ad8d2f9aefab02c421d98057d72038fd8bdd` added the distribution path.
  Commit `7a736954e8a0aef9c3734fc6fab10ec0d231584d` added Home Assistant's standard
  config-entry-only schema after Hassfest identified the missing declaration.
- Final workflow run `30586222948` passed HACS custom-repository validation,
  Hassfest without annotations, 572 Home Assistant tests, and 161 pure tests, 733
  total. The proprietary licence check is intentionally excluded from HACS Action
  because custom-repository installation is restricted to True Tech Solutions
  and customers or testers with written authorization.
- No GitHub release, App image, Home Assistant installation, MQTT connection,
  Zigbee action, Scheduler change, dashboard change, automation change, or
  heating action occurred in this source-only gate.

## Coordinated 0.2.1 Release Evidence

The source-only distribution work was followed by a coordinated integration and
journal App patch release from commit
`83c2826c5e55ae353ec52cfe38431b7bbc8f77f1`.

- Release-branch HACS, Hassfest, and 733-test validation passed in workflow
  `30587501734`; its non-publishing arm64 and amd64 image build passed in
  workflow `30587514391`.
- The same commit passed the main-branch validation in workflow `30587747004`.
  Guarded publication workflow `30587861324` then published signed generic,
  aarch64, and amd64 `0.2.1` images without publishing `latest`.
- The anonymous generic image resolves to manifest digest
  `sha256:3ea34326eca4f218c0587173eecae299a18fe087cf1be0ab97d90ef210991587`.
  Image platforms, labels, source revision, and in-toto provenance all bind to
  the release commit and publication workflow.
- A separately downloaded, checksum-verified Cosign `v3.0.6` verified all three
  image signatures, the exact workflow certificate identity and OIDC issuer,
  and their transparency-log inclusion proofs.
- GitHub Releases now expose `0.2.0` at publication commit `32f9f8482e22eddd934e9d66806fc1ed5a829fb2`
  and latest release `0.2.1` at `83c2826c5e55ae353ec52cfe38431b7bbc8f77f1`.
  Post-publication workflow `30588325757` again passed HACS, Hassfest, and all
  733 tests.

## Disposable HACS 2.0.5 Evidence

A network-enabled, in-process Home Assistant `2026.7.4` harness exercised the
installed HACS `2.0.5` source against the public repository. The disposable
harness added Core's exact `home-assistant-frontend==20260624.6` requirement in
an external overlay and used a current-loop DNS resolver because the ordinary
unit-test fixtures intentionally disable Internet access. Neither adaptation
changed HACS repository or installation logic.

- An administrator HACS WebSocket command registered
  `TheOnlyHyland/True-Tech-Solutions` as an integration custom repository.
- HACS reported `0.2.1` as the available version and downloaded that exact
  release into the disposable `custom_components/true_family` path.
- The installed manifest reported `0.2.1`. A second WebSocket download replaced
  the integration tree atomically; a local sentinel placed between downloads did
  not survive.
- HACS safely rejected an explicit `0.2.0` download before changing the installed
  tree because that historical tag predates `hacs.json`. The installed `0.2.1`
  manifest remained intact.
- The custom repository was uninstalled and unregistered through HACS before
  unload. The temporary test, copied HACS source, integration files, and
  credential environment were removed. No household Home Assistant state was
  used or changed.

This proves first install and replacement through the real HACS release path. It
does not claim a `0.2.0` to `0.2.1` HACS upgrade: repairing or replacing the
already-published historical predecessor would change release history and
requires a separate decision.

## Remaining Supervisor Gate

- Inspect real Supervisor-applied process capability sets and `NoNewPrivs`, and
  verify watchdog recovery explicitly.
- Deliberately issue one stale signed request against the permanent App identity;
  automatic rekey recovery passed, but explicit stale-request rejection was not
  exercised in this live gate.
- Decide whether to preserve the original `0.2.0` release unchanged or publish a
  separately identified HACS-compatible predecessor, then exercise a true
  version-to-version HACS upgrade. `0.2.1` first install and replacement already
  pass.
- Repeat the combined App and integration lifecycle in a disposable environment
  when one becomes available.
- Add amd64 runtime evidence if that architecture remains supported; the amd64
  build, provenance, labels, and signature already pass.

This evidence remains process-crash-only. It does not certify arbitrary hardware
power loss and cannot authorize live host mutation.
