# True Family TRV Replacement Prototype

Permanent public release destination:

`https://github.com/TheOnlyHyland/True-Tech-Solutions`

Current durable workspace:

`/homeassistant/projects/true-family-trv-replacement/`

This directory contains the isolated development project for a guided radiator
valve replacement workflow.

The phase-one backend creates command intentions as plain data but never
publishes them, and the frontend runs entirely in demo mode. Phase two adds
installable custom-integration source, a pinned Home Assistant harness, strict
bootstrap/reference-migration logic, durable journal wiring, fail-closed
provider readiness, sanitized admin APIs, and an integrated project-only
companion App journal. The source remains outside the live Home Assistant
installation and cannot affect the live home unless deliberately installed and
configured.

## Layout

- `backend/models.py`: room, device, command, and session data models.
- `backend/z2m_protocol.py`: strict Zigbee2MQTT event parsing and command-intent
  builders.
- `backend/replacement.py`: guarded in-memory replacement state machine.
- `frontend/index.html`: standalone prototype entry point.
- `frontend/replacement-wizard.js`: browser-only customer workflow.
- `custom_components/true_family/`: installable phase-two integration source that
  remains outside the live Home Assistant installation.
- `custom_components/true_family/reference_projection.py`: strict semantic
  entity-reference projection for scalar fields and allowlisted Jinja helpers.
- `custom_components/true_family/reference_journal_remote.py`: signed client for
  the private companion-App journal protocol.
- `true_family_journal/`: repository-root non-privileged Home Assistant App source
  with bounded HTTP, SQLite CAS, cold backup, and process-crash recovery.
- `release/identity.json`: frozen repository, Supervisor slug, hostname, GHCR,
  and Cosign identity contract.
- `.github/workflows/release-app.yaml`: manually triggered immutable-version,
  multi-architecture, keyless-signed image release.
- `.github/workflows/validate-integration.yaml`: HACS custom-repository,
  Hassfest, and locked integration validation.
- `LICENSE`: proprietary True Tech Solutions source terms.
- `tests/`: pure and disposable Home Assistant runtime tests.
- `scripts/verify`: complete offline verification gate.

## Supported Installation

True Family `0.2.0` is an experimental Home Assistant `2026.7.4` integration and
companion App. It creates seven unbound logical climates but does not migrate an
existing heating system. Do not bind production radiators until the remaining
physical-valve gates are complete.

The integration is distributed from this True Tech Solutions GitHub repository
as a HACS **custom repository**. HACS acts only as the downloader and update
manager; this project is not submitted to the default HACS catalogue.

Requirements:

- Home Assistant OS with Home Assistant `2026.7.4` or newer.
- MQTT configured in Home Assistant.
- HACS installed.
- A current full Home Assistant backup.

[![Open your Home Assistant instance and add this repository to HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=TheOnlyHyland&repository=True-Tech-Solutions&category=integration)

Use this integration-first order:

1. In HACS, add
   `https://github.com/TheOnlyHyland/True-Tech-Solutions` as a custom
   **Integration** repository and download **True Family**.
2. Restart Home Assistant Core so the integration is available before App
   discovery begins.
3. In **Settings > Apps > App Store > Repositories**, add the exact same URL.
   Do not add `.git`, a trailing slash, a branch, query, or fragment because
   Supervisor derives a different untrusted identity from every alias.
4. Install and start **True Family Journal**. Keep protection mode enabled.
5. In **Settings > Devices & services**, add **True Family** and enter the exact
   Zigbee2MQTT base topic. The default is `zigbee2mqtt`.

If the App was installed first, install the integration through HACS, restart
Core, then restart the App once so Supervisor sends fresh discovery. If setup is
retrying because the App is stopped, start or restart the App; the entry reloads
from fresh in-memory discovery without storing its HMAC key.

The journal lives only in the App's private `/data`. Create a partial backup that
includes **True Family Journal** before an App reinstall. Uninstalling the App
deletes that private data. Restore the App backup rather than deleting or
recreating the True Family config entry: missing journal data fails closed, and
fresh discovery reloads the existing entry only after its exact journal returns.

## Licensing

This repository remains proprietary to True Tech Solutions. Public GitHub
availability and HACS custom-repository support do not grant permission to copy,
deploy, modify, or redistribute it. The installation instructions are for True
Tech Solutions and customers or testers with prior written authorization.

## Run Tests

From this directory:

```bash
scripts/verify
```

The verification script uses the pinned disposable Home Assistant 2026.7.4
harness. Set `TRUE_FAMILY_HA_HARNESS_ROOT` when the harness is elsewhere. The
current gate passes 571 Home Assistant runtime tests and 161 pure, protocol,
persistence, release, and static contract tests, for 732 total.

## Preview Frontend

Serve only the prototype directory with a local static server:

```bash
python3 -m http.server 8123 -d frontend
```

Then open `http://localhost:8123/`. Every action is simulated in the browser.
Individual states can be opened directly for visual review, for example
`http://localhost:8123/?stage=prepare` or
`http://localhost:8123/?stage=complete`.

## Safety Boundary

The phase-one backend and browser demo do not:

- Import Home Assistant.
- Connect to an MQTT broker.
- Open Zigbee joining.
- Rename or remove devices.
- Register climate entities.
- Modify schedules or dashboards.
- Control heating.

The phase-two source contains Home Assistant, MQTT, climate, and WebSocket
adapters that would become active only after a deliberate installation and
config-entry setup. It is not installed, imported, registered, or connected to
the live home. No concrete five-provider write bridge or migration executor is
installed by default, so reference migration remains unavailable even in the
development integration until those explicit host capabilities are supplied.

Reference migration is deliberately conservative. Complete entity IDs are
matched semantically, so a physical entity such as `climate.kitchen_radiator`
is distinct from `climate.kitchen_radiator_with_term`. Only five literal Jinja
helper calls can be rewritten. Dynamic lookups, aliases, computed entity IDs,
unknown functions, non-allowlisted filters, ambiguous scalar fields, mapping
keys, and unsupported provider/template combinations block the plan before any
write.

The offline transaction recorder uses deterministic journal-before-dispatch
identities, exact dispatch authorization, durable host-ledger receipts,
authoritative no-effect tombstones, fresh read-back verification, provider epoch
high-water marks, and verified compensation before retry. Schema-v4 Store data
binds each changed plan to its exact provider manifest, execution scope, bridge
identities, recorder, journal, originals, expected writes, and terminal outcome.

The integrated vertical slice uses strict Supervisor discovery, exact App
identity, HMAC-signed requests and responses, generation/revision CAS, bounded
receipt replay, cold backups, restart rekey, and a real SQLite WAL database. The
actual App server and actual Home Assistant client pass provisioning, mutation,
barrier, read-back, SIGKILL recovery, restart, and stale-client tests together.

A temporary App-only real-Supervisor test also passed on aarch64 with version
`0.1.3`: protection mode and the custom AppArmor profile remained active, private
DNS and discovery worked, the signed client survived restart/rekey, a stale
credential was rejected, and a Supervisor cold backup preserved the exact
generation-one journal. The App, test backup, discovery record, repository, and
Git server were removed afterward. The integration was not installed. Restore,
integration reload, watchdog, and real process-capability inspection remain
future gates.

The permanent public repository is
`https://github.com/TheOnlyHyland/True-Tech-Solutions`. Home Assistant derives
repository prefix `8c9c720e`, full App slug
`8c9c720e_true_family_journal`, and private hostname
`8c9c720e-true-family-journal`. The integration now rejects the former local and
temporary identities. Release version `0.2.0` targets the generic image
`ghcr.io/theonlyhyland/true-family-journal`; the guarded workflow publishes no
mutable `latest` tag, rejects an existing version tag, and uses GitHub OIDC
keyless Cosign for every architecture and the final manifest. Supervisor does
not currently enforce Cosign signatures, so external verification remains part
of the release gate.

Release `0.2.0` is public and linked to the source repository. Its immutable
multi-architecture manifest is
`sha256:6e97c25c54d08e0bdde35978444553d657622666758e51f5d67781be0ce59f1a`
and contains the expected arm64 and amd64 images plus in-toto provenance. The
guarded workflow passed in non-publishing mode before publication, then signed
and verified the published manifest. A separate checksum-verified Cosign `v3.0.6`
run reproduced the exact workflow-identity, certificate-authority, claims, and
transparency-log verification.

The permanent `0.2.0` release also passed a tightly scoped App-only test on a
real aarch64 household Supervisor after the user chose that backed-up environment
because no disposable HAOS target was available. Supervisor derived exact slug
`8c9c720e_true_family_journal`, pulled the public image, and ran it protected
under its custom AppArmor profile with every privileged API and host surface
disabled. Private DNS, health, restart, discovery replacement, cold partial
backup, and partial restore passed. The integration remained absent, so the
signed journal protocol and config-entry reload could not be exercised; Core
logged the expected missing-integration error when discovery fired. Watchdog
crash recovery, actual process capabilities, and `NoNewPrivs` remain open. The
App, private data, test backup, and repository were removed, and the release is
not currently installed.

A later controlled integration gate installed the component before the App and
used isolated MQTT root `true_family_gate`. The first real REST flow exposed a
Home Assistant `2026.7.4` form-serialization defect; the source now keeps custom
topic validation outside the serializable form schema and has a regression test
for both serialization and wildcard rejection. The complete gate passes 568 Home
Assistant tests and 160 pure tests, 728 total. Live setup created exactly seven
unbound, unavailable logical climates and a signed schema-v4 generation-zero
journal without opening Zigbee joining or changing heating. App restart, cold
backup, full App uninstall, Supervisor restore, automatic config-entry reload,
and post-restore backup all retained exact journal digest
`3538a8d3e1111a09cbb360078f8cd9c71e04c6b1d640684ffc14eeaf59cf8d79`
and its durable provisioning receipt. The entry, climates, App, private data,
backups, repository, component, and temporary downloads were removed afterward;
Core, MQTT, Zigbee, climate count, and heating returned to their original
baseline.

The remote journal is the only production default; the earlier raw-file backend
is retained as isolated reference/test code and is never a fallback. SQLite's
signed capability is explicitly process-crash-only. It can persist and reload
schema-v4 journal state but cannot authorize a bridge transaction, migration
application, or any live host mutation. Three final reviewers returned GO for
this exact offline boundary.
