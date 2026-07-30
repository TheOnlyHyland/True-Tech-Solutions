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
- `LICENSE`: proprietary True Tech Solutions source terms.
- `tests/`: pure and disposable Home Assistant runtime tests.
- `scripts/verify`: complete offline verification gate.

## Run Tests

From this directory:

```bash
scripts/verify
```

The verification script uses the pinned disposable Home Assistant 2026.7.4
harness. Set `TRUE_FAMILY_HA_HARNESS_ROOT` when the harness is elsewhere. The
current gate passes 567 Home Assistant runtime tests and 160 pure, protocol,
persistence, release, and static contract tests, for 727 total.

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

This source-only release package is prepared locally but not yet published. The
public GitHub repository remains empty, no GHCR image or signature exists, and no
release workflow has run. The first publication must preserve the exact
repository URL above, make the resulting GHCR package public, run the workflow
once without publishing, and then publish immutable version `0.2.0`.

The remote journal is the only production default; the earlier raw-file backend
is retained as isolated reference/test code and is never a fallback. SQLite's
signed capability is explicitly process-crash-only. It can persist and reload
schema-v4 journal state but cannot authorize a bridge transaction, migration
application, or any live host mutation. Three final reviewers returned GO for
this exact offline boundary.
