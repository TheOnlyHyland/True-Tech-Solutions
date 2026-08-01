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
- `custom_components/true_family/physical_probe.py`: stdlib-only, unwired generic
  protocol-v2 physical-probe contracts and the three pinned converter-resolved
  BRT identity aliases.
- `custom_components/true_family/probe/true_family_brt_probe.mjs`: source-only
  Zigbee2MQTT 2.12.1 external extension with bounded serialization, durable
  recovery, and no deployment lifecycle.
- `tests/fixtures/physical_probe_vectors.json`: shared Python/Node UTF-8
  canonicalization, digest, request, record, result, and frame vectors.
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

True Family `0.2.1` is an experimental Home Assistant `2026.7.4` integration and
companion App. It creates seven unbound logical climates but does not migrate an
existing heating system. Do not bind production radiators until the remaining
physical-valve gates are complete.

The integration is distributed from this True Tech Solutions GitHub repository
as a HACS **custom repository**. HACS acts only as the downloader and update
manager; this project is not submitted to the default HACS catalogue. Version
`0.2.1` is the first HACS-supported release. Earlier tags predate the required
HACS metadata and are not valid HACS installation targets.

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
harness and requires exact Node.js `20.19.2`. Set
`TRUE_FAMILY_HA_HARNESS_ROOT` when the harness is elsewhere. The current gate
passes 610 Home Assistant runtime tests, 252 pure Python protocol, persistence,
release, and static contract tests, and 130 zero-dependency Node tests, for 992
total.

The physical-probe source is offline and unwired: integration setup does not
import or register it, and this project contains no automatic external-extension
deployment, save, or removal path. Protocol v2 accepts only BRT DP2
`commandDataResponse` frames as physical and direct-command proof, treats DP2
`commandDataReport` as competing traffic, and ignores unrelated companion
DP5 and DP14 `commandDataResponse` frames. Generated command sequences are
limited to `0..65534`; observed physical frames may use `65535`. Physical proofs
have a 60-second deadline, direct proofs have a 10-second deadline, and restore
stops after three durable attempts. One core FIFO serializes startup, MQTT,
device frames, timers, and stop handling. Candidate resolution is bounded to four
seconds and request authority is rechecked after it returns. Every no-op and
challenge dispatch is bound to the exact durable operation, generation, phase,
expected proof, candidate topic, and authorization epoch; stale resolver
completions cannot invoke an old command. Non-safety invocation must begin
strictly before a captured deadline that leaves the complete pinned five-second
Endpoint timeout before both proof and operation deadlines. The default adapter
rechecks that deadline after its own synchronous candidate inspection. A claimed
restore remains bound to the original operation deadline and can be created or
reused only when its complete ten-second direct-proof window fits. Post-deadline
safety restoration ignores command-capable deadlines only through bounded
unclaimed intended-target dispatch; it can never create proof, a result, or
cleanup authority. Queue overflow synchronously and irreversibly
latches remediation before queued work can run; its handler uses only bounded
unclaimed intended-target defense and never starts a claimed restore. Scheduler
failure, journal uncertainty, restart recovery, result drift, acknowledgement
identity drift, and shutdown retain that safety path while blocking new unsafe
work. Definite sequence, transition, validation, or journal-write failures inside
frame and drift processing synchronously latch safety-only operation before the
adapter may suppress an error; challenged work receives an unclaimed restore and
all such failures install durable or in-memory no-result remediation.
Restore-to-remediation intent is durable across restart. Pending results
have a durable two-second settling window: only immediate duplicate final-restore
responses are ignored, and cleanup remains blocked until a later valid
acknowledgement in the same boot. Any validation failure from candidate-,
endpoint-, cluster-, and DP2-relevant traffic supersedes a pending result, issues
intended-target safety restoration, and makes later acknowledgement impossible;
unrelated non-DP and noncandidate traffic remains ignored. Neither claimed
restore, restart recovery, nor terminalization can extend the original operation
deadline. A claimed restore
lacking a full proof window is replaced by unclaimed restoration and remediation.
The complete result settling window must also end strictly before the original
deadline, both before and after the terminal journal write. Otherwise the probe
enters no-result, no-cleanup remediation. Every pending result or quiescent record loaded
from an earlier boot is invalidated into restore-only remediation and cannot be
republished, acknowledged, or trusted for cleanup. Because safety restore
precedes remediation persistence, this startup rule also fails closed after
process death in that interval. An unexpired previous-boot physical or no-op phase
remains inactive until an explicit resume rebinds it. If it expires first, it
enters no-result remediation with no restore requirement and cannot advertise a
result under the old boot. In the current boot, timer or acknowledgement
processing at or beyond the operation deadline supersedes the result and enters
restore-required remediation instead of republishing or granting cleanup. After
a same-boot acknowledgement, the external orchestrator must complete cleanup and
remove both the journal and extension through the attested out-of-band lifecycle
before any restart; persisted quiescence is deliberately not restart authority.

Every final DP2 write uses `sendPolicy: "immediate"`,
`disableRecovery: true`, `disableDefaultResponse: true`, and a pinned five-second
Endpoint timeout. Before every request resolution, command, and acknowledgement,
the selected endpoint and every available endpoint on the candidate device must
expose `hasPendingRequests()` and report an empty queue. This is read-only: the
probe never clears or mutates herdsman queues. Immediate send, disabled recovery,
and empty queues are necessary but do not prove final adapter/radio ordering;
that still requires the pinned runtime harness and actual-spare physical proof.

The writer monitor deliberately covers the exact candidate friendly-name and IEEE
publish subtrees more broadly than Zigbee2MQTT's documented aliases. It recognizes
direct `/set...` writes and endpoint-shaped paths followed by `/set...`, including
space, tab, vertical-tab, form-feed, CR/LF, zero-padded, hexadecimal, scientific,
and long numeric endpoint spellings accepted through JavaScript `Number()`
coercion, plus attribute subpaths. It rejects only MQTT-invalid NUL/wildcards,
malformed Unicode, size violations, and non-candidate roots; conservative false
positives beneath the exact candidate roots are intentional. The broker ACL must
deny each entire friendly-name and IEEE candidate publish subtree rather than
enumerate expected aliases. The event can
arrive after the built-in Publish extension has already invoked a converter, so
this remains restore-triggering defense rather than prevention. Any slash-delimited
MQTT topic containing `bridge/request/`, except the two exact probe request topics, is also
reactive drift. Pinned entity-rename and group-membership callbacks detect changes
to the candidate identity or endpoint. These callbacks can run after the built-in
action and do not claim to prevent it. Candidate name and group membership must
therefore remain frozen by preflight. Before either physical proof is accepted,
the candidate is boundedly re-resolved and its immutable identity, set topic, and
empty endpoint queues are checked again; this still does not establish transport
origin.

Claimed restore is limited to three distinct durable sequences and attempts. A
persisted claimed attempt may be retransmitted after restart. Separately, each
distinct safety event or restart may issue up to three unclaimed, fresh-sequence,
intended-target-only endpoint invocations; there is no global maximum of three
physical transmissions.
The durable used-sequence bound is 16. Initial and resumed no-op allocation must
leave one challenge, all three claimed restores, and all three unclaimed safety
attempts available. Challenge allocation must leave all six restore slots, each
claimed restore must leave every remaining claimed slot plus three unclaimed
slots, and result, quiescent, and remediation records must retain three slots.
Both validators reject records that violate the reserve for their phase. A no-op
resume that would cross its reserve is rejected before persistence or dispatch,
leaving the existing operation and its timeout safety path unchanged.
Unclaimed remediation restores track per-key in-flight versus completed
invocation. Completion means only that `endpoint.command` was invoked; it never
claims a proof, delivery, restore success, or cleanup authority.

Journal, publication, dispatch, and graceful-stop waits are bounded.
Reconciliation never calls `load()` while a journal write is still pending
because that could delete the live pre-rename temporary file. It instead keeps
the current record as observed authority, latches safety-only operation, and
authorizes any unclaimed defense against the current operation, generation, and
epoch while using the intended record only for target and sequence exclusion. A
settled may-have-committed error may perform bounded read-back.

Atomic startup load validates the main journal and every bounded matching temp
before deleting anything. It compares immutable operation, profile, candidate,
deadline, and target identity before considering generation because generation
restarts for each operation. Every valid surviving temp, including an exact
canonical duplicate of the main journal, is interruption evidence. Coherent temp
evidence of any generation is converted with all coherent records into atomically
durable `journal_uncertain` remediation, including main replacement and directory
fsync, before any temp is unlinked. The highest-generation evidence supplies the
remediation state, while all credible evidence contributes restore risk.
Conflicting identity preserves every file, leaves no operational authority, and
requires manual remediation. A failed recovery write preserves every original
temp and gives startup only in-memory safety authority. Pre-unlink fsync, unlink,
and post-unlink fsync failures are reported with the safe recovery record; at
that point main is already durable remediation, so cleanup failure cannot revive
stale active authority. Recovery can issue an intended-target restore when
credible evidence may have reached challenge, restore, or restored terminal
state, but it never returns active result or cleanup authority and never creates
a challenge. Startup remains no-ready and cannot resume the stale active record
on a later restart.

The adapter passes
relative publication topics to Zigbee2MQTT, which adds the configured
base-topic prefix; effective publications use QoS 1 and `retain: false`. READY is
only a discovery hint. Request acceptance and the latest status generation plus
result ID are authoritative. Zigbee2MQTT `Mqtt.publish` may swallow broker
delivery failures, so periodic status/result attempts and request retries can
mitigate loss but do not prove broker delivery.

Identity is fingerprint-specific and immutable: `_TZE200_b6wax7g0` and
`_TZE200_6y7kyjga` require model `BRT-100-TRV` and vendor `Moes`, while
`_TZE200_qsoecqlk` requires model `Powerswitch-ZK(W)` and vendor `Sibling`.
Cross-combinations fail closed.

Python and JavaScript text validation share one explicit boundary-whitespace set:
Unicode White_Space plus U+FEFF. Boundary U+0085 and U+FEFF are rejected in both
runtimes rather than inheriting the different behavior of `strip()` and `trim()`.
Both reject ill-formed Unicode, including lone UTF-16 surrogates, and both treat an
observed proof at its exact proof deadline as expired.

Exact runtime/build verification, extension lifecycle and collision handling,
and the residual writer fence remain a separate future preflight. That fence
must give Zigbee2MQTT a dedicated broker principal. The external orchestrator's
MQTT PUBLISH ACL must be deny-by-default and allow only the two exact, fully
base-prefixed probe request and acknowledgement topics. Every other principal
must be denied all friendly-name, IEEE, endpoint, attribute, and group write
aliases for the candidate and every bridge control request.

The deny rules must use containment semantics compatible with Zigbee2MQTT 2.12.1's
unanchored bridge request regex, including repeated-prefix aliases. They must
explicitly block raw `bridge/request/action`, device rename, group membership,
backup, restart, extension mutation, and converter mutation requests, including
their save/remove forms. The orchestrator's SUBSCRIBE ACL must also be
deny-by-default and allow only the exact probe ready, status, result, and response
topics it needs. It must deny `bridge/response/backup` and broad bridge or source
surfaces. Backup, journal, or source access belongs only to a separately attested
administrator/recovery principal if ever required. Retained `bridge/extensions`
source must remain denied to the orchestrator and be handled only by that privacy
policy and exact source-attestation path.

The preflight must freeze the candidate friendly name and endpoint group
membership; disable the Zigbee2MQTT frontend and every relevant automation,
script, and Scheduler writer; attest and allowlist exactly one copy of this
external extension; exclude every unreviewed in-process endpoint writer; and keep
payload-debug logging disabled for the complete proof.

No second instance or reload may start while one loader owns the journal.
Cross-instance late journal completion remains blocked on that future
single-loader lifecycle/collision preflight; this source deliberately does not
invent a process-local lock. Zigbee2MQTT publishes external-extension source on
`bridge/extensions`, so broker privacy and source attestation must cover that
retained surface. Full IEEE identity is durable recovery data but remains masked
from public probe messages. Raw DP2 and write-alias monitoring is only defense in
depth because it cannot enforce broker ACLs, prevent the built-in Publish action,
or inspect retain metadata. Physical provenance is operational isolation, not a
transport-origin bit. Exact direct-command sequence echo and final adapter/radio
ordering across all three fingerprints still require the pinned harness and an
actual-spare no-op bench gate. These offline tests do not establish bench
readiness.

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
