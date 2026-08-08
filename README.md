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
companion App journal. Release `0.2.1` of the integration and App remains
installed on the household Home Assistant system in a deliberately inactive
state: its seven climates are unbound and unavailable, and bootstrap and
migration are incomplete. The physical-probe and preflight source described
below is unreleased, unwired, and absent from that installed release.

## Layout

- `backend/models.py`: room, device, command, and session data models.
- `backend/z2m_protocol.py`: strict Zigbee2MQTT event parsing and command-intent
  builders.
- `backend/replacement.py`: guarded in-memory replacement state machine.
- `frontend/index.html`: standalone prototype entry point.
- `frontend/replacement-wizard.js`: browser-only customer workflow.
- `custom_components/true_family/`: phase-two integration source; released
  `0.2.1` remains installed but inactive, while later physical-probe work here is
  unreleased and unwired.
- `custom_components/true_family/physical_probe.py`: stdlib-only, unwired generic
  protocol-v2 physical-probe contracts and the three pinned converter-resolved
  BRT identity aliases.
- `custom_components/true_family/physical_probe_preflight.py`: pure, non-I/O
  raw deployment/pre-arm validation reports and digest-only ARM permit candidates.
- `custom_components/true_family/probe/true_family_brt_probe.mjs`: source-only
  Zigbee2MQTT 2.12.1 external extension with bounded serialization, durable
  recovery, and no deployment lifecycle.
- `custom_components/true_family/probe/true_family_brt_probe.manifest.json`:
  immutable artifact, protocol, runtime, upstream-reference, topic, and
  fresh-deployment identity.
- `tests/fixtures/physical_probe_vectors.json`: shared Python/Node UTF-8
  canonicalization, digest, request, record, result, and frame vectors.
- `tests/fixtures/physical_probe_preflight_vectors.json`: byte-preserved PASS B0
  v1 deployment, pre-arm, request, report, and permit-candidate vectors.
- `tests/fixtures/physical_probe_pass_b_manifest.json`: exact non-authoritative
  PASS B0 container, package, verifier, limit, and claim contract.
- `tests/js/test_physical_probe_z2m_runtime.mjs`: brokerless real-loader smoke
  cases for the disposable runtime container.
- `tests/js/verify_physical_probe_z2m_runtime.mjs`: strict tar, binding, Docker
  inspect, sanitizer, and canonical evidence verifier.
- `scripts/pass-b-z2m-runtime`: Docker-only two-pass CI orchestrator; normal
  execution deliberately fails when Docker or the amd64 CI runner is absent.
- `.github/workflows/pass-b0-runtime.yaml`: main-branch-only non-authoritative
  PASS B0 smoke workflow.
- `tests/fixtures/physical_probe_pass_b1_manifest.json`: exact PASS B1A
  Mosquitto, packet-gateway, ACL-plan-v2 topic oracle, composite-policy,
  principal, matrix, topology, evidence, and claim-limit contract.
- `tests/js/test_physical_probe_broker_runtime.mjs`: zero-dependency raw MQTT v5
  client and packet-aware enforcement gateway, Dynamic Security installer and
  read-back client, and live composite-policy matrix harness.
- `tests/js/verify_physical_probe_broker_runtime.mjs`: strict PASS B1A manifest,
  preflight-policy, Docker inspect, read-back, redaction, cleanup, and canonical
  evidence verifier.
- `scripts/pass-b1-broker`: two-replica disposable Mosquitto plus gateway
  launcher with separated private credentials and fixed sanitized output.
- `.github/workflows/pass-b1-broker.yaml`: main-branch-only, fixed-runner,
  non-authoritative PASS B1A composite MQTT policy workflow.
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
passes 610 Home Assistant runtime tests, 301 pure Python protocol, persistence,
deployment-preflight, release, and static contract tests, and 157 zero-dependency
Node tests, for 1,068 total. The Docker-free PASS B1A shell and verifier
self-checks are additional static gates and are not included in that test count.

### PASS B0 CI-Only Runtime Smoke

PASS B0 is implemented as a same-repository, reviewed-source, non-authoritative
GitHub Actions smoke gate in `.github/workflows/pass-b0-runtime.yaml`. It is not
malicious-source-resistant, independently attested, branch-protection evidence,
or an authorization input. The first successful `ubuntu-24.04` result completed
on 2026-08-02 at commit
`8e367973fb3875a86a2287945ab59ccd7a4b22ee` in GitHub Actions run
`30769426275`. That run completed both fresh internal replicas, required
byte-identical normalized verifier output, validated final evidence, verified
zero labeled containers and networks, and deleted its private run root before
emitting pass evidence. No evidence artifact was uploaded or retained by the
repository.

The gate pins the Linux amd64 child image to
`docker.io/library/node:20.19.2-bookworm-slim@sha256:ae5e29a169a6dbe7f45d552d73674001cc00913a0a8a5967c57a34f92e940ec8`.
The multi-platform index digest
`sha256:7cd3fbc830c75c92256fe1122002add9a1c025831af8770cd0bf8e45688ef661`
is recorded only as a reference and is not the pulled child identity. The gate
performs two fresh acquisition, offline-install, and runtime passes, then requires
byte-identical normalized verifier output. This is not runtime-byte
reproducibility: raw journals, boot IDs, command sequences, and other private
runtime bytes may differ. The expected 148-package closure digest is
`de77c8dea2c3a531c3af9331147426d708ad83435072aa4aec228cdcf10c9e52`, and the
published Zigbee2MQTT `dist` digest is
`b69100d9ec7992eb47ee756d4cbaf540996e30e12b24b8dbb348c05356c72ff2`.
These are content checks, not provenance or signature claims. The exact Git
commit and tree establish content identity only; the gate does not verify a Git
signature or independent build provenance.

Four disposable package-fetch containers run only the checked-in verifier with
Node's built-in HTTPS client. Each receives the verifier and manifest as
read-only inputs plus one writable `/out` bind, with no source workspace, HOME,
package-manager invocation, package-manager configuration, proxy configuration,
or inherited host environment. The manifest pins each exact HTTPS URL, filename,
SHA-512 SRI, compressed size, and response ceiling. The downloader requires a
direct GET to `registry.npmjs.org` on default port 443, rejects redirects and
unexpected status or length, writes exclusively at mode `0600`, hashes while
streaming, fsyncs the verified file, and removes any partial output on failure.
It emits only fixed sanitized pass or failure records.

The downloaded and strictly validated pnpm program executes later in its
constrained fetch stage. That stage has network access and receives only the
exact upstream package, lock, workspace, and optional project `.npmrc` inputs.
Fetch and offline install retain their existing commands and exit statuses but
receive the launcher-pinned literal `CI=true`, rather than a value inherited
from the host, so pnpm remains noninteractive without a TTY. Both use pnpm's
machine `ndjson` reporter redirected to private tmpfs files. On a nonzero exit,
the verifier reads only regular, non-symlinked files bounded to
1 MiB each and first inspects canonical root `code` or nested `err.code` values.
Any single identifier matching exactly `ERR_PNPM_[A-Z0-9_]{1,40}` is emitted as
a lowercase phase suffix. Structurally invalid NDJSON receives one bounded raw
scan using ASCII token boundaries; one unique identifier is emitted, multiple
identifiers become `multiple_codes`, and no identifier becomes only
`diagnostic_empty`, `diagnostic_oversize`, `diagnostic_non_ndjson`, or
`diagnostic_no_code`. Raw messages, paths, package names, URLs, hashes, counts,
and timing are never emitted.
The common `/tmp` tmpfs is exactly 256 MiB with
`rw,noexec,nosuid,nodev,mode=1777`; producer containers use the captured host
UID/GID and the runtime uses `65532:65532`. This bounded ceiling accommodates
the measured 88 MiB temporary pnpm virtual store while the memory cgroup remains
exactly 768 MiB.
Every package fetch, dependency fetch, install, extraction, and verifier container
that writes a host bind output runs under the runner's captured numeric UID/GID,
which must both be nonzero. No `nproc` limit is applied to these producers because
Linux accounts it across every process using the shared runner UID; producer
process and thread containment is instead enforced by Docker's exact 64-process
pids cgroup. The UID-65532 runtime retains exact `nproc=64:64` and `pids=64`
limits. Installation
copies the sealed upstream inputs into a mode-`0700` writable `/work` tree,
recursively normalizes regular files to mode `0600`, verifies the copied package
is writable, and verifies the read-only source snapshot did not change. A
separate install uses a copied store with Docker networking disabled, lifecycle
scripts disabled, and the exact frozen lock. Package URLs and dependency fetches
target `registry.npmjs.org` and GitHub, but
Docker's default egress is used: `fetch_host_allowlist_enforced` is deliberately
`false`. This smoke gate does not prove host-level destination filtering. The
lock's `packages` section requires every resolution to be one exact inline
SHA-512 integrity mapping. Structural resolution fields and external protocols
are rejected without scanning package names such as `file-uri-to-path` for raw
substrings. The separately downloaded zigbee-herdsman and
zigbee-herdsman-converters tarballs
provide only independent direct-pin SRI evidence; the installed production
closure comes from the exact lock file in the pinned Git tree.

The runtime container remains the distinct numeric UID/GID `65532:65532`. It is
networkless, read-only, non-root, capability-free, resource-bounded, and receives
only read-only input mounts plus private tmpfs data and temporary directories.
Immutable mount directories are mode `0555` and their files are mode `0444`,
except the read-only runner which is mode `0555`. Ownership, traversal,
readability, and nonwritability are asserted before mounting. During each actual
full runtime, UID 65532 must read the staged inputs, must fail write attempts to
all seven immutable mounts and the read-only root, and must report those checks
in verifier-enforced evidence. Dedicated writable work, output, and store trees
contain no verifier source. It exercises the real
Zigbee2MQTT EventBus,
disconnected Mqtt object, ExternalExtensions/ExternalJS loader, and only the
Controller add/remove/get/enable API shell. It does not construct, start, or stop
the full Controller, connect MQTT, construct/start Zigbee or herdsman, open
serial/radio devices, or use Home Assistant. Device and endpoint behavior remains
synthetic.
The pinned Zigbee2MQTT `ExternalJS` loader creates its `node_modules` symlink
lazily inside the per-source `loadFiles` loop. The source-free `stop_remove`
restart therefore proves an empty external-extension directory with no retained
alias; positive-source runs still require exactly one alias targeting
`/z2m/node_modules`.

Every attached container uses Docker's transient `json-file` log driver with
exact `max-size=1m` and `max-file=1` bounds. Attached stdout and stderr are also
captured only in private temporary files; no PASS B0 logs or evidence are
uploaded as workflow artifacts. A failed bounded start retains its container
for a bounded private `.State` inspection before cleanup. Only the fixed
`package_fetch`, `fetch`, `install`, `runtime`, and `verifier` stage roles reach
the classifier. It emits
fixed timeout, OOM, process-exit, malformed-inspect, unknown, or OCI `rlimit`,
mount, permission, invalid-argument, exec, `no_such_file`, `not_directory`,
`readonly`, cgroup, and security categories. Exact canonical
`true-family-pass-b0-runtime-failure-v2` records preserve only a lowercase
`failure_code` matching `^[a-z0-9_]{1,40}$` as `runtime_<failure_code>`.
This includes the wrapper's synthetic `case_failed` and the harness's exact
`internal_failure`; malformed, noncanonical, duplicate, multiple, oversized, or
extended records remain `runtime_process_exit`. Downloader failure records also
receive specific process-exit codes. Every other invoked verifier mode emits at
most one bounded canonical `true-family-pass-b0-verifier-failure-v1` record. It exposes
only an allowlisted mode-level `failure_code`; unknown exceptions become
`verifier_failed`. The start classifier accepts only that exact canonical schema
and otherwise retains `verifier_process_exit`. All other package, Node, Docker,
and process output remains private and maps to the stage's generic process-exit
code. Each container and its transient Docker log are removed immediately after
bounded use or by failure cleanup. Label-based container and network cleanup is
verified before pass output.
Sealed immutable directories remain read-only through all container, network,
and final-validation work. Only then, after exact zero leftover containers and
networks, the launcher verifies the temporary-root path and owner and uses
`find -P -xdev -type d` to restore directory mode `0700` solely for deletion;
files and symlinks are never chmodded. Trap cleanup performs the same preparation
best-effort. Pass evidence is not emitted until root deletion and absence are
verified.

The raw extension source is necessarily seen inside the process through
Zigbee2MQTT's in-memory retained inventory. It is not emitted in CI or final
evidence, and no broker delivery is exercised or claimed.

The duplicate-source case intentionally records that the test preflight rejects
the byte-identical collision while the real loader sequentially replaces the same
class. The real EventEmitter functions are measured as removed on stop, but
EventBus bookkeeping retains the four same-class callback records; after the
sequential replacement it contains eight records under the shared class key.
Callback-registry cleanup and runtime collision enforcement are therefore
explicitly not proven, and no authority is granted. The gate also does not prove
a broker, ACL enforcement, retained replay, physical frame provenance,
coordinator or radio ordering, actual-spare behavior, external permit authority,
or the single-writer fence. Even a successful CI result remains smoke evidence
only.

Every Docker info, image, create, start, inspect, removal, network, and cleanup
query has an explicit timeout and fixed failure classification. The launcher has
a 2,040-second full-run watchdog, while the workflow allows 45 minutes so bounded
cleanup can complete and report failures without being killed by the runner.

The HAOS development host has no Docker and is not an amd64 GitHub runner. Normal
local execution therefore exits before network or temporary-file creation with a
fixed `inherited_environment`, `docker_required`, or `ci_runner_required` result;
it never falls back to unshare, DAC permissions, or Landlock. Local validation
is limited to the strictly static `--shell-self-check`, `--self-check`, and
project tests; neither self-check uses Docker, network access, or a temporary
PASS B0 root.

### PASS B1A CI-Only Composite MQTT Policy Foundation

PASS B1A adds a separate same-repository, reviewed-source, non-authoritative
broker plus packet-gateway policy gate in `.github/workflows/pass-b1-broker.yaml`. It runs only on
`refs/heads/main` with fixed `ubuntu-24.04` and Linux amd64 expectations. It is
not PASS B1 completion, independent attestation, malicious-source-resistant
evidence, household equivalence, or an authorization input. No loose spare,
coordinator, radio, valve, Home Assistant, household broker, or household
Zigbee2MQTT instance is used. Until the main-branch workflow itself succeeds,
the repository claims only the implemented and statically verified gate, not a
completed live-broker result.

Under the accelerated policy, one successful B1A run is sufficient to proceed
to the minimum B1B gate; there is no repeat-attestation requirement. This does
not authorize a loose spare: no spare may be paired until the minimum permit
consumption and continuously held writer-fence gate passes.

The gate pins the exact Node child already used by PASS B0 and the exact
Mosquitto `2.0.22` Linux amd64 child
`docker.io/library/eclipse-mosquitto@sha256:54c90ecc78645241b6aa272b2a5ac8fc20b0eaf02cc4dd431c0cc8d2fd4447dd`.
The Mosquitto multi-platform index digest is reference metadata only. Image
inspect must match the expected platform, exact child digest, Mosquitto OCI
config digest, exact registry environment and OCI labels, entrypoint, and
command. Each of two sequential replicas gets a fresh mode-`0700` private root,
fresh separated credentials, fresh Dynamic Security database, fresh persistent
broker data, and two fresh internal Docker networks. The broker, installer,
read-back, and temporary source-observer containers are backend-only. Matrix
clients are frontend-only. The packet gateway is the sole dual-homed container,
with alias `gateway` on frontend port `18884`, and the broker has alias `broker`
only on backend port `18883`. No host port is published and no client has a
route or DNS name for the broker. Frontend probes also inspect the default-route
state, resolve the common Docker host aliases where available, and attempt
bounded host-alias and external TCP connections. Those observations do not prove
isolation from the same GitHub runner host.

Mosquitto Dynamic Security remains the authentication, delivery, and
representable-ACL authority. Its
initial admin is generated by the image's official isolated
`mosquitto_ctrl dynsec init` path, with the mode-`0600` password supplied only to
the private setup process and host-side redaction verifier. The required
`mosquitto_ctrl` password argument is
transiently visible to same-runner processes able to inspect that setup process's
`/proc` command line; it is absent from Docker create/inspect data and emitted
evidence. A backend-only installer receives only that admin
credential, narrows the admin role, installs exact bound identities for
synthetic Zigbee2MQTT, orchestrator, test-only collector, and authenticated
no-access control principals, and emits a separate frontend credential set plus
a single temporary observer credential. Frontend clients never receive admin or
observer credential files. The gateway is provisioned no credential or probe
artifact files, but password-bearing CONNECT frames and source-payload bytes do
pass through its memory in transit. It parses the metadata needed for policy,
does not decode those bytes as credentials or source, does not write or persist
them, and forwards the original CONNECT for broker authentication. Anonymous,
unknown, wrong-password, and right-password/wrong-client-ID connections must
fail; gateway-close denials also prove that no broker ACK or PUBLISH preceded the
close. The collector exists only for this disposable test and is not part of the
production preflight principal model.

The installed policy is compiled against the exact ACL-plan-v2 `topic_contract`
and B1-only versioned oracle in `physical_probe_pass_b1_manifest.json`. The
committed `physical_probe_preflight_vectors.json` remains byte-identical PASS B0
v1 input; current v2 fencing rejects its old v1 ACL evidence rather than adding
compatibility behavior. The orchestrator can publish
only the two exact probe request topics and subscribe only to the five exact
ready, status, result, response, and acknowledgement-response topics. Candidate,
source, backup, descendant, broad, and repeated bridge-request cases are tested
with broker-confirmed positive controls and gateway-close negative controls. The
gateway enforces the exact preflight topic-validity oracle, including the
256-Unicode-code-point bound and accepted internal empty segments. Exact-limit,
overlength, empty, leading/trailing slash, ASCII and Unicode boundary whitespace,
U+0000/U+0001-U+001F, U+007F-U+009F, surrogate, Unicode noncharacter, wildcard,
and malformed UTF-8 cases are exercised without adding an NFC normalization
rule. It denies any adjacent `bridge/request` segments at arbitrary depth, with
explicit depth 0, 8, 32, and 100 cases. It also enforces orchestrator QoS 1 with retain disabled,
allows Zigbee2MQTT QoS 0, 1, or 2 with either retain value on contract-valid
topics inside or outside the base root, allows its sole `<base>/#` filter or any
contract-valid concrete topic at requested QoS 0, 1, or 2, and denies all other
wildcard or shared filters. Stateful PUBREC/PUBREL/PUBCOMP handling proxies both
QoS2 directions, accepts only identity-exact DUP PUBLISH races before completion,
rejects changed or stale retransmissions, and requires successful PUBREC and
PUBCOMP results. Other and collector publishing remains denied. The broker and
protocol endpoints still perform every successful PUBACK, PUBREC, PUBCOMP,
SUBACK, and delivery; the gateway never forges a broker success acknowledgement.

Every policy command carries unique correlation data, and command success comes
only from the matching Dynamic Security response, never from request PUBACK.
The verifier obtains canonical live lists and individual detail read-backs for
defaults, anonymous-group state, clients, assignments, roles, ACL priorities,
and groups. Missing, extra, duplicated, reordered, or changed objects fail. The
Zigbee2MQTT role read-back must place the exact `<base>/#` literal subscription
before its broad defense-in-depth `#` subscription pattern. Backend-only probes
using application credentials sample native allows and denials, explicitly show
that Mosquitto alone does not enforce the orchestrator QoS/retain envelope, and
exercise Zigbee2MQTT outside the base root at QoS2. Two clean broker stops and
restarts require bounded authenticated MQTT v5 readiness before backend probes,
preserve the exact observed policy digest, and rerun the complete frontend
authentication matrix after each restart.

The source-privacy exercise publishes the exact source-derived retained inventory
through the synthetic Zigbee2MQTT principal, proves a temporary narrow observer
can replay it at QoS 1, and proves fresh and reconnect attempts by the
orchestrator, collector, and other principal cannot subscribe through exact,
base-wildcard, or shared-wildcard filters. The source is then cleared by the
synthetic Zigbee2MQTT principal; after broker restart, the old retained payload
must be absent while a new non-retained positive control remains deliverable.
Raw source and credentials are excluded from evidence and logs. JSON and text
outputs remain strict UTF-8. After live replica verification, the gateway and
broker are cleanly stopped and the broker's zero-exit inspect is captured before
the exact data-directory target is scanned. Its one bounded, regular, single-link
`mosquitto.db` is scanned as raw bytes for exact source and credential canaries.
Credential inputs are separately metadata- and containment-validated to obtain
those canaries; they are never scanned against themselves or included in the
explicit non-secret output roots. Request topics
must finish non-retained, and private broker
state is deleted before final pass output. `check_retain_source` is configured,
but this layer deliberately does not claim an adversarial source-authorization
change that proves that option's behavior. The pre-restart observer is revoked
before read-back, a freshly generated post-restart observer is used only for the
old-retained-absence and non-retained positive-delivery controls, and that second
observer is also revoked before final read-back.

A separate application-credential sentinel is published retained at QoS 2,
replayed after the first broker restart, cleared at QoS 2, immediately checked
absent, and checked absent again after the second restart with a positive
non-retained QoS2 control. This proves sampled native retained persistence and
clear behavior; it is distinct from the exact Dynamic Security read-back and
does not claim the untested adversarial `check_retain_source` transition.

The two replicas must produce byte-identical normalized verifier records after
random names, credentials, container IDs, network IDs, timestamps, and
nondeterministic inspect collection order are validated and omitted. Containers
run as the non-root runner UID/GID with a read-only root, all capabilities
dropped, `no-new-privileges`, private IPC and
cgroup namespaces, an observed Docker seccomp filter, bounded
memory/CPU/pids/file descriptors, bounded
`json-file` logs, and no forbidden host paths or Docker socket. Cleanup uses only
the validated private root and labeled resources, does not follow symlinks or
chmod regular files, and requires zero labeled containers and networks plus root
and credential absence before the one canonical final record is emitted. The
internal watchdog fires after 1,920 seconds; against the 2,700-second workflow
limit this is 780 seconds of nominal headroom, or 510 seconds after the longest
270-second command. Workflow setup occurs before the watchdog starts, so this is
not a mathematically guaranteed external-timeout cleanup reserve and an overall
GitHub timeout is not cleanup proof. Host commands are bounded, the final-output descriptor is closed in
children, and failure handling attempts private-root removal even when resource
cleanup or its read-back fails. Seccomp is an observed hardening setting, not a
complete host or kernel isolation boundary. On failure, only the launcher emits
one small canonical `true-family-pass-b1a-launcher-failure-v2` record containing
the fixed failure code and one finite allowlisted `failure_stage`; invalid stage
state projects to `unknown`. A failed installer writes only a private canonical
`true-family-pass-b1a-runtime-failure-v2` category record; a bounded verifier
reduces that record to one of eight tokens for the launcher stage suffix, with
generic or malformed failures becoming `unknown`. The private record is never
emitted separately. No command, status, path, log, stderr, random value, or other
diagnostic field is emitted. No workflow artifact is uploaded.

The effective policy is explicitly composite. Dynamic Security provides broker
authentication, successful delivery, and its representable defense-in-depth ACL
rules. Those broker ACLs are intentionally broad enough for the shared preflight
Zigbee2MQTT semantics; they are defense in depth, not the exact envelope. The
packet-aware Node MQTT v5 gateway enforces the missing exact
topic-validity, arbitrary-depth containment, QoS, retain, concrete-subscription,
source-privacy, and candidate-privacy rules before forwarding frames. It also
uses bounded handshake/idle timers, rejects residual post-CONNECT bytes, closes
backend-connect races, applies backpressure in both directions, and unreferences
its timers. Frontend malformed input closes only that session; malformed or
unsupported broker-origin packets latch the disposable gateway globally, while
normal client-close races do not. Gateway,
broker-policy, preflight-ACL, read-back, matrix, source, image, launcher, runtime,
verifier, and workflow digests are bound into canonical evidence. Unsupported or
malformed packet states fail closed. The run proves that the listener remains
healthy through the sequence; backend and listener fault injection are explicitly
not claimed.

Final evidence distinguishes the exact Dynamic Security read-back, sampled
native broker outcomes, exact gateway matrix enforcement, and tested pure
composite equivalence. The launcher reruns the Python preflight oracle against
the same bound matrix before starting Docker. It does not collapse any one of
those layers into proof of the others.

PASS B1A still does not exercise the real Zigbee2MQTT MQTT/ExternalJS retained-source
path, broker delivery to a real Zigbee2MQTT process, atomic permit consumption,
a continuously held writer fence, physical response provenance, coordinator or
radio ordering, or actual-spare behavior. It does not authorize pairing or any
live-home action. Those limitations are embedded in the manifest and final
evidence and keep overall PASS B1 incomplete.

The physical-probe source is offline and unwired: integration setup does not
import or register it, and this project contains no automatic external-extension
deployment, save, or removal path. The pure preflight module validates only
caller-supplied mappings; it has no collector, broker client, deployment mutator,
filesystem, process, network, MQTT, or Home Assistant access. Protocol v2 accepts
only BRT DP2
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
and empty queues are necessary but do not prove final adapter/radio ordering. The
CI-only PASS B0 smoke cannot establish that ordering; it still requires a future
authoritative broker/coordinator harness and actual-spare physical proof.

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

The raw snapshot contract remains v1, while the unreleased normalized ACL plan
is v2 with a domain-separated digest and explicit topic contract. It defines,
but does not deploy or collect, the exact runtime/build, external-extension
identity, lifecycle collision, privacy, and
writer-fence evidence required by this source. Its first raw temporal snapshot is
fresh-deployment-only: the semantic digest of the complete immutable manifest,
exact clean artifact, pinned runtimes and upstream references, normalized
effective ACL, disabled writers and unsafe controls, full candidate identity,
and complete absence of journal, temporary, alias, recovery, or in-flight write
evidence must all match. The expected owner is derived from the collection epoch,
process instance, artifact, extension path, and journal path. Configuration and
ACL generations and digests form the observed fence report. Any existing or
recovery journal fails closed; this pass never invokes recovery.

The second, shorter-lived raw snapshot uses strict temporal order:
`deployment observed < pre-arm observed < now < pre-arm expiry`, with pre-arm
expiry no later than deployment expiry. It repeats the same epoch, process,
derived owner, configuration/ACL fence, source hashes, candidate identity, name,
set topic, and empty groups; records exactly one current loader and journal owner
with any previous owner drained and zero late completions; repeats the fresh
absent-journal observation; proves complete idle endpoint inventory; and requires
a ready, generation-zero, record-free, command-free probe.

Deployment and pre-arm attestations are reports only. They are deliberately
constructible data and are never accepted as authorization input.
`validate_prearm` re-runs deployment validation from the raw deployment mapping.
`authorize_arm` accepts the two raw snapshots plus only an exact canonical ARM
JSON string, then re-runs deployment, pre-arm, duplicate-key, canonical-byte, and
strict request validation. Raw trees accept only exact built-in dictionaries and
lists, never proxies or subclasses. Canonical ARM text is character-bounded before
UTF-8 encoding and then byte-bounded before parsing. The permit binds safe digests
of those exact payload bytes and the fully prefixed publication topic plus fixed
QoS 1 and retain false; it exposes no raw request, candidate, or topic.
`verify_arm_permit` repeats that complete raw pipeline before exact-comparing a
permit candidate. It proves only recomputed self-consistency, not authenticity,
and a fabricated report or permit cannot replace raw evidence.

The permit candidate sets `one_shot_required` to `true`,
`consumption_enforced` to `false`, and `commands_authorized` to `false`. Repeated
pure calculation may return the same candidate. It grants no endpoint command
authority and does not enforce one-shot use. A future external consumer must hold
the fence lease, atomically consume the exact permit, and publish the exact
canonical bytes and fixed topic/QoS/retain envelope.

The normalized orchestrator PUBLISH and SUBSCRIBE policy is deny-by-default. It
allows only the two exact fully prefixed probe request topics for publication at
QoS 1 with retain disabled, and only the five exact ready, status, result, normal
response, and acknowledgement-response topics for subscription. Candidate
friendly-name and IEEE publish subtrees remain denied to every non-Zigbee2MQTT
principal. A candidate friendly name cannot use `bridge` as its first topic
segment or duplicate its IEEE root, keeping both fenced roots distinct from every
bridge/probe namespace. Slash-delimited `bridge/request/` containment, including
repeated prefix forms, fails closed outside the exact request pair; bridge source,
backup, broad bridge, and candidate surfaces are not exposed to the orchestrator.
Zigbee2MQTT subscription remains default-allow for concrete topics and the sole
exact `<base>/#` filter, including request topics, while every other wildcard
filter and Zigbee2MQTT publication to any bridge-request containment remains
denied.

This is a report boundary, not operational readiness. Raw evidence establishes
only internal self-consistency until an authenticated trusted collector proves
real candidate-alias ownership, obtains authoritative broker/lifecycle evidence,
and continuously holds the external fence lease. Two point-in-time mappings do
not acquire or hold a lease. PASS B1A now supplies a non-authoritative disposable
real-broker plus packet-gateway composite policy, exact installation/read-back,
and synthetic retained-source privacy foundation. It does not supply atomic permit consumption, a continuously held
writer fence, the real Zigbee2MQTT source path, cross-instance lifecycle
enforcement, deployment/removal workflow, authoritative full-runtime evidence,
final adapter/radio ordering, or actual-spare physical bench proof. PASS B0
remains only the reviewed loader/adapter smoke. Neither gate establishes bench or
deployment readiness, and overall PASS B1 remains incomplete.

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

The released phase-two source contains Home Assistant, MQTT, climate, and
WebSocket adapters. Release `0.2.1` of the integration and journal App remains
installed but intentionally inactive on the household system: no logical valve
is bound and no bootstrap, migration, probe, or heating action is active. The
unreleased physical-probe preflight is not imported or registered by integration
setup. No concrete five-provider write bridge or migration executor is installed
by default, so reference migration remains unavailable until those explicit host
capabilities are supplied.

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
App, private data, test backup, and repository were removed. That temporary
`0.2.0` test installation is not current; the separate `0.2.1` integration and
App installation described above remains present but inactive.

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
