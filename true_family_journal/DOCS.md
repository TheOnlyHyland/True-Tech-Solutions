# True Family Journal Documentation

## Scope

Version `0.2.0` is a minimal companion App vertical slice. It listens only on
the Home Assistant internal App network at port `8765`; `config.yaml` publishes
no host port and enables no ingress. The App does not import or modify the True
Family integration. It treats a journal root as opaque canonical JSON apart
from its built-in object type, `journal_id`, and non-negative `generation`.

## Discovery

On every process start the App generates a new 32-byte HMAC key and a new
16-byte boot identifier. It starts listening before replacing the Supervisor
discovery message for service `true_family`. The discovery configuration is:

```json
{"boot_id":"<32 lowercase hex>","host":"<internal hostname>","key":"<64 lowercase hex>","port":8765,"protocol":"true-family-journal-v1"}
```

The key and complete discovery payload are never logged. Only the previous
discovery UUID is persisted, at `/data/true_family_journal.discovery_uuid`, so a
stale message can be deleted before its replacement is posted. The `/discovery`
Supervisor API is available to Apps without `hassio_api` or an elevated role.
SIGTERM and SIGINT handlers are installed immediately after the listener starts
and before discovery begins. A stop during stalled discovery cancels that
request, drains the listener, and closes/checkpoints SQLite.

Install the True Family integration through HACS and restart Home Assistant Core
before adding the exact public repository URL to the App Store and starting this
App. App-first installation is recoverable by installing the integration,
restarting Core, and restarting the App once, but it produces an avoidable
missing-integration discovery error. Uninstalling this App deletes its private
`/data`; restore an App-inclusive backup instead of recreating the integration
entry or silently provisioning a replacement journal.

## Release Identity

The only trusted production repository URL is
`https://github.com/TheOnlyHyland/True-Tech-Solutions`. Supervisor hashes its
lowercase bytes to repository prefix `8c9c720e`, producing full App slug
`8c9c720e_true_family_journal` and internal hostname
`8c9c720e-true-family-journal`. URL aliases such as a `.git` suffix, trailing
slash, query, fragment, or branch suffix are different identities and are not
trusted.

The release workflow publishes `ghcr.io/theonlyhyland/true-family-journal` and
its per-architecture children, then signs each digest and the final manifest
with GitHub OIDC keyless Cosign. Home Assistant Supervisor does not currently
enforce Cosign signatures during installation, so signature verification is an
external provenance gate rather than a runtime authorization claim.

## Canonical JSON

Every request and response body is UTF-8 JSON serialized with sorted object
keys, compact separators, ASCII escaping, and `allow_nan=false`. Incoming bytes
must already equal that canonical serialization. Duplicate object keys,
non-built-in root objects, unknown endpoint-envelope keys, non-finite numbers,
invalid Unicode, more than 64 levels, more than 250,000 nodes, and bodies over
4 MiB are rejected. A save root has its own 3 MiB ceiling. The server computes
the exact worst-case canonical load-envelope overhead at import time and refuses
to start if the resulting response could exceed the 4 MiB wire limit.

Journal IDs use the project contract: non-empty text of at most 255 characters,
unchanged by trimming, with no control or delete characters. Journal IDs are
SQLite values and are never interpolated into filesystem paths. Request IDs are
`tfj-` followed by 32 lowercase hexadecimal characters. Boot and client IDs are
32 lowercase hexadecimal characters. Digests, keys, revisions, and commit
tokens are 64 lowercase hexadecimal characters.

## Authentication

All `POST` routes require exactly one of each header:

- `X-True-Family-Boot-ID`
- `X-True-Family-Request-ID`
- `X-True-Family-Signature`

The request signature is lowercase HMAC-SHA256 over these exact bytes:

```text
true-family-journal-request-v1\n<METHOD>\n<PATH>\n<BOOT_ID>\n<REQUEST_ID>\n<SHA256_BODY>
```

Authenticated responses echo the current boot ID and request ID and sign:

```text
true-family-journal-response-v1\n<STATUS>\n<PATH>\n<BOOT_ID>\n<REQUEST_ID>\n<SHA256_BODY>
```

Verification uses `hmac.compare_digest`. A new boot invalidates every signature
from the prior process. Non-idempotent request IDs may be used once per boot.
Save request IDs are deterministic and body-bound. They are `tfj-` plus the
first 32 hexadecimal characters of SHA-256 over these ASCII bytes:

```text
true-family-journal-save-id-v1\n<SHA256_BODY>
```

This check occurs before receipt lookup, so reusing an old or pruned save ID with
different bytes fails even when its receipt no longer exists. Save retries may
reuse the ID only with the byte-identical body. Other endpoint IDs remain random.
Barrier retries are idempotent for an existing commit token.

Production port `8765` is owned by a small strict asyncio HTTP/1.1 frontend, not
aiohttp's request parser. It allows at most 16 accepted active connections, one
request per connection, and 8 KiB total request headers. Headers must complete
within two seconds. Request lines, names, values, and framing are parsed as
strict ASCII; obs-fold and duplicate headers are rejected. POST requires one
canonical `Content-Length`, rejects every `Transfer-Encoding` including
chunking, and must deliver exactly that bounded length within five seconds.
`Content-Length` is rejected if it contains more than ten decimal digits before
integer conversion. Every response write and drain is bounded to five seconds;
timed-out transports are aborted.

Malformed framing, admission saturation, wrong boot identity, invalid signature
shape, body timeout, and failed HMAC authentication are pre-authentication
failures. Their responses contain no boot ID, request ID, signature, key, or
other live process identity. Only after the full request HMAC validates are
successes and protocol errors signed with the current boot and request IDs.

## Endpoints

`GET /healthz` is unauthenticated and returns only:

```json
{"protocol":"true-family-journal-v1","status":"ok"}
```

`POST /v1/hello`

```json
{"client_id":"<client id>","nonce":"<1-128 byte nonce>"}
```

The response reflects `nonce` and reports the exact supported capabilities,
including `durability.sqlite-wal-full-process-crash-cas.v1`. This capability is
evidence for process-crash recovery only. It is not a host crash-durability
provider and must never authorize live household or host mutations.

`POST /v1/load`

```json
{"client_id":"<client id>","journal_id":"<journal id>"}
```

The response always has exactly `absent`, `generation`, `revision`, and `root`.
All except `absent` are `null` when the journal does not exist.

`POST /v1/save`

```json
{"client_id":"<client id>","expected_revision":null,"journal_id":"<journal id>","root":{"generation":0,"journal_id":"<journal id>"}}
```

For an absent journal, `expected_revision` must be `null` and generation must be
zero. For a present journal, `expected_revision` must exactly match the loaded
revision and generation must be exactly the current generation plus one. A
successful response contains exactly `commit_token`, `generation`, and
`revision`. The request ID is the durable idempotency key: the same ID and body
returns the original canonical response, while the same ID with different bytes
returns HTTP 409. There is no last-write-wins path.

`POST /v1/barrier`

```json
{"client_id":"<client id>","commit_token":"<commit token>","journal_id":"<journal id>"}
```

Success is returned only when the exact token has a committed durable operation
receipt for that journal. Repeating the barrier is harmless.

`POST /v1/close`

```json
{"client_id":"<client id>"}
```

Close is an acknowledged no-op in this first stateless client model.

Protocol failures use canonical `{"error":"<code>"}` bodies. Authentication
failures return 401, malformed requests 400 or 413, and CAS, replay, receipt, or
idempotency conflicts 409. Body-read timeouts return 408 and saturated request
admission returns 503. Authenticated-route responses with a canonical request ID
are signed, including errors.

## SQLite Durability Boundary

The sole database is `/data/true_family_journal.sqlite3`. All SQLite access is
serialized through one private worker thread. Startup enables WAL,
`synchronous=FULL`, foreign keys, and a busy timeout, enforces exact
schema-v3 `PRAGMA user_version`, validates exact normalized `sqlite_master` DDL,
tables, indexes and indexed columns, foreign-key actions, durability PRAGMAs,
and durable rows, and runs `PRAGMA quick_check`. Extra or altered tables,
indexes, views, triggers, keys, old versions, or corrupt rows stop startup. This
uninstalled source has no database upgrade path; schemas v1 and v2 are rejected.

Save uses `BEGIN IMMEDIATE`, exact generation and revision CAS, and one atomic
transaction for the journal row and immutable operation receipt. Canonical root
bytes, generation, revision digest, commit token, request digest, and the small
exact canonical response are persisted before commit returns. Full request
bodies are not retained. The request digest is sufficient to require
byte-identical same-ID replay.

Each journal retains exactly the newest 4,096 receipts once that many
generations exist. Pruning is part of the same save transaction. Startup
requires a contiguous retained suffix ending at the current generation and
revalidates every retained token, response, revision, and journal relationship.
Retained replay and barriers work normally; pruned IDs and tokens fail closed.
Graceful shutdown first stops acceptance, drains accepted work and the worker,
and gives handlers at most 15 seconds. Remaining handler transports are then
aborted and tasks cancelled before SQLite work is drained, a successful
truncating WAL checkpoint is required, and SQLite is closed.

`backup: cold` requires Supervisor to stop the App first. The stop does not
complete until the same checkpoint-and-close sequence has finished, so the
database is closed before its private `/data` volume is copied. App metadata
sets a 60-second stop timeout so this bounded drain can finish before Supervisor
uses a hard termination.

Tests exercise SIGKILL after commit with an uncheckpointed WAL, fresh-process
recovery and exact receipt replay, termination during accepted partial work, and
graceful cold-stop checkpointing. This is strong prototype process-crash
evidence only; it does not certify hardware power-loss behavior or an arbitrary
host storage stack.
