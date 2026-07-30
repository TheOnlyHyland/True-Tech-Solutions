# Changelog

## 0.2.1

- Establish `0.2.1` as the first HACS-supported release; earlier tags remain
  preserved but are not HACS installation targets.
- Add the proprietary GitHub/HACS custom-repository installation path and local
  integration branding.
- Fix Home Assistant form serialization while preserving strict MQTT topic
  validation.
- Recover exact restored journals when discovery arrives during retry, error, or
  an older setup attempt.
- Require Home Assistant OS `2026.7.4` or newer for both integration and App.
- Run the complete Home Assistant suite in release CI and reject reused Git and
  container version tags.

## 0.2.0

- Bind the App and integration to the permanent public repository identity.
- Publish from the repository-root Home Assistant App layout.
- Declare the generic GHCR multi-architecture image built by the guarded release
  workflow.
- Require the exact repository-derived Supervisor hostname before discovery.

## 0.1.3

- Run the single-process journal directly instead of executing the unused S6
  overlay from writable runtime paths.
- Keep the App under its restrictive AppArmor profile in a real Supervisor
  build while allowing only the journal launcher and declared runtime.
- Verify private DNS, signed save/barrier/load, restart rekey, stale-credential
  rejection, cold backup, and post-backup read-back in an App-only test.

## 0.1.0

- Add the project-only internal journal protocol and signed discovery contract.
- Add strict canonical JSON validation and generation-plus-revision CAS.
- Add single-worker SQLite WAL storage with durable idempotency receipts.
- Add focused offline Home Assistant harness coverage.
- Advertise an explicit process-crash-only SQLite WAL/FULL CAS capability.
- Add cold-backup shutdown, bounded request admission, and timed body reads.
- Add a 3 MiB root ceiling and strict schema-v2 receipt/version validation.
- Put production port 8765 behind a bounded strict HTTP/1.1 frontend.
- Keep every pre-authentication error free of live process identity.
- Move to bounded schema-v3 receipt suffixes without canonical request blobs.
- Add real SIGKILL, accepted-work crash, and graceful cold-stop process evidence.
- Bound decimal `Content-Length` parsing and all production response writes.
- Cancel hung discovery on early process signals and bound handler shutdown.
- Bind every save request ID deterministically to its canonical body digest.
