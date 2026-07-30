# True Family Journal

True Family Journal is an experimental Home Assistant App that provides a small
crash-aware persistence boundary for the True Family TRV replacement project.

It is not installed in the live Home Assistant instance. It has no ingress,
host networking, published ports, Home Assistant directory mappings, privileged
access, Docker API access, or Home Assistant API access. Its only persistent
state is held in its private `/data` volume.

The production identity is bound to public repository
`https://github.com/TheOnlyHyland/True-Tech-Solutions`, full Supervisor slug
`8c9c720e_true_family_journal`, and GHCR image
`ghcr.io/theonlyhyland/true-family-journal`. The integration rejects local,
temporary, aliased, and suffix-matched App identities.

Production traffic enters through a bounded strict HTTP/1.1 frontend rather than
aiohttp's parser. The frontend accepts at most 16 active connections, deadlines
headers and fixed-length bodies, and rejects transfer encoding and chunking.
Response writes are bounded to five seconds. Shutdown gives accepted handlers at
most 15 seconds before aborting their transports and proceeding to SQLite drain
and checkpoint.

Backups are cold: Supervisor stops the App and waits for its graceful SQLite WAL
checkpoint and connection close before copying `/data`. Supervisor allows up to
60 seconds for that drain before terminating the App.

The advertised durability capability is process-crash-only. This remains
prototype evidence, not a hardware power-loss certification, and cannot be used
as authorization for live host mutations.

Install the True Family integration through HACS and restart Home Assistant Core
before installing this App. The complete installation, recovery, and exact
repository-identity procedure is documented in the project
[README](../README.md#supported-installation).

This App requires Home Assistant OS with Home Assistant `2026.7.4` or newer.

See [DOCS.md](DOCS.md) for the wire protocol and storage contract.
