"""Constants for the True Family integration."""

from __future__ import annotations

DOMAIN = "true_family"
NAME = "True Family"
VERSION = "0.2.1"

CONF_BASE_TOPIC = "base_topic"
CONF_BOOTSTRAP = "bootstrap"
CONF_REFERENCE_JOURNAL_ID = "reference_journal_id"
CONF_ROOMS = "rooms"
DEFAULT_BASE_TOPIC = "zigbee2mqtt"
DEFAULT_ALLOWED_MODELS = ("BRT-100-TRV",)
DEFAULT_ALLOWED_MANUFACTURERS = ("Moes",)

PAIRING_SECONDS = 60
CANDIDATE_DISCOVERY_SECONDS = 30
READBACK_SECONDS = 25
READBACK_TOLERANCE = 0.1
DEFAULT_SAFE_TARGET = 12.0

PERMIT_JOIN_RESPONSE_SECONDS = 10
PERMIT_JOIN_RECONCILE_SECONDS = 15
PERMIT_JOIN_OPEN_INFO_SECONDS = 10
PERMIT_JOIN_BASELINE_MAX_AGE_SECONDS = 15
PERMIT_JOIN_END_MAX_SECONDS = 254
PERMIT_JOIN_END_CLOCK_SKEW_SECONDS = 5

DEFAULT_ROOM_NAMES: tuple[tuple[str, str], ...] = (
    ("living_room", "Living Room"),
    ("kitchen", "Kitchen"),
    ("downstairs_bathroom", "Downstairs Bathroom"),
    ("guest_room", "Guest Room"),
    ("our_bedroom", "Our Bedroom"),
    ("clarks_room", "Clark's Room"),
    ("upstairs_bathroom", "Upstairs Bathroom"),
)

SIGNAL_SESSION_UPDATED = f"{DOMAIN}_replacement_session_updated"
DATA_SETUP_MANAGER = f"{DOMAIN}_setup_manager"

WS_PREFIX = f"{DOMAIN}/replacement"
WS_ROOMS = f"{WS_PREFIX}/rooms"
WS_START = f"{WS_PREFIX}/start"
WS_COMMIT = f"{WS_PREFIX}/commit"
WS_CANCEL = f"{WS_PREFIX}/cancel"
WS_ROLLBACK = f"{WS_PREFIX}/rollback"
WS_SUBSCRIBE = f"{WS_PREFIX}/subscribe"

WS_SETUP_STATUS = f"{DOMAIN}/setup/status"
WS_BOOTSTRAP_PLAN = f"{DOMAIN}/bootstrap/plan"
WS_BOOTSTRAP_COMMIT = f"{DOMAIN}/bootstrap/commit"
WS_MIGRATION_PLAN = f"{DOMAIN}/migration/plan"
WS_MIGRATION_COMMIT = f"{DOMAIN}/migration/commit"
WS_MIGRATION_RECOVER = f"{DOMAIN}/migration/recover"
