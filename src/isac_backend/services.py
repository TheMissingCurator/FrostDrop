"""Local bootstrap advertisements. Advertising is not service implementation.

Mirror the observed retail order/multiplicity with locally derived identifiers.
No retail names, process IDs, account material or capture files are loaded.
IDs are stable across connections to this experimental single-server catalog.
"""
from uuid import NAMESPACE_URL, uuid5

from isac_protocol.service_advertisement import ServiceAdvertisement


SERVICE_TYPES = (
    "profile_client", "group", "chat", "push_message", "auth", "server_list",
    "group", "chat", "match", "last_stand_match", "messaging", "server_list",
    "survival_session", "profile_cache_front", "leaderboard_client_handler",
    "money", "user_logs", "auth", "push_message", "money", "survival_match",
    "profile_client", "messaging", "profile_cache_front",
)


def _local_identifier(label: str) -> bytes:
    # Observed text layout: 8-4-4-16 hex digits (35 bytes), NOT standard UUID
    # text's 8-4-4-4-12. The client field is an opaque bounded string.
    value = uuid5(NAMESPACE_URL, "urn:project-isac:local-services:v1:" + label).hex
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:]}".encode("ascii")


def local_service_advertisements() -> tuple[ServiceAdvertisement, ...]:
    # Retail observed a distinct process_guid per advertisement, separate from
    # its service name. These are logical local instances, not OS process IDs.
    return tuple(ServiceAdvertisement(_local_identifier(f"service:{index}:{kind}"), (
        (b"type", kind.encode("ascii")),
        (b"process_guid", _local_identifier(f"process:{index}:{kind}")),
    )) for index, kind in enumerate(SERVICE_TYPES))
