from enum import Enum

class Scope(str, Enum):
    """Canonical capability scopes for API tokens.

    Only two roles are supported: 'dev' and 'server'.
    We keep 'policy.read' and 'event.ingest' literals for compatibility in places
    that check effective permissions, but token creation restricts to dev/server.
    """

    read = "policy.read"
    event_ingest = "event.ingest"
    dev = "dev"       # developer token (read + publish + key upload + ingest)
    server = "server" # service token (read + ingest)