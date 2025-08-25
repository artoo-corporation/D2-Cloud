from enum import Enum

class Scope(str, Enum):
    """Canonical set of capability scopes for API tokens.

    Enum ensures payload validation via Pydantic. Values must remain stable as they
    are stored verbatim in the ``api_tokens.scopes`` column and enforced by
    ``require_scope`` at runtime.
    """

    read = "policy.read"
    admin = "admin"
    key_upload = "key.upload"
    policy_publish = "policy.publish"
    policy_revoke = "policy.revoke"
    policy_revert = "policy.revert"
    metrics_read = "metrics.read"
    event_ingest = "event.ingest"
    dev = "dev"  # shorthand for read + policy.publish + key.upload
    server = "server"  # read-only role (download & ingest)