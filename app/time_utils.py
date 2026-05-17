from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return the current UTC time as a naive datetime for DB compatibility."""
    return datetime.now(UTC).replace(tzinfo=None)