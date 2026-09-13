"""Collect one selected ServiceNow incident record."""

from ._client import IncidentReadError, IncidentReadSession
from ._contracts import IncidentClockResult, make_result


def collect(session: IncidentReadSession) -> IncidentClockResult:
    """Traverse only the fixed endpoints and cursors admitted by the owned session."""
    if type(session) is not IncidentReadSession:
        raise IncidentReadError()
    try:
        if session.provider != "servicenow":
            raise IncidentReadError()
        session.read_record()
        return make_result(session.finish())
    finally:
        session.close()
