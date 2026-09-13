"""Collect one selected PagerDuty incident log interval."""

from ._client import IncidentReadError, IncidentReadSession
from ._contracts import IncidentClockResult, make_result


def collect(session: IncidentReadSession) -> IncidentClockResult:
    """Traverse only the fixed endpoints and cursors admitted by the owned session."""
    if type(session) is not IncidentReadSession:
        raise IncidentReadError()
    try:
        if session.provider != "pagerduty":
            raise IncidentReadError()
        page = session.read_record()
        while page.accepted and not page.terminal:
            start = page.next_start
            if start is None:
                raise IncidentReadError()
            page = session.read_history_page(start)
        return make_result(session.finish())
    finally:
        session.close()
