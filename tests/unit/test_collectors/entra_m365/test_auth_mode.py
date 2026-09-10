"""Preserve unknown pre-resolution mode without accepting known contradictions."""

import pytest
from pydantic import ValidationError

from ._transport_support import CA_PATH, ORIGIN, Reply, encode_page


@pytest.mark.parametrize("state", ["complete", "partial", "401", "403"])
def test_known_mode_cannot_be_erased_from_accepted_or_denied_evidence(make_run, state):
    if state in {"401", "403"}:
        replies = [Reply(status=int(state))]
    elif state == "partial":
        replies = [Reply(encode_page([], ORIGIN + CA_PATH + "?page=2")), Reply(b"{")]
    else:
        replies = [Reply()]
    source = make_run(replies).read()
    capability = source.capability
    assert capability.declared_auth_mode == "application"
    assert capability.state == ("unavailable" if state in {"401", "403"} else state)
    payload = capability.model_dump()
    payload["declared_auth_mode"] = None
    with pytest.raises(ValidationError, match="invalid_auth_mode"):
        type(capability).model_validate(payload)


@pytest.mark.parametrize("reason", ["private", "run-budget"])
def test_pre_resolution_refusal_keeps_mode_unknown_and_does_not_resolve(make_run, runtime, reason):
    run = make_run([])
    if reason == "private":
        runtime[0].refusal = "private"
    else:
        run.clock.advance(300)
    source = run.read()
    assert source.capability.state == "unavailable"
    assert source.capability.declared_auth_mode is None
    assert source.capability.requests_attempted == 0
    assert run.provider.calls == []
    assert run.scenario.requests == []
