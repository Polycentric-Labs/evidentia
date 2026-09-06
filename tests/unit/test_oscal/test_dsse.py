import base64

import pytest
from evidentia_core.oscal import dsse


def test_pae_matches_dsse_spec_known_answer():
    # Canonical example from the DSSE protocol spec.
    result = dsse.pae("http://example.com/HelloWorld", b"hello world")
    assert result == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"


def test_pae_length_is_utf8_byte_count_not_char_count():
    # 'café' is 4 chars but 5 UTF-8 bytes; the LEN field must be 5-derived.
    ptype = "application/vnd.café+json"  # 25 chars, 26 bytes
    out = dsse.pae(ptype, b"x")
    assert out.startswith(b"DSSEv1 26 ")
    assert ptype.encode("utf-8") in out


def test_decode_b64_accepts_standard_and_urlsafe_identically():
    raw = b"\xfb\xff\xbe\x01\x02\x03"  # bytes whose base64 differs by alphabet
    std = base64.b64encode(raw).decode("ascii")  # contains + / =
    url = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")  # - _ no pad
    assert dsse.decode_b64(std) == raw
    assert dsse.decode_b64(url) == raw


def test_decode_b64_rejects_embedded_whitespace_and_noncanonical():
    good = dsse.b64encode_std(b"hello world")
    with pytest.raises(dsse.DSSEError):
        dsse.decode_b64(good[:2] + " " + good[2:])  # embedded space
    with pytest.raises(dsse.DSSEError):
        dsse.decode_b64("/x==")  # decodes to b'\xff' but re-encodes to '/w==' -> non-canonical


def test_decode_b64_accepts_canonical_all_symbol():
    assert dsse.decode_b64("////") == b"\xff\xff\xff"


def test_envelope_round_trip():
    env = dsse.Envelope(
        payload_type="application/vnd.in-toto+json",
        payload_b64=dsse.b64encode_std(b'{"_type":"x"}'),
        signatures=(dsse.Signature(keyid="abc", sig=dsse.b64encode_std(b"sig")),),
    )
    text = dsse.serialize_envelope(env)
    back = dsse.parse_envelope(text)
    assert back == env


@pytest.mark.parametrize(
    "bad",
    [
        "{}",  # missing fields
        '{"payloadType":"x","payload":"eA==","signatures":[]}',  # empty signatures
        '{"payloadType":1,"payload":"eA==","signatures":[{"keyid":"a","sig":"eA=="}]}',  # wrong type
        '{"payloadType":"x","payload":"eA==","signatures":[{"keyid":"a"}]}',  # sig missing
        "not json",
    ],
)
def test_parse_envelope_strict_rejects(bad: str):
    with pytest.raises(dsse.DSSEError):
        dsse.parse_envelope(bad)


def test_parse_envelope_rejects_deeply_nested_json():
    with pytest.raises(dsse.DSSEError):
        dsse.parse_envelope("[" * 60000 + "]" * 60000)
