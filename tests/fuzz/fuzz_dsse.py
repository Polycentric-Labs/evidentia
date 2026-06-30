"""Atheris fuzz harness for the DSSE envelope parser (CWE-248 robustness).

Mirrors tests/fuzz/fuzz_oscal_verify.py. parse_envelope / decode_b64 must
raise DSSEError (or return) on ANY input — never an unhandled exception.
"""

import sys

import atheris

with atheris.instrument_imports():
    from evidentia_core.oscal import dsse


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    try:
        dsse.parse_envelope(text)
    except dsse.DSSEError:
        pass
    try:
        dsse.decode_b64(text)
    except dsse.DSSEError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
