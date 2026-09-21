"""Small authored release pages and exact request examples."""

import hashlib
import json

from evidentia_core.release_cadence._json import canonical_bytes


def request(*, persist=False, channel="full_releases"):
    return {
        "schema_version": "release-poll-request-v1",
        "source_profile": "github-public-releases-2026-03-10",
        "owner": "Allen",
        "repository": "Example",
        "channel": channel,
        "persist": persist,
    }


def row(identifier=101, **changes):
    return {
        "id": identifier,
        "node_id": f"synthetic-{identifier}",
        "url": "inert://source",
        "html_url": "",
        "tag_name": "v1",
        "target_commitish": "main",
        "name": None,
        "draft": False,
        "prerelease": False,
        "created_at": "",
        "published_at": "2000-01-01T00:00:00Z",
        **changes,
    }


def request_bytes(**changes):
    return canonical_bytes(request(**changes), 4096)


def pages(monkeypatch, module, entries):
    calls = []

    def fetch(attempt, owner, repo, number, *, budget, totals):
        calls.append((owner, repo, number, budget.deadline))
        entry = entries[number - 1]
        if isinstance(entry, BaseException):
            raise entry
        raw, links = entry
        attempt.status_code = 200
        attempt.raw = attempt.decoded = len(raw)
        totals.raw += len(raw)
        totals.decoded += len(raw)
        attempt.raw_body_complete = attempt.body_complete = True
        attempt.raw_body_sha256 = attempt.body_sha256 = hashlib.sha256(raw).hexdigest()
        attempt.links = links
        attempt.links_available = True
        return raw

    monkeypatch.setattr(module.HttpAttempt, "fetch", fetch)
    return calls


def encoded(rows):
    return json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode()
