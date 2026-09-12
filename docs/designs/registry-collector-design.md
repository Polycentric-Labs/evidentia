# Public registry collector design

The public registry collector records a bounded observation about one selected identity. A registry listing, TLS handshake, metadata signature or published disclosure does not establish compliance, eligibility, ownership or permission to test a system. Each result keeps the source facts, the query scope and the collection limits visible.

This design defines the shared foundation for the eleven selectors in the v0.13 registry batch. Provider projectors and application integration use that foundation. The source ledger binds the reviewed inputs; it does not assert continuing source currency or live provider acceptance.

## Requests and results

Requests contain only registry, its typed target and an optional scope_label. The label is an operator assertion. Requests cannot supply URLs, paths, credentials, proxies, timeouts, trust certificates, private address exceptions or an SSL Labs activation flag.

| Selector | Target | Observation scope |
| --- | --- | --- |
| tls | hostname | One verified TLS handshake on port 443 |
| rdap | domain | One domain record under a packaged IANA service selection |
| sam-entity | uei | Public registered entity occurrences from the selected v4 response |
| sam-exclusions | uei or organization_name | Selected firm exclusion occurrences, preserving every action |
| gleif | lei | One LEI record |
| fedramp | product_id | Matching products in the complete dated package |
| cmvp | certificate_number | Matching certificate in the complete reviewed package |
| fcc-covered-list | organization_name and named_organization_entries query_scope | Exact normalized names in the reviewed named-entry rows |
| incommon | entity_id | One entity descriptor verified under the pinned signature policy |
| ssl-labs | hostname and endpoint_ip | Disabled live access; zero upstream attempts |
| security-txt | hostname | The selected well-known file and permitted same-origin redirects |

The wire format separates lookup_outcome, collection_status and freshness. Complete traversal with no matching observations can produce not_found only within the selected source scope. Stale snapshots cannot establish current absence. Partial traversal with evidence remains partial; an unavailable lookup has no admitted observation. More than one distinct candidate identity remains ambiguous.

Every observation includes exact selected fields, source identity, match basis, field coverage, literal source times, transport verification and signature state. Missing, null, empty and unknown values remain distinct. Integers, finite floats, quoted numbers and timestamp precision are preserved. The result embeds complete observation copies in findings, with no automatic control mappings or inferred compliance decisions.

Native JSON admission rejects duplicate object keys, non-finite numbers, surrogates, coercion and caller-built model bypasses. Request data is limited to 64 KiB, depth 16 and 10,000 nodes. An observation has the same byte, depth and node limits. A complete result is limited to 4 MiB and depth 20. Capacity accounting reserves all terminal records and the complete finding copies before admitting a page.

## Shared execution

RegistryReadSession owns the nine finite operations: read_tls, read_rdap, read_sam_entity, read_sam_exclusions, read_gleif, read_snapshot, read_incommon, read_ssl_labs and read_security_txt. Each takes its typed target and a pure projector. Provider modules cannot create clients, resolve credentials, follow links, paginate or maintain response caches.

The session captures source identity, raw record counts and expected selected values before invoking a projector with a detached view. It compares the result with the independent finite field contract. Admission is atomic for a page. Equal identities with equal selected facts coalesce; conflicting duplicates are quarantined while unrelated earlier evidence remains available. A later failed page does not erase already admitted evidence.

A run permits at most 20 accepted pages, 100 admitted records, 64 network attempts, 24 source reads and 64 diagnostics. Raw and decoded HTTP bytes have separate 8 MiB ceilings. Observation bytes have a 2 MiB aggregate ceiling; at most 100 findings are emitted. A monotonic 60-second scheduling deadline applies throughout parsing, projection, admission and final validation. Connection timeout is at most five seconds and read timeout at most ten seconds, each limited by remaining time. These bounds do not claim preemptive interruption of every native call or a universal native allocation ceiling.

HTTP attempts own their clients, transport, sockets and DNS pins. Complete DNS answers must be public before connection; mixed public/private answers are refused. Each attempt connects only to the first address in that complete approved result. Each accepted redirect is checked and pinned again. HTTPS uses an explicit verified SSL context with reviewed trust, HTTP/1, disabled environment proxy/netrc support, no automatic redirects or library retries, no keepalive and a reject-all cookie jar. SAM credentials never enter HTTPX or HTTPcore.

Retry candidates are HTTP 408, 429, 500, 502, 503 and 504, or operational connect/read timeout. Ordinary logical pages permit at most three attempts, with default delays of one then two seconds. One Retry-After value may be decimal seconds or a supported HTTP date, must fit remaining time and cannot exceed ten seconds. Write timeout, authentication failure, source schema failure, identity mismatch and unsafe redirects are not retried. SAM makes one attempt per page; SSL Labs makes none.

Security.txt permits up to three same-origin HTTPS redirects. RDAP additionally requires every hop to remain under the selected service base path. Paths must be canonical: no dot segments, encoded separators, empty internal segments, query or fragment delimiters, credentials or protocol-relative references. Relative path references are resolved only after the original spelling passes these checks. This is a declared interoperability subset; unrelated referrals and legacy security.txt fallback are not followed.

Cleanup preserves the original cancellation object and records cleanup failures. A completed result is detached from private session state so later caller mutation cannot change cached evidence. A canceled session cannot be restarted as a fresh run.

## Registry interpretation

TLS reports the negotiated protocol and cipher, peer address and verified leaf certificate evidence. It does not enumerate supported protocols, assess revocation or assign a vulnerability score. A certificate verification failure never triggers an insecure retry to obtain missing fields. Only the first approved resolver address is attempted.

RDAP uses the original packaged IANA DNS bootstrap, longest DNS-label suffix and the first admissible HTTPS service base in source order. HTTP-only entries remain unavailable. The selected base, alternatives, publication and cache metadata remain visible. The domain object class and ldhName must bind the query before projection. A conflicting unicodeName is preserved with a visible advisory. Personal entities and vCard contact data are excluded from the selected projection.

SAM Entity always reports partial or unavailable because the reviewed source material does not establish complete traversal. SAM Exclusions uses native totals and raw page counts before local filtering. Each outer exclusion row is one occurrence containing its ordered actions. Response-body, request-page and source-row locators are explicitly local evidence locators, not invented publisher identifiers. Organization names use the declared normalization and a limited matching scope; a zero-match name query does not establish an authoritative exact-identity absence.

GLEIF binds data.type, data.id and attributes.lei. Legal-entity status and registration status are separate facts. Lapsed registration is not a synonym for an inactive entity. Multiple successor entities and unknown bounded values remain visible. Source dates and values are not silently rewritten to current interpretations.

FedRAMP, CMVP and FCC load immutable complete packages. Hash, byte count, canonical JSON, source manifest, selected field shape, source occurrence counts and identity joins are checked before lookup. Detached views cannot mutate the package. There is no runtime refresh or persistent response cache.

The current reviewed packages contain 6,651 selected records in total. FedRAMP retains 666 products, 334 unmatched history records and 62 unjoined package records. CMVP retains 5,510 certificates with their original active, historical and revoked memberships; only the reviewed certificate 5517 detail is included. FCC retains all 79 reviewed fact records, including 12 named rows and 40 conditional approvals. The full tuple inputs preserve the original selected-source occurrence correspondence separately from lookup snapshots.

FCC exact-name observations retain the selected named row, both applicable Appendix A footnotes, five linked scope-context records and complete snapshot provenance. Category, deployment, indirect-affiliate, conditional-approval and legal applicability remain unassessed. A named match does not imply that a deployment falls within the list, and a name not found does not negate category-based coverage.

Snapshot age uses the oldest applicable reviewed publisher cutoff, never a later retrieval or regeneration time. FedRAMP and FCC become stale after seven days; CMVP and the RDAP bootstrap use thirty days. FCC date-only cutoffs use UTC calendar dates. Missing, malformed or future cutoffs remain unknown. The current CMVP cutoff is unknown rather than inferred from its capture time.

InCommon uses the fixed production MDQ entity path and one percent-encoding of the opaque entity ID. Optional XML dependencies are checked before I/O. The verifier requires one root EntityDescriptor, exact entityID, a unique root ID and one direct signature with a single root reference. The supported tuple is RSA-SHA256, SHA256 digest and ordered enveloped plus exclusive canonicalization without comments. External references, ambiguous IDs, extra signatures, unsupported transforms and unexpected parameters are refused.

The production certificate is fixed by its reviewed DER fingerprint. A response KeyInfo cannot replace it. validUntil must have an exact supported comparison, be after observation and stay within the fourteen-day policy. Selected organization names, registration information and roles are derived only from the actual verifier-returned signed root. A valid signature does not establish schema validity, direct federation membership, deployment or resource ownership. No captured current production metadata tuple is claimed by the synthetic verification tests.

Security.txt requires UTF-8 text/plain, with at most an optional UTF-8 charset parameter. Raw and decoded content are each bounded to 65,536 bytes, with at most 2,048 physical LF/CRLF lines, 4,096 bytes per line and 1,024 recognizable fields. Field spelling, raw values, order and source-line correspondence remain exact. Other Unicode separators do not create new fields.

Presence, required Contact, single Expires, optional single Preferred-Languages, lexical syntax, exact expiry comparison and Canonical retrieval matching are labeled controller checks. Unknown fields remain visible. URI and language validation are explicitly limited lexical checks. Expiry beyond 365 days is advisory. Unsupported timestamp comparison remains unknown, with no precision rounding. Supported cleartext-signed framing may expose its correctly unescaped body; the OpenPGP signature remains unverified. No linked URI is fetched automatically.

SSL Labs retains the reviewed v4 Endpoint contract and exposes live_disabled before all I/O. There is no request, environment or UI activation flag, automatic assessment, polling, registration or fallback.

## Source and package evidence

The runtime source index binds source contracts, original captures, the finite field table, packaged snapshots, IANA bootstrap and public InCommon trust data. The fixture ledger distinguishes authored synthetic examples, unsigned XML templates and reviewed full selected-source tuples. Synthetic fixtures have no invented retrieval hash or publisher-signature claim.

Full snapshot regeneration consumes the reviewed complete tuples. Minimal converter fixtures test declared formats and drift refusal; they do not establish complete source correspondence. FCC regeneration consumes reviewed fact JSON and does not claim to parse arbitrary PDF or discover later amendments. Original raw source hashes are distinct from normalized tuple and snapshot hashes.

CMVP stores the complete snapshot and tuple payload as single gzip members under the existing file-size gate. Stored size and hash are checked before bounded decompression, and decoded size and hash are checked before JSON parsing. The snapshot decoder permits at most 4 MiB; converter tuple input permits at most 16 MiB. Source reads report actual stored bytes and identity separately from decoded bytes and identity. Regeneration uses a fixed gzip header, one raw DEFLATE stream with the reviewed Huffman-only policy and an explicit checksum trailer. Both locked Python runtimes reproduce the recorded archive bytes; future runtime upgrades must repeat that comparison.

The registries optional extra contains the XML verifier dependencies. Model and schema imports remain available without that extra. Exact optional-root absence is distinguished from broken transitive dependencies. Installed artifact acceptance requires fresh base and extra environments on both supported Python runtimes, package-data inspection and actual verifier controls. Masked imports in an all-extras process do not establish a real base-install result.

Shared foundation acceptance precedes provider implementation dispatch. It requires independent review of the exact executable contracts, transport ownership, signature policy, complete tuple correspondence, package contents and import profiles. Final batch acceptance also requires provider cross-review, application integration, generated artifact checks, required repository gates and verified protected-queue admission. Tags and releases remain separate actions.

### Reviewed FedRAMP source-data exception

The owner-approved Batch 16 exception retains 22 standing-rule substring matches in two reviewed FedRAMP data files. The matches occur in preserved public publisher values. The following raw LF bytes are the complete approved scope:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| packages/evidentia-collectors/src/evidentia_collectors/registries/data/fedramp/snapshot.json | 976293 | d37fdce16b3d497ea12a71757878a36397260fb6940a504d4ba34d4f88c2d99b |
| tests/fixtures/registries/fedramp/full-source-tuples.json | 1535178 | 11a62feef97245ead1ef1f40e90ae48a0074007e4b1508d7ab4345643b0685f7 |

The standing-rule sweep checks the exact repository-relative path, byte length and full SHA-256 before counting matches in the same captured bytes. All 21 rule fingerprints and all 21 occurrence counts must match the reviewed policy. Each file has counts 4, 2, 2 and 3 at zero-based rule positions 7, 9, 11 and 17; every other count is zero. Changed bytes, line endings, paths, rules or counts, and missing or failed verification tools, are refused.

All other public files and commit messages retain the normal 21-rule scan. The original publisher values remain exact. Source refreshes require a new source review and explicit owner approval of any replacement exception. Secret scanning, source correspondence, package integrity, runtime validation, signed commits and protected merge-queue requirements still apply.

### Offline API startup

API startup and model-status reporting read model configuration without loading AI provider clients. Schema generation, lifespan startup and the health endpoint work with an empty offline home and no tokenizer cache. The AI client retains its existing `get_default_model` import for callers. Model selection still reads `EVIDENTIA_LLM_MODEL` at call time, using the existing `gpt-4o` fallback only when that variable is absent.
