# xjet-swarma-video
A video deilvery system concept


Updated high-level design spec (integrated “Requirements and Attestations” and non-card payments)

1) Purpose and scope
•  Goal: Decentralized, creator-hosted video publishing and delivery. Creators own storage and keys; a neutral coordination fabric handles discovery, access policy, verification of “requirements,” and key release. Delivery is hybrid P2P + HTTP with optional ISP/edge caching.
•  Out-of-scope: Central custody of funds, general-purpose social networking, long-term DRM escrow.

2) Core principles
•  Creator sovereignty: content and encryption keys remain with creators; release is policy-driven.
•  Open storage: any S3-compatible storage (e.g., MinIO or cloud buckets).
•  Hybrid delivery: content fetched via P2P swarms with HTTP/S3 fallback for tail content or poor swarm health.
•  Verification-agnostic access: “payment” is just one of many possible requirements; the system accepts diverse, pluggable proofs.
•  Minimal trusted core: coordination fabric moves metadata, proofs, and short-lived key grants—not video bytes or funds.

3) Primary components
3.1 Creator Endpoint App (CEA)
•  Transcode and segment (e.g., GOP-aligned segments of ~2–10s; minute-long segments acceptable if aligned with UX).
•  Encrypt per segment with unique content keys; wrap keys under creator master key (local KMS/HSM optional).
•  Upload encrypted segments + checksums to S3-compatible storage; immutability preferred.
•  Push metadata: title, description, tags, language, thumbnails/previews, manifest (ordered segment IDs), and access Policy.
•  Seeder: optional always-on P2P seed for initial swarm health.
•  Key Agent: evaluates viewer-presented Attestations against Policy and issues short-lived, viewer-bound key grants.

3.2 Storage layer (creator-owned)
•  S3-compatible object store; segment objects addressed by content_id + segment_id.
•  Integrity: per-segment checksum and optional Merkle proof.
•  Access: public ciphertext (optionally presigned) or private with per-request presigned URLs.

3.3 Coordination & Discovery Fabric (CDF)
•  Global, stateless control-plane services (active-active).
•  Content registry: indexes creator-signed metadata, manifests, policies, segment location pointers.
•  Discovery API + UI: localized (target ≈250 languages).
•  Offer catalog: presents creator-defined “availability ads” (what’s required to unlock).
•  Verification broker: orchestrates verifier adapters to produce signed Attestations.
•  Key request broker: relays key requests to creator Key Agents and returns signed key grants.
•  Analytics signals: privacy-preserving counters; no raw playback telemetry unless creator opts in.

3.4 Viewer applications
•  P2P engine: content-only swarms for permitted content IDs/segment IDs.
•  HTTP fallback: fetch from creator S3/MinIO or edge caches.
•  Requirements module: guides user through selected unlock paths (puzzles, goodwill, social, email, crypto receipt, ad attention).
•  Attestation module: binds actions to viewer identity and content scope; submits to broker.
•  DRM/secure playback: holds keys in OS keystore/TEE where available; decrypts in-memory.

3.5 Pluggable verifier adapters (no custody of funds)
•  Email verifier: issues challenge, verifies mailbox control.
•  Puzzle/verifiable work verifier: human proof or calibrated PoW; includes difficulty/work factor.
•  Social-like verifier: platform API/OAuth or decentralized attest service proving a like/follow/share.
•  Crypto receipt verifier: validates on-chain/Lightning/rollup transfers to creator address (min confirmations).
•  Ad attention verifier: time-watched events with anti-spoof signals; issues proof-of-attention.
•  Allowlist/subscription verifier: codes, passes, NFTs, or creator-issued credentials.

4) Requirements and Attestations (payments are not credit cards)
4.1 Requirement types (extensible)
•  goodwill_ack: simple consent/acknowledgment; very low trust.
•  puzzle_solve: proof of work or human challenge; tunable difficulty.
•  email_verify: mailbox control with domain rules.
•  social_like: proof of interaction with a specified post/profile.
•  crypto_payment: receipt of funds to creator; chain/network/configurable confirmations and currencies.
•  watch_ad: proof of attention for N seconds.
•  allowlist_token: passcode/subscription/NFT/token-gate credential.

4.2 Policy model
•  A Policy is a Boolean expression (anyOf/allOf) over Requirements with parameters and per-requirement minimum trust thresholds.
•  Grants specify scope (segments/time), count, and TTL for key access.
•  Optional weight/score aggregation in addition to min_trust gates.
•  Optional per-path limits: segment caps, max plays, cooldowns, geotime windows.

4.3 Attestation model (viewer-bound, short-lived)
•  Fields (conceptual):
◦  attestation_id (unique, non-replayable)
◦  issuer (verifier adapter identifier/DID)
◦  subject (viewer public key or device binding; optional anonymized account)
◦  content_bind (title_id, segment scope or nonce)
◦  requirement (type) with params snapshot
◦  proof (verifier-specific evidence; opaque to evaluators except issuer)
◦  verifier_trust (0.0–1.0 calibrated by issuer reputation and method)
◦  issued_at, expires_at, nonce (for replay protection)
◦  signature (issuer)
•  Privacy: minimum PII; bind to viewer public key and content nonce; short TTLs.

4.4 Key Grants (creator-signed)
•  Fields (conceptual):
◦  grant_id, segment_ids or time-window scope
◦  key_ciphertexts (KMS-wrapped CEKs or envelope references)
◦  expires_at
◦  audience (viewer binding)
◦  policy_hash and creator signature
•  Semantics: viewer-bound and scope-limited; independent per segment to support caching.

5) APIs (interface descriptions, not code)
5.1 Discovery
•  GET /v1/catalog/search: query content registry; localized fields.
•  GET /v1/titles/{title_id}: metadata, manifest summary, preview policy.

5.2 Requirements broker
•  POST /v1/requirements/offer
◦  Input: title_id, viewer binding, locale.
◦  Output: Policy (current), localized UX strings, estimated unlock scopes per path.
•  POST /v1/actions/start
◦  Input: requirement type + params; returns challenge (e.g., email token, puzzle config).
•  POST /v1/actions/complete
◦  Input: challenge response; returns Attestation or error with retry hints.
•  GET /v1/attestations/{id}
◦  Retrieve status/metadata; idempotency support.

5.3 Key brokering
•  POST /v1/keys/request
◦  Input: title_id, requested segment_ids/time window, Attestations[], viewer binding, device signals (optional).
◦  Flow: CDF validates signatures/expiry/issuer reputation → forwards to creator Key Agent.
◦  Output: KeyGrants[] or reasons (unsatisfied policy, trust too low, rate limit).
•  POST /v1/keys/revoke (creator-initiated)
◦  Input: grant_id(s), reason; propagates revocation to caches/clients (short cache TTLs).

5.4 Caching/edge control
•  GET /v1/caching/hints
◦  Output: public popularity hints, creator prefetch directives (e.g., “intro segments cacheable”).
•  POST /v1/caching/register
◦  Edge registers capabilities/regions; receives prefetch directives for opted-in titles.

6) Data model (conceptual fields)
•  Creator: id; public keys; payout endpoints (non-custodial); issuer allow/deny lists; locales.
•  Title: uid; manifest (ordered segment GUIDs, durations); metadata (title, description, tags, language, captions); Policy; preview assets.
•  Segment: guid; size; checksum; storage URLs; encryption info (wrapped CEK reference); popularity counters (privacy-preserving).
•  Policy: list of Requirement entries (type, params, min_trust, optional weights); grants definition; caps/windows.
•  Attestation: see section 4.3.
•  KeyGrant: see section 4.4.

7) Playback and unlock flows
7.1 Publish
•  CEA segments → encrypts → uploads → registers metadata/Policy with CDF; optionally seeds P2P swarm.

7.2 Discover and preview
•  Viewer browses catalog; may play preview or first segment if allowed by Policy (keyless or pre-authorized key).

7.3 Fulfill requirements (non-card)
•  Viewer selects a path (goodwill, puzzle, email, social like, crypto receipt, ad watch, allowlist).
•  Broker coordinates selected verifier adapter(s); returns Attestations with calibrated trust.

7.4 Unlock and stream
•  Client requests KeyGrants for next N segments; submits Attestations.
•  Key Agent verifies and evaluates Policy; issues short-lived KeyGrants bound to viewer and segment scope.
•  Client fetches encrypted segments via P2P/HTTP; decrypts and plays; continues rolling window.

7.5 Edge/ISP caching (optional)
•  Encrypted segments cached; keys never stored at edges.
•  Creators may pre-authorize intro segment keys for instant start in selected regions/ISPs.

8) Security, privacy, and abuse controls
•  Signatures everywhere: creator-signed metadata/manifests, verifier-signed Attestations, creator-signed KeyGrants.
•  Binding: all claims bound to viewer public key + content nonce; mitigate replay and cross-title reuse.
•  Trust and reputation:
◦  Per-verifier trust scores; system-wide issuer reputation; creator-configurable min_trust.
◦  Attestation revocation list with short TTL caching.
•  Rate limiting and quotas:
◦  Per-viewer/device/IP cooldowns and caps (e.g., goodwill limited to first 2 segments).
◦  Bot/automation detection signals; anomaly detection for farms/fake likes.
•  Watermarking (optional):
◦  Per-grant watermark salt; client composites subtle marks to deter redistribution.
•  Minimal PII:
◦  Email stored hashed with creator salt; social handles optional pseudonyms; device bindings rotate periodically.

9) Internationalization and accessibility
•  All UI strings available in localized bundles; right-to-left support.
•  Clear disclosure of requirements and estimated unlock scope before action.
•  Captioning/subtitles pipeline; creator uploads or auto-ingestion.

10) Observability, reliability, and SLAs
•  Anycast API front doors; health-based routing across active-active regions.
•  Stateless, idempotent endpoints with idempotency keys.
•  Metrics/logs/tracing with privacy-by-design; creator dashboards (latency, completion, unlock conversions, revenue proxies).
•  SLA targets:
◦  Control-plane APIs ≥ 99.99% monthly; metadata registry multi-region replicated.
◦  Verifier adapters: soft-SLA with degradation paths (fallback to alternative requirements).

11) Scalability and cost posture
•  Long tail: HTTP fallback + small swarms.
•  Hits: large swarms + edge caches for encrypted segments; intro pre-authorization for fast start.
•  Policy-guided segment sizing and grant TTLs to optimize unlock cadence and CDN cacheability.
•  Creator cost calculators for storage/egress and “verification friction vs. conversion” insights.

12) Governance, moderation, and compliance
•  CDF stores pointers and policies—not the content; creators remain custodians.
•  Abuse reporting on metadata/previews; automated scans of metadata/art only.
•  Jurisdictional flags to help creators apply geofencing/time windows.
•  Notice workflows: notify creators; creators decide to delist/relocate.

13) Extensibility
•  New requirement types require:
◦  Schema/params definition, verifier adapter registration, localized UX copy, and Policy evaluation support.
•  New transports (e.g., WebTransport) and new chains/wallets (for crypto receipt) pluggable via adapter contracts.

14) Open questions and risks
•  Proof-of-attention standardization without invasive tracking.
•  Handling refunds/chargebacks for non-custodial crypto and goodwill/puzzles.
•  Legal posture of metadata pointers in restrictive jurisdictions.
•  Offline playback UX with expiring, per-segment keys and portable Attestations.
•  Incentive design for edge/ISP caches vs. creator directives.

15) Minimal interoperability contracts (non-code summary)
•  Identity: viewer keypair abstraction with device binding; DIDs acceptable but not required.
•  Attestation envelope: JOSE/COSE-signed object containing issuer, subject binding, content scope, expiry, nonce, and proof blob.
•  KeyGrant envelope: creator-signed object binding viewer, scope, expiry, and envelope-wrapped CEKs.
•  Policy evaluation: deterministic, side-effect-free Boolean evaluation with optional weighted scoring; produces explicit reasons on failure.
•  Verifier registry: directory of issuer identifiers, supported requirement types, trust calibration method, and status.

If you want, I can convert this into a formal, implementation-agnostic OpenAPI outline (endpoints, fields, error codes) and a short glossary, still without including any code.
