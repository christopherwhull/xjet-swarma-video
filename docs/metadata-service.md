# Central Metadata Service

**Status: service definition; implementation and wire-level API are not yet delivered.**

This document defines the first centralized metadata service for xjet-swarma-video. It is an index and discovery service, not the owner of publisher content, the authority for viewer trust, or the media delivery network.

## Purpose

The service gives publishers one place to publish discoverable records and gives clients documented ways to search those records and resolve current media locations. It is one discovery source among many. Direct links and later independent indexes must remain viable.

The first release is a single centrally operated directory designed to be replaceable. Publisher-signed records, stable identifiers, documented interfaces, and portable data formats provide a path to independent indexes later; federation is not part of this first release.

## First-release scope

The directory indexes:

- Publisher profiles, stable publisher identifiers, and public verification keys.
- Publisher-supplied video metadata, such as title, description, tags, language, duration, warnings, disclosures, and references to previews.
- Publisher-signed manifest records or references to publisher-hosted signed manifests, including immutable version identifiers and integrity information.
- Expiring location advertisements for publisher-controlled origins and verified replicas, including supported transport and the version each location can serve.

Captions, transcripts, reviews, and collections are deferred from the first directory release. The service does not store or deliver video bytes; preview references do not make it a media host.

## Authority and data boundaries

| Data or decision | Authority | Service responsibility |
| --- | --- | --- |
| Publisher identity and authored metadata | Publisher signing key | Verify signatures, retain the signed source record, and index its permitted fields. |
| Manifest and media integrity claims | Publisher signature and referenced immutable version | Validate structure and consistency; never infer that a record grants copyright or viewing permission. |
| Origin and replica locations | Publisher or authorized operator | Record the claim, check freshness and readiness, and return only currently valid locations. A location is not proof of permission to watch. |
| Corrections, warnings, and moderation actions | Authorized service operator under published policy | Publish separately attributed, versioned overlays. Do not silently rewrite the publisher-signed source. |
| Viewer trust, subscriptions, and local discovery preferences | Viewer | Do not infer or store them in the public directory. Clients apply their own trust rules. |
| Unlocks, decryption keys, payment proofs, and private viewing histories | Publisher Key Agent or the applicable private service | Keep them outside public discovery records and responses. Discovery does not grant access. |

Operator overlays must identify the issuing authority, reason or policy basis, applicable record/version, and update state. A client must be able to distinguish publisher-authored content from operator-authored annotations.

## Record lifecycle

1. **Publish:** An authorized publisher submits a signed, versioned record. Updates are authenticated and idempotent; stale revisions and forged ownership changes are rejected.
2. **Validate:** Check the signature, schema, version relationships, and manifest consistency. Any location probes must be constrained and must not turn registration into an arbitrary server-side fetch proxy.
3. **Index:** Build searchable projections from records the publisher chose to share. Keep derived search fields separate from the signed source and preserve provenance.
4. **Discover:** Clients read public records through documented search and lookup interfaces. Read access does not confer publisher trust, posting rights, key access, or payment authority.
5. **Resolve:** Return fresh locations for a specific immutable media version. Location claims expire and are refreshed independently of stable publisher and title identifiers. Do not publish long-lived storage credentials or viewer-specific signed URLs.
6. **Withdraw:** Record publisher withdrawals, ownership-key changes, and operator removals as attributable state changes or tombstones. Propagate them to derived indexes and caches; returning origins must not revive withdrawn versions.

If the directory is unavailable, clients may use cached, verified records only within their applicable freshness, safety, quota, and grant constraints. Expired locations are not valid fallback endpoints. Directory failure must not bypass access checks.

## Client-facing interface

The initial contract needs four interface families:

- **Publisher writes:** create and update publisher and video records; refresh or withdraw locations; retrieve publication status and validation errors.
- **Search and lookup:** search permitted public fields; fetch publisher and video records by stable identifier and version.
- **Location resolution:** request current endpoints for a specific signed manifest/version and transport.
- **Change feed:** retrieve paginated changes, revisions, and tombstones so local catalogs can update without treating the directory as their source of trust.

These are interface requirements, not finalized routes or schemas. Before client implementation, define request/response schemas, signature envelopes, pagination and cursor behavior, authorization, error semantics, rate limits, and compatibility/versioning rules.

## Operational model

Managed and self-hosted deployments use the same service behavior, API, and data model. The project will document and test a reference self-hosted high-availability topology. That is a supported deployment target, not a blanket uptime guarantee for arbitrary self-hosted installations.

The agreed availability objective is **99.5% monthly** for the metadata service in a qualifying reference deployment. This corresponds to about 3 hours 36 minutes of downtime in a 30-day month. It is an engineering target, not a customer SLA. The exact availability measurement, endpoint scope, and exclusions still need definition.

Recovery time will be measured during the pilot before an RTO is set. The data-loss objective (RPO), database and search technology, reference topology, monitoring requirements, backup retention, and upgrade procedure remain open.

### Candidate implementation approach

These are implementation proposals, not yet selected technologies:

- Keep the API stateless so multiple instances can serve requests.
- Use a portable durable record store; begin with its built-in text search rather than operating a separate search cluster until measured needs justify one.
- Keep publisher-signed records, operator overlays, and derived search/location state distinguishable and recoverable.
- Keep large manifests publisher-hosted where practical; store signed references and necessary discovery fields centrally.
- Provide managed and self-hosted deployment profiles without making the API or data model depend on one cloud vendor.
- Design the service as a metadata control plane, not a video CDN. Public-read traffic and cached preview egress are cost drivers to measure; media delivery remains on publisher origins and authorized replicas.

## Acceptance checks

Before calling the service ready for client integration, demonstrate that:

- A publisher can publish, update, and withdraw signed records; clients can search and resolve them by stable identifiers.
- Forged signatures, stale revisions, inconsistent manifest versions, and unauthorized writes are rejected with explicit errors.
- Operator corrections and safety actions are visible as attributed overlays without altering publisher-signed records.
- Location records expire and refresh independently; clients do not receive expired locations as current endpoints.
- Change feeds propagate updates and tombstones, and withdrawn records are not restored by a returning origin.
- Public responses contain no decryption keys, private trust lists, payment credentials, or per-viewer histories.
- Cached-record behavior during a directory outage respects freshness and access controls.
- The documented self-hosted reference topology passes failover, backup-restore, and upgrade tests against the defined availability measurement.

See also [the full architecture design](design.md#metadata-library) and [MVP open questions](../openquestions.md).
