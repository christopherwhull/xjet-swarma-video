> Generated from [docs/design.html](design.html). Edit the HTML source, then run `pwsh -NoProfile -File scripts/Sync-GitHubDocs.ps1` from the repository root.

<a id="xjet-swarma-video"></a>

# xjet-swarma-video

[Executive overview — what the video publisher provides](overview.md)

High-level design — total solution · journey-first · §§ in reading order

[Original video goals vs our design delivery — timestamped comparison and gaps](video-comparison.md)

Product concept: **xjet-swarma-video** · creator-owned storage & keys · pennies-per-view · multi-ISP encrypted delivery

Decentralized publishing · creator-owned storage & keys · verification-agnostic access · hybrid P2P/HTTP delivery · ISP/edge ciphertext caching & incentives

<a id="contents"></a>

## Contents

Ordered for **creator** and **viewer** journeys first; implementation contract last. Section numbers (§) follow reading order (Parts A–E).

[**Executive summary** — what the product does](#executive-summary)

1.  Part A — Frame
    1.  [§1 Purpose and scope](#s1)
    2.  [§2 Core principles](#s2)
    3.  [§3 Architecture one-liner](#s3)
    4.  [§4 Primary components](#s4)
    5.  [§5 Business order & multi-ISP cache-fill model](#s5)
2.  Part B — Creator experience
    1.  [Creator journey](#journey-creator)
    2.  [§6 Content creator role](#s6)
    3.  [§7 Live vs VOD + media object model](#s7)
    4.  [§8 Requirements and attestations](#s8)
    5.  [§9 Creator monetary experience](#s9)
    6.  [§10 Key Agent availability & delegation](#s10)
    7.  [§11 ISP / edge cache incentives](#s11)
3.  Part C — Viewer experience
    1.  [Viewer journey](#journey-viewer)
    2.  [§12 Identity, recovery, multi-device](#s12)
    3.  [§13 End-to-end flows](#s13)
    4.  [§14 Internationalization and accessibility](#s14)
    5.  [§15 Viewer feedback & content review](#s15)
    6.  [§16 Account watch quotas](#s16)
4.  Part D — Network, trust & operations
    1.  [§17 CDF business, funding, ToS & trust-safety ske…](#s17)
    2.  [§18 Governance, moderation, compliance](#s18)
    3.  [§19 Security, privacy, abuse](#s19)
    4.  [§20 Observability, reliability, SLAs](#s20)
    5.  [§21 Scalability and cost posture](#s21)
5.  Part E — Build contract
    1.  [§22 Data model](#s22)
    2.  [§23 APIs](#s23)
    3.  [§24 Interoperability contracts](#s24)
    4.  [§25 Extensibility](#s25)
    5.  [§26 Architecture diagrams](#s26)
    6.  [§27 Glossary](#s27)
    7.  [§28 MVP roadmap](#s28)
    8.  [§29 Open questions and risks](#s29)

<a id="executive-summary"></a>

<a id="executive-summary-what-this-product-does"></a>

## Executive summary — what this product does

A creator-owned video network where artists keep their files and keys, fans unlock with fair free paths or **pennies per view**, and the open internet—plus many ISPs—delivers the bits fast. We coordinate discovery, trust, and cashflow visibility. We do not become the next warehouse that owns your library.

<a id="for-creators"></a>

### For creators

Publish from your own storage. Set the door policy. Watch earnings tick when people actually watch. Optionally buy multi-network speed—without surrendering the masters.

<a id="for-viewers"></a>

### For viewers

Find something worth watching. Preview freely when allowed. Unlock with goodwill, a puzzle, an email, a tip of pennies—or whatever the creator asked. Report the worst stuff. Play.

<a id="for-isps-the-network"></a>

### For ISPs & the network

Cache encrypted hits near subscribers. Save transit. Earn on delivery, not by skimming creator pennies. Many networks can warm the same popular title—fairly.

<a id="the-story-in-five-parts"></a>

### The story in five parts

<a id="part-a-—-frame"></a>

<a id="part-a-frame"></a>

## Part A — Frame

**The pitch.** This is not “another YouTube.” It is a network where creators host their own video, keep the keys, and a global fabric only does what a platform must: help people find work, prove a fair unlock, move pennies in the open, and keep the worst content from riding the rails. Part A states the promise, the rules of the road, and who gets paid in what order—so nobody “accidentally” rebuilds a warehouse monopoly.

<a id="s1"></a>

<a id="purpose-and-scope"></a>

## 1) Purpose and scope

- **Goal:** Decentralized, creator-hosted video publishing and delivery. Creators own storage and keys; a neutral coordination fabric handles discovery, access policy, verification of requirements, key release, and optional delivery settlement with ISP/edge caches. Delivery is hybrid P2P + HTTP with optional ISP/edge caching of ciphertext.
- **Out of scope:** Central custody of viewer “payments” or funds meant for access; general-purpose social networking beyond publisher-owned pages and feedback forums (§6.11); long-term DRM escrow of creator master keys; caches holding plaintext or content keys.

<a id="s2"></a>

<a id="core-principles"></a>

## 2) Core principles

- **Creator sovereignty:** Content and encryption keys remain with creators; release is policy-driven.
- **Publisher-owned presence:** publishers define their public page, highlighted videos, and feedback forum. Human-led niche curation and viewer-selected AI discovery are choices, not compulsory platform ranking. See §6.11 and §4.8.
- **Trust before attention:** the viewer owns a local catalog and decides which publisher identities may populate it. Central indexing, publication volume, payment, and popularity do not confer viewer trust. Untrusted publishers do not enter the ordinary feed or autoplay; explicit discovery/review is a separate action (§12.7).
- **No platform commercial injection:** The platform does not insert ads, promotions, or other unsolicited commercial material into the creator–viewer relationship. Quality questionnaires are the only platform-inserted engagement; necessary playback, consent, payment, and safety controls are operational UI, not advertising inventory.
- **Bilateral overlay consent:** Optional overlays remain hidden unless both creator and viewer have explicitly opted in before display. Publication, payment, gift acceptance, or continued playback is not overlay consent. See §7.6.
- **Open storage:** Any S3-compatible store (MinIO, major clouds, USB-backed nodes, etc.).
- **Publisher-operated cloud backup:** every published local-origin title has a verified serving replica on a cloud instance operated and funded by its video publisher. An unplugged appliance must not be the sole source of published media; the CDF does not become the backup host. See [§4.7](#cloud-backup-origin).
- **Hybrid delivery basis:** HLS playlists and HTTPS media delivery, assisted by WebTorrent/WebRTC peers for scale; origin/edge HTTP remains available when peer assistance is absent or disabled. See [§7.7](#webtorrent-hls).
- **Verification-agnostic access:** Access is not “credit card checkout.” Requirements are API-described (goodwill, puzzle, email, social proof, crypto receipt, ad attention, allowlists, etc.). Publishers choose how little or how much to verify.
- **Split ledgers:** *Access attestations / key grants* are separate from *delivery settlement* (ISP cache incentives). Money or credits for bytes delivered never substitute for unlock policy.
- **Minimal trusted core:** Coordination fabric moves metadata, proofs, short-lived key grants, cache hints, and settlement metering—not video plaintext and not custody of access payments.

<a id="s3"></a>

<a id="architecture-one-liner"></a>

## 3) Architecture one-liner

**Creators host and encrypt their own segments; viewers unlock keys by satisfying API-described requirements of the creator’s choosing; a global fabric only catalogs, brokers verification, and relays key grants; optional ISP edges cache ciphertext and earn transit savings and/or metered delivery incentives—never keys and never access-payment custody.**
<a id="s4"></a>

<a id="primary-components"></a>

## 4) Primary components

<a id="creator-endpoint-app-cea"></a>

### 4.1 Creator Endpoint App (CEA)

- Transcode and package HLS multivariant/media playlists with GOP-aligned segments; duration is a product choice. Publish the signed transport mapping described in §7.7.
- Encrypt **per segment** with unique content keys; wrap under creator master key (local KMS/HSM optional).
- Upload encrypted segments + checksums to S3-compatible storage; prefer immutability after publish.
- Push metadata: title, description, tags, language, thumbnails/previews, manifest (ordered segment IDs), **access Policy**, and optional **delivery/cache Policy** (pin sets, rebate budgets, prefetch allow-lists).
- Optional always-on P2P seed for initial swarm health.
- **Key Agent:** evaluates viewer Attestations against access Policy; issues short-lived, viewer-bound KeyGrants. Does not run ISP payouts.

<a id="storage-layer-creator-owned"></a>

### 4.2 Storage layer (creator-owned)

- S3-compatible objects addressed by content_id + segment_id.
- Integrity: per-segment checksum and optional Merkle proofs.
- Access: public ciphertext and/or presigned URLs; edges and peers fetch ciphertext only.
- Local origins replicate published assets to the publisher-operated cloud backup origin before a title version is marked ready (§4.7).

<a id="coordination-discovery-fabric-cdf"></a>

### 4.3 Coordination & Discovery Fabric (CDF)

- Global, active-active, largely stateless control plane; target high uptime; UI/strings aimed at many locales (~250 languages as a product goal).
- **Content registry:** creator-signed metadata, manifests, access policies, segment location pointers (not media bytes).
- **Metadata and location libraries:** searchable publisher/page/title records plus verified, expiring origin/replica endpoint advertisements; resolve where authorized clients can fetch media without owning or decrypting it (§4.8).
- **Discovery / offer catalog:** publisher-selected shared records and search/change feeds for viewer-owned local catalogs; clear unlock disclosures, no compulsory global recommendation feed (§12.7).
- **Verification broker:** pluggable verifier adapters → signed Attestations; publisher-defined depth of checking.
- **Key request broker:** relays key requests to creator Key Agents; returns KeyGrants or structured failure reasons.
- **Edge registry & delivery control:** register ISP/edge nodes; publish popularity hints, pin/prefetch manifests, delist streams; meter Proof of Delivery; optional settlement credits (separate from attestations).
- **Analytics:** centralized collection of playback and interaction events; creator and platform operator share aggregate overviews, while per-viewer detail is encrypted for the relevant creator only. See §20.1.

<a id="viewer-applications"></a>

### 4.4 Viewer applications

- Local catalog, explicit publisher trust/block list, provenance-aware imports, and viewer-authorized agents reviewing eligible content (§12.7).
- HLS playback with a WebTorrent/WebRTC peer-assisted segment loader, limited to permitted content/segment swarms (§7.7).
- HTTPS startup and fallback: creator origin and/or edge caches, without requiring a healthy swarm.
- Requirements UX: goodwill, puzzle, email, social, crypto receipt, ad watch, allowlist, etc.
- Attestation handling: bind actions to viewer identity and content scope.
- Secure playback: keys in platform keystore/TEE where available; decrypt in memory.
- Optional delivery receipts (sampled) to support honest cache settlement.

<a id="pluggable-verifier-adapters"></a>

### 4.5 Pluggable verifier adapters

- Email, puzzle/PoW, social interaction, crypto receipt (on-chain/L2/LN etc.), ad attention, allowlist/subscription/NFT-gate, and future types.
- Each returns a standard Attestation with calibrated `verifier_trust`.
- Creators may use network verifiers or self-hosted issuers they trust more or less.
- **No requirement that verifiers be ISPs;** an ISP may optionally offer a verifier product, but that is not cache settlement.

<a id="isp-edge-cache-operators"></a>

### 4.6 ISP / edge cache operators

- Store and serve **encrypted** segments (and public previews).
- Optional prefetch of creator-allowed segment sets (e.g. first minute / “good parts”).
- Optional stable P2P seeding for whitelisted content.
- Never store content keys; never evaluate access Policy unless they separately run a verifier.
- Participate in **Delivery Credits / rebates** when creators fund them; otherwise operate on transit-savings alone.

<a id="cloud-backup-origin"></a>

### 4.7 Publisher-operated cloud backup origin

**Availability requirement:** the video publisher runs a separate, always-on cloud instance as a warm, serving backup for their local origin, in their own cloud account with their own billing and administrative control. This is a required origin replica, not an optional ISP cache, a restore-only archive, or storage owned by CDF. Losing local power or connectivity triggers media failover to this instance.

- **Complete serving copy:** replicate each published VOD version's ciphertext segments, HLS playlists, initialization objects, captions, previews, and signed metadata to the cloud origin, optionally using publisher-controlled object storage behind the instance. Preserve object ids, checksums, key ids, and byte identity across origins so HLS and WebTorrent do not require re-encoding or new grants.
- **Publish gate:** upload immutable objects, verify the cloud copy and off-network reads, then atomically advertise the signed ready manifest and both endpoints. Do not mark a new title/version ready while its cloud copy is incomplete. Show replication progress, last verified version, failed objects, and cloud readiness in the creator console.
- **Failover:** use independently reachable endpoint discovery and off-network probes; the player retries the same verified segment from the cloud endpoint when local requests fail or miss deadlines. Do not rely solely on DNS changes or a redirect served by the failed appliance. Bound retries and test failover within the configured playback-buffer budget; publish measured recovery targets rather than promising zero interruption.
- **Safe failback:** resume local preference only after sustained health and version/integrity checks. Serve immutable published versions while synchronizing; do not let a stale local node overwrite newer metadata or resurrect a withdrawn title. Use backoff to avoid switching repeatedly between unstable origins.
- **Unlock continuity:** media replication does not replicate plaintext keys into public storage. A publisher-controlled cloud Key Agent or separately reachable authorized agent must sustain new grants when the appliance is down, with scoped credentials and creator-controlled key protection (§10). Funding/quota state and revocations must remain authoritative across agent failover; do not double-issue paid credits or bypass limits. CDF and ciphertext-only relays still receive no unwrapped media keys.
- **Operations and cost:** publisher selects the provider, deploys or connects the instance through the wizard, authorizes narrowly scoped credentials, and accepts storage, compute, and egress costs before provisioning. Monitor capacity, certificate expiry, replication lag, billing limits, and regional failures. Alert on loss of backup readiness; if both origins fail, disclose the outage and stop new unavailable paid offers rather than silently provisioning platform-funded capacity.
- **Removal and recovery:** delist, access revocation, and required removal/restriction apply to both local and cloud origins; returning nodes reconcile tombstones before serving. Keep versioned/offline recovery backups separately: a serving replica alone is not protection against accidental deletion, compromise, or mirrored corruption.
- **Live limitation:** replicate live segments as they arrive and disclose lag. Cloud failover can serve only already-received media; continuing a live broadcast after the local encoder loses power needs an independent publisher-operated ingest/encoder path. Do not claim a cloud replica can produce missing live footage.

**Acceptance:** publish a replicated test title, disable peers/edges, unplug the local appliance during playback, and verify continuation and a fresh viewer unlock from the cloud path without duplicate billing. Repeat with local-only Key Agent failure, incomplete replication, expired cloud credentials, both origins unavailable, and local recovery after a delist. Record actual failover time and rebuffering. This remains a design requirement, not a deployed instance.

<a id="metadata-library"></a>

### 4.8 Centralized platform servers — metadata and location libraries

**Executive definition:** the centralized platform servers hold the discovery material each publisher chooses to share: metadata, locations, and optionally closed captions/transcripts, reviews, and collection references. Viewers find publishers through any number of routes and build their own local catalogs; the directory is one source, not the owner of attention or a mandatory feed. A discoverable record does not make its publisher trusted (§12.7).

<a id="what-the-library-contains"></a>

#### What the library contains

| Library record | Information held centrally | Authority and boundary |
|----|----|----|
| Publisher and public page | Stable publisher id, public verification keys, name/about text, page version, public page/forum endpoints, and publisher-authored featured video/collection references | Publisher controls page content and ordering; CDF indexes signed public records, not private forum administration or an ownership claim over the community |
| Video catalog | Title, description, tags, language, duration, captions availability, ratings/warnings, disclosures, and preview/thumbnail references | Publisher supplies metadata and rights declarations; platform may label or delist under published rules, without silently rewriting the signed source |
| Shared captions and reviews | Publisher-selected caption/transcript text or references, language/version, authorized review text/excerpts or links, reviewer attribution, and selection provenance | Sharing is per asset and purpose, with author rights and visibility respected. A publisher's selected reviews are labeled as selected, not a claim to represent all feedback or suppress another publisher's lawful review |
| Media description | Signed manifest/version, renditions and tracks, segment identifiers, ciphertext hashes, public key ids, and WebTorrent/HLS transport references | Enough to select and verify bytes, never the secret keys needed to decrypt them; large inventories can remain publisher-hosted with signed references |
| Locations and readiness | Local and publisher-cloud origin endpoints, authorized replica/edge hints, transport capabilities, health, replica version, last verification, and expiry | Location is a current claim, not proof of ownership, payment, or permission to watch. Publisher-cloud readiness is checked independently of optional caches |
| Viewing offer and unlock service | Public access Policy/version, free/paid offer descriptions, prices/caps, gift availability, verifier choices, and Key Agent endpoint/health | Disclosure and routing only; authoritative unlock remains with publisher Key Agents and payment proofs, never the location directory |
| Discovery and safety state | Search indexes, attributed curated collections, coarse popularity/quality summaries, and separate delist, warning, or jurisdiction status | Distinguish publisher selections, viewer-agent selections, aggregate signals, and network enforcement. No covert paid placement or behavioral viewer dossiers in the public catalog |

<a id="publishing-lookup-and-freshness"></a>

#### Publishing, lookup, and freshness

1.  **Choose what to share:** preview the exact central discovery payload and select metadata, caption/transcript, review, and preview sharing separately. Full captions can disclose a paid video's substance even when its video remains encrypted; explain this before opt-in. Unshared assets remain on the publisher's service and are not silently transcribed, scraped, or sent to third-party AI by CDF. Minimal routing/verification fields are disclosed as required for any chosen registration.
2.  **Register:** publisher signs/version-publishes page, title, offer, and location records; prove control before accepting publisher/domain changes. Use authenticated, authorized updates and idempotency; reject stale revisions and forged ownership changes.
3.  **Verify:** validate signatures, schemas, content/manifest consistency, and off-network origin readiness. Location probes must reject private/internal addresses, unsafe redirects, oversized responses, and arbitrary code; registration is not an open server-side fetching proxy.
4.  **Index:** materialize searchable metadata and public collection references. Maintain provenance and keep operator labels separate from publisher-authored content; a page editor changes their page, not the network's entire catalog.
5.  **Discover and resolve:** the viewer's local catalog or authorized agent queries documented read interfaces for permitted records and fresh endpoints. Apply local publisher trust before normal presentation; unfamiliar publishers remain in a separate, explicitly requested discovery/review workflow. Required grants still govern subsequent media fetching through HLS/HTTPS, WebTorrent, or an eligible edge.
6.  **Refresh:** expire/renew location advertisements, probe actual availability, and record which immutable versions each replica can serve. Use stable ids rather than treating changing IPs or URLs as a new title; do not put long-lived storage credentials or viewer-specific signed URLs in the public index. Mint short-lived fetch URLs through authorized endpoints when needed.
7.  **Withdraw:** propagate removals, tombstones, revoked ownership keys, and policy changes to derived indexes/caches. Returning origins must not re-advertise stale withdrawn versions. If discovery is down, cached verified metadata may support already-authorized playback only within its freshness, safety, quota, and grant constraints; never bypass access checks to hide an outage.

<a id="discovery-choice-and-operational-boundaries"></a>

#### Discovery choice and operational boundaries

- **Human niche curation:** publishers and identified curators can publish attributed, ordered collections of eligible public video references, with subject expertise and selection notes. Preserve the human editor's order when presenting that collection; clearly distinguish it from personalized or algorithmically ranked results.
- **Your agent, your choice:** viewer-selected agents maintain/review the local catalog from trusted feeds and publisher-shared metadata, captions, and reviews. Agents may inspect unfamiliar sources only within the viewer's explicit discovery policy; no model-generated trust decisions silently expand subscriptions. This does not imply a platform AI service or access to private analytics, forum membership, keys, or credentials. Private actions need scoped, revocable authorization.
- **Editorial authority:** publisher controls publisher-page highlights; curator controls their attributed collection; viewer controls personal discovery preferences. An AI-created list must be labeled as agent-selected, not passed off as a human curator's original list. External links/references do not grant rights to republish another creator's media.
- **Central but replaceable:** keep schemas, ids, signatures, pagination, and change feeds documented for interoperable clients and later independent indexes. This does not claim competing portals/federation are implemented; those remain separate roadmap work.
- **Not literally metadata only:** platform servers also operate verification/key relays, rate/quota controls, reports/cases, billing/settlement records as applicable, and the encrypted analytics store (§20.1). Public previews may be cached. Isolate these operational/private stores from the public library; this executive description must not erase their security and privacy obligations or turn CDF into the default media host.

**Acceptance:** publish a signed publisher page and title, discover them through a human collection and a read-only agent client, resolve local/cloud copies, and verify direct encrypted playback. Reject forged page edits, stale/poisoned locations, unsafe probe targets, and unauthorized access to private records. Verify expiry/removal propagation, origin failover, and that discovery responses contain no content keys or per-viewer analytics.

<a id="s5"></a>

<a id="business-order-multi-isp-cache-fill-model"></a>

## 5) Business order & multi-ISP cache-fill model

This section locks the **normative order of money and obligations** and the business model that **encourages multiple ISPs** to cache popular creators without thundering-herd origin pulls or a single-cache monopoly.

<a id="normative-business-order-do-not-invert"></a>

### 5.1 Normative business order (do not invert)

Three ledgers stay separate:

| Order | Flow | Ledger | Purpose |
|----|----|----|----|
| **1** | Viewer → Creator | Access / earnings (§9) | Pennies-per-view (or other requirements). Creator sees pending/available as viewing starts. |
| **2** | Network enforcement | Trust-safety (§15) | Block/pull can remove addressability and future delivery eligibility before more money is spent warming bad content. |
| **3** | Creator → ISPs / edges | Delivery settlement (§11, this section) | Optional pin, prefetch, and hit rebates so *many* ISPs hold and serve ciphertext. |
| **4** | Anyone → CDF | Control-plane fees (§17) | Thin catalog/broker fees only. CDF is not default merchant of record for access pennies. |

**Hard rules:** ISPs do *not* take a default cut of `per_view` pennies. Delivery budgets are not mixed into tip/view balances. Paid multi-ISP fill follows demand (or explicit creator boost)—not unbounded clone bounties. Opt-in micro-ledger (§9) is UX only; sweeps still end at the creator.
<a id="forbidden-inversions"></a>

### 5.2 Forbidden inversions

| Inversion | Why forbidden | Correct order |
|----|----|----|
| ISP cut of viewer pennies | Turns the pipe into access MoR; fights live creator earnings | ISP paid only from delivery ledger / transit value |
| Pay all edges before popularity or lease | Funds cold spam and origin herds | Demand or boost → fill lease → fill → then pay hits/pins |
| CDF custodial access by default | Central cashier gravity | Creator wallet first; micro-ledger opt-in |
| One exclusive ISP cache deal as default | Blocks multi-ISP goal and off-net viewers | Replica targets across ASNs/cells; diversity pay |
| Full prefetch bounty to every clone | Race + overpay identical bytes | Lease winners + hit rebates + capped replicas |
| Big pin spend after S0/S1 block with no stop | Pays to warm unacceptable content | Block list voids new delivery claims; purge ACKs |

<a id="goal-of-the-multi-isp-model"></a>

### 5.3 Goal of the multi-ISP model

- Popular creators become **locally warm on many networks**, not one CDN lookalike.
- Each region/metro gets **fast start** for viewers on-net.
- Creator origin (MinIO/S3/home) sees **bounded** fill traffic.
- ISPs gain **transit savings** plus optional **transparent cash/credits**.
- Second and third ISPs are **paid to exist** (diversity), not punished for missing the first race.

<a id="who-pays-for-multi-isp-cache-sources-of-funds"></a>

### 5.4 Who pays for multi-ISP cache (sources of funds)

| Source | When used | Encourages multiple ISPs? |
|----|----|----|
| **Transit savings only (\$0 budget)** | Default / independents | Yes for truly hot titles—each ISP saves its own transit—but weak for second replica of lukewarm content |
| **Creator delivery budget** (rebate pool, pin, boost) | Popular or strategic catalogs | Yes—primary lever; creator buys multi-homed warmth from earnings or promo funds |
| **Popularity matching pool** (optional CDF/consortium) | Titles above global/regional heat threshold | Yes—tops up diversity replicas when creator budget is thin |
| **Sponsor / public grant** | Education, news, open license | Yes—same delivery ledger, different payer |
| **Viewer pennies** | Never automatically | No direct ISP skim; creator may *manually* allocate part of earnings to delivery budget |

<a id="fair-fill-control-plane-race-coordination"></a>

### 5.5 Fair fill control plane (race → coordination)

Before full origin GET of a cold segment or prefetch pack:

1.  Edge calls fill coordinator: `fill-lease(segment_id | pack_id, fill_cell, asn, tier)`.
2.  **Fill cell** default: metro (fallback country if sparse). Not one global lock.
3.  Grant **K primaries** per cell (default K=1 cold; K=2 when heat high).
4.  Other edges: **FOLLOWER**—peer-fill from HAVE donors or short wait; no origin token.
5.  Primary publishes signed `HAVE` + checksum; followers fan out edge-to-edge / swarm.
6.  Lease TTL + heartbeat; failure reassigns primary.
7.  Blocked titles (§15): leases denied; HAVE invalidated by purge.

Lottery weight example: `integrity² × √free_disk × asn_diversity_bonus × tier_factor`, with per-operator win caps so one fleet cannot vacuum all bounties.

<a id="replica-policy-explicit-multi-isp-targets"></a>

### 5.6 Replica policy (explicit multi-ISP targets)

| Knob | Default intent | Effect |
|----|----|----|
| `replica_target_per_cell` | 1 for warm; 2–3 for hot/popular creator packs | Coordinator *invites* additional ASNs—not only first writer |
| `replica_cap_per_cell` | Small hard max (e.g. 3–4 paid storage slots) | Stops paying for endless identical copies |
| `min_asn_diversity` | ≥2 distinct ASNs for hot intro packs when budget allows | Core “multiple ISPs” requirement |
| `origin_fill_credit` | Once per (object, cell) to lease primary | Compensates origin pull work without cloning bounties |
| `peer_assist_credit` | Small | Rewards edges that upload to followers during fan-out |

<a id="payout-menu-that-favors-many-isps"></a>

### 5.7 Payout menu that favors many ISPs

| Instrument | Paid to | Multi-ISP effect |
|----|----|----|
| **Hit delivery rebate** (\$/GB served with PoD) | Every edge that actually serves viewers | Strong—each ISP earns by serving its own subscribers |
| **Diversity bonus** | 2nd, 3rd, … distinct ASN in cell that maintains HAVE + uptime | Directly pays “be the other ISP” |
| **Storage pin** within replica_cap | Edges holding pin set | Steady multi-home libraries; cap prevents clone farms |
| **Launch / popularity boost** | Lease primaries + diversity invitees for intro pack | Warms many networks at premiere without N× origin |
| **QoE bonus** | Cells meeting join-latency / rebuffer targets | Pays quality, often correlated with local replicas |
| **Seed assist** | Stable swarm seeds | Helps ISPs and neutrals share piece load |

**Do not** pay uncapped “bytes downloaded from origin” or uncapped “bytes stored identical cold objects.” Those recreate the race.

<a id="popular-creator-packages-productized"></a>

### 5.8 Popular creator packages (productized)

| Package | Creator sets | Network does |
|----|----|----|
| **Free speed** | \$0 delivery budget; allow cache | Opportunistic multi-ISP via transit savings only; lease still protects origin |
| **Offset egress** | Monthly rebate pool + \$/GB + cap | All serving ISPs claim PoD hits until cap; natural multi-ISP |
| **Popular multi-home** | Diversity target (e.g. 3 ASNs/metro) + intro pack pin | Invites additional ISPs with diversity bonus until target met |
| **Launch boost** | Time-boxed budget for premiere window | Coordinated multi-cell fill of preview/first-minute pack |
| **Catalog pin** | \$/GB-month for title set | Replica_cap slots assigned across operators for fairness over time |

Funding path for popular creators: **earnings sweep (§9) → optional auto-allocate % to delivery budget** (creator toggle, e.g. “send 10% of available view pennies to multi-home cache”). Never silent.

<a id="optional-popularity-matching-pool"></a>

### 5.9 Optional popularity matching pool

- CDF or ISP consortium funds matching when `heat` exceeds threshold and creator enabled matching.
- Match pays **diversity slots and intro HAVE**, not unlimited storage.
- Transparent rules; same PoD and purge obligations as creator-funded spend.
- Prevents only the largest creators from being multi-homed.

<a id="isp-value-proposition-why-join"></a>

### 5.10 ISP value proposition (why join)

- Less upstream transit on hit titles.
- Cash/credits for hits + diversity + pins without negotiating one-off CDN contracts per creator.
- Standard fill-lease + purge API; settlement statements.
- No content keys; lower legal surface than hosting plaintext.
- Compete on QoE for their subscribers; multiple winners per metro.

<a id="creator-value-proposition"></a>

### 5.11 Creator value proposition

- Viewer pennies still land on the earnings ticker first.
- One budget controls “how warm am I on many ISPs,” separate from unlock price.
- Origin egress predictable under leases.
- Can stay \$0 delivery and still allow opportunistic multi-ISP on breakout hits.

<a id="end-to-end-sequence-popular-title"></a>

### 5.12 End-to-end sequence (popular title)

1.  Viewers pay/fulfill → creator ledger ticks (§9).
2.  Heat crosses threshold and/or creator enables Popular multi-home / boost.
3.  Delivery policy advertises intro pack + replica_target + budgets.
4.  Fill leases elect primaries per cell; origin pull bounded; HAVE fans out to other ISPs.
5.  Diversity invites fill remaining ASN slots.
6.  Viewers hit local edges; PoD → hit rebates to *each* serving ISP.
7.  If pulled for trust-safety: purge, deny leases, stop delivery claims.

<a id="settlement-math-illustrative-not-tariff"></a>

### 5.13 Settlement math (illustrative, not tariff)

- `hit_pay = served_GB × rebate_rate × integrity_multiplier`
- `diversity_pay = flat_or_daily × asn_rank_weight` for ranks 2..N under target
- `pin_pay = GB_held × pin_rate` if within cap and probe-verified
- `origin_fill_pay = fixed` once per (object, cell) primary success
- All subject to creator/matching `budget_cap`; unpaid cache may continue for transit savings

<a id="roadmap-placement"></a>

### 5.14 Roadmap placement

- **Phase 1:** creator pennies + ticker; opportunistic cache allowed; no paid multi-ISP required.
- **Phase 2:** fill-lease + HAVE gossip (even at \$0) to protect origins.
- **Phase 3:** PoD, hit rebates, diversity bonus, popular multi-home packages, optional matching pool.

Business order on the roadmap matches cash order: **creator money UX before paid multi-ISP market**.

<a id="apis-descriptive"></a>

### 5.15 APIs (descriptive)

- `POST /v1/cache/fill-lease` / heartbeat / complete
- `POST /v1/cache/have` — signed HAVE advertisements
- `GET /v1/cache/donors` — peer-fill candidates in cell
- `GET /v1/delivery/policy/{title_id}` — replica targets, budgets, packs
- `POST /v1/delivery/claims` — hit, diversity, pin, origin_fill, assist
- `POST /v1/creator/delivery-budget` — allocate from earnings % or top-up
- Block/purge channels from §15 override leases and claims

<a id="success-metrics"></a>

### 5.16 Success metrics

- Median distinct ASNs holding intro pack for top-N titles per metro.
- Origin GB / served GB ratio falling as heat rises.
- Fill-lease wait time and primary failover rate.
- Fraction of delivery spend on diversity vs pure duplicate storage.
- Creator retention on “multi-home” packages vs free speed only.

<a id="part-b-—-creator-experience"></a>

<a id="part-b-creator-experience"></a>

## Part B — Creator experience

**Make it. Price it. Get paid when they watch.** Ship from your bucket or a USB-backed MiniO box. Choose free doors or penny doors. See the balance move as views start—not in a mystery month-end envelope. Stay unlock-online even when your laptop sleeps. When a title breaks out, spend a clear delivery budget so many ISPs warm your intro—not a hidden cut of your tips. You own the library. You own the relationship. You own the upside.

<a id="journey-creator"></a>

<a id="creator-journey-day-one-to-steady-state"></a>

## Creator journey (day-one to steady state)

This is the creator-facing path through the system. Detailed mechanics live in the linked sections.

1.  **Act as content creator** — publish video and expect payment ([§6](#s6)).
2.  **Set up the creator appliance** — install or flash a supported device, complete the guided connectivity and recovery checks, then publish without terminal commands. [§6.10](#turnkey-appliance)
3.  **Establish identity & org** — creator root keys, optional team roles (Owner, Publisher, Policy, Key Operator, Finance, Moderator). [§12](#s12)
4.  **Run CEA** — transcode, segment, per-segment encrypt, upload to your S3/MinIO, optional seed. [§4.1](#s4), [§7](#s7)
5.  **Publish metadata** — title, preview pack, manifest, content warnings. [§7](#s7), [§13.1](#s13)
6.  **Set access Policy** — free paths (goodwill, puzzle, email, …) and/or paid penny paths. [§8](#s8)
7.  **Set money defaults** — e.g. ~\$0.02/view after a few seconds, optional per-minute, session cap; watch the live ticker as plays start. [§9](#s9)
8.  **Keep unlock online** — local Key Agent or delegated agents with health on the title page. [§10](#s10)
9.  **Optional delivery spend** — free speed, offset egress, popular multi-home, launch boost; never an automatic ISP cut of pennies. [§11](#s11), [§5](#s5)
10. **Operate** — analytics, strikes/notices, appeals, payout sweeps. [§20](#s20), [§15](#s15), [§9](#s9)

**Creator promise:** you host the bytes and keys; you set the unlock rules; you see pennies when paid viewing starts; multi-ISP warmth is an explicit delivery budget, not a hidden platform skim.
<a id="s6"></a>

<a id="content-creators-and-publishers-media-and-recommendations"></a>

## 6) Content creators and publishers (media and recommendations)

A **content creator** (also: publisher) is a person or organization that **puts video on the network** and **expects to be paid** when viewers unlock and watch—normally in **pennies-scale** earnings that appear as viewing starts— while retaining ownership of storage, encryption keys, and unlock policy.

**Publisher is the broader distribution role:** a user who shares recommendations or reviews also publishes under their own identity, from a local or cloud setup (§6.12). They need not create, host, or earn money from the referenced videos. Media creators retain the rights, keys, access rules, and earnings for their own work; recommendation publishing does not transfer those rights.

<a id="who-counts-as-a-content-creator"></a>

### 6.1 Who counts as a content creator

- Individuals, studios, educators, brands, or collectives that **origin-publish** titles.
- Recommendation/review publishers are a distinct publishing mode (§6.12); media-specific bucket, Key Agent, and payout duties apply only when they also publish media or offers requiring them.
- Media origin-publishers operate (or authorize) a **Creator Endpoint App (CEA)**, origin bucket, and Key Agent path.
- Media origin-publishers hold a **creator root identity** used to sign manifests, policies, and KeyGrants (or Delegation Grants); recommendation publishers sign their own records without acquiring media-key authority.
- They are **not** merely viewers, ISP edge operators, verifiers, or CDF operators—though one human may wear multiple hats with separate identities.

<a id="core-job-to-be-done"></a>

### 6.2 Core job to be done

| Job | What “done” looks like |
|----|----|
| Publish | Encrypted segments on creator-controlled storage; catalog shows title, preview, unlock offer |
| Price access | Policy lists free and/or paid paths; penny defaults clear to fans |
| Get paid | Ledger ticks pending to available as paid viewing starts; sweeps to creator destinations |
| Stay open | Key Agent healthy (local or delegated); title shows unlock status |
| Optionally go wide | Delivery budget / multi-home for ISPs—without skim of view pennies |
| Good standing | Respond to notices; honor pulls; accurate metadata |

<a id="rights"></a>

### 6.3 Rights

- **Custody of masters** — choose origin storage (MinIO, cloud S3, etc.).
- **Own the public presence** — define page content, featured videos, collections, and feedback forum rules/data portability (§6.11).
- **Custody of keys** — master keys stay creator-controlled; CDF never holds unwrapped content keys.
- **Policy and pricing sovereignty** — requirements, pennies, free paths, grant windows.
- **Payout sovereignty** — creator wallets/endpoints; no default platform MoR on access value.
- **Delegation** — Key Agents, team seats, delivery budgets without surrendering root ownership.
- **Delist / relocate / appeal** — control catalog presence and contest moderation outcomes.

<a id="responsibilities"></a>

### 6.4 Responsibilities

- Only publish content they have rights to distribute.
- Accurate metadata, previews, and content warnings.
- Reachable unlock path (Key Agent) when promising paid or gated viewing.
- Operate and fund a verified cloud backup origin for published local-origin content, including an unlock path that survives local appliance failure (§4.7).
- Trust-safety notice response; origin removal when a pull requires it.
- Correct payout setup; understand pending vs available vs reversed.
- Fund multi-ISP delivery budgets explicitly if used.
- Secure creator root keys and recovery; rotate on compromise.

<a id="payment-expectation-normative"></a>

### 6.5 Payment expectation (normative)

**Creators expect money when fans watch paid paths—not a black-box monthly surprise.** Default promise: micropayments (pennies per view / minute / small unlock), live ledger visibility, sweep to creator-controlled rails. Free paths may pay \$0 access value unless a sponsor subsidy exists.

- **Trigger:** paid watch start / meter ticks under a funded session.
- **Visibility:** pending within seconds; available after rail finality.
- **Not automatic:** ISP rebates and CDF fees are separate from view pennies.
- **Payment is not infinite farm rights:** viewer daily watch quotas still apply.

<a id="role-vs-team-seats"></a>

### 6.6 Role vs team seats

Content creator is the **economic principal**. Work may split across org seats:

| Seat | Duties |
|----|----|
| **Owner** | Root identity, recovery, payout endpoints, final authority |
| **Publisher** | Upload, manifests, metadata, previews |
| **Policy Editor** | Access requirements, penny prices, previews |
| **Key Operator** | Key Agent health, delegation, rotation |
| **Finance** | Ledger, sweeps, delivery budgets, tax exports |
| **Moderator liaison** | Notices, strikes, appeals, takedowns |

Solo creators wear every seat; larger teams separate Key Operator from Policy Editor.

<a id="what-creators-are-not"></a>

### 6.7 What creators are not

- Not the CDF (unless also operating fabric under another role).
- Not ISPs by default (may self-seed P2P).
- Not forced into ads-only monetization.
- Not promised legacy-platform RPM parity—only a fair pipe and honest ledgers.

<a id="lifecycle"></a>

### 6.8 Lifecycle

1.  **Onboard** — creator root; optional verification; payout endpoints.
2.  **First publish** — CEA pipeline; free and/or penny template.
3.  **First earnings** — confirm ticker and sweep.
4.  **Operate** — policy, multi-home, fans, notices.
5.  **Pause / exit** — delist, revoke agents, final sweep, retire keys.

<a id="success-metrics-1"></a>

### 6.9 Success metrics

- Time from publish to first paid view credit.
- Share of available balance swept successfully.
- Key Agent / unlock-path uptime.
- Explainable eCPMv (earnings per thousand paid views).
- Notice SLA met; low reverse rate.

<a id="turnkey-appliance"></a>

### 6.10 Turnkey creator appliance

**Product requirement:** a nontechnical creator can turn a supported old PC or small single-board computer into a creator-owned video appliance through an installer or prebuilt image and a browser-based setup wizard. The appliance manages CEA, local storage, publishing, and the selected Key Agent mode; creators should not need to configure S3, certificates, containers, or command-line services to publish.

<a id="supported-hardware-and-installation"></a>

#### Supported hardware and installation

| Profile | Design target | Release requirement |
|----|----|----|
| Existing PC / mini-PC | 64-bit x86 device with supported local disk and network adapter; guided installer or dedicated appliance image | Publish tested CPU/RAM/free-space requirements, OS versions, and separate limits for serving and transcoding |
| Small ARM appliance | Selected 64-bit Raspberry Pi-class boards with supported power supply, boot media, and USB/SSD library storage | Publish exact supported board models/revisions, memory, storage, and image versions; do not claim support for every ARM board |
| Network and storage | Wired Ethernet recommended; supported Wi-Fi permitted after a connectivity check; creator-selectable library disk | Measure usable upload, storage health/capacity, sustained reads/writes, and a representative encode; show realistic concurrency and processing estimates |

These are support targets, not certified hardware or benchmark results. A release must ship a versioned support matrix and reject unsupported configurations with a plain-language explanation. Low-powered devices may serve pre-encoded content; offer a supported desktop preparation path or explicitly authorized external transcoding rather than promising real-time 4K encoding on every board.

- **Safe installer/image:** signed downloads and checksums; guided target-disk selection and explicit confirmation before formatting or overwriting. Preserve existing user files by default; offer a non-destructive install where supported. Never silently repartition an old PC or reuse a library disk as boot media.
- **First-run wizard:** discover the appliance locally, establish secure authenticated administration through physical/local pairing, choose storage, create or recover creator identity, verify an encrypted recovery backup, connect the publisher-operated cloud backup instance (§4.7), test media/unlock failover, and select a free or paid publishing template. Explain provider costs before activation; without a ready cloud replica, keep local imports as drafts rather than ready published titles.
- **Publish experience:** upload a video through the browser, edit title/thumbnail/captions and access rules, preview, then publish. Show preparation progress, resumable failure handling, readiness checks, and an externally usable watch link. Initial setup does not require monetization or a funded delivery budget.

<a id="connectivity-and-availability-fallback"></a>

#### Connectivity and availability fallback

- **Probe before claiming online:** test local access and independent off-network media and Key Agent reachability. Detect changing public IP, carrier-grade NAT, blocked inbound ports, certificate failures, and inadequate upload; dynamic DNS alone is not a reachability solution.
- **Direct mode:** automate supported address updates and TLS issuance/renewal. Router changes or port mapping require explicit permission; never expose the administrative interface to the public internet by default.
- **Fallback:** use the required publisher-operated cloud backup origin for local outages (§4.7). An optional outbound authenticated tunnel can additionally make a live local appliance reachable behind NAT, but never substitutes for the cloud copy. Disclose providers, availability, bandwidth caps, and cost; no silent billable fallback. A ciphertext-only media relay receives no content keys and is not the CDF metadata broker.
- **Honest degradation:** show local-origin, cloud-origin, replication, and unlock health separately. Fail over automatically when the local appliance is unplugged; if cloud media or the independent key path is also unavailable, warn or pause new unavailable paid offers and show actionable recovery. Replication cannot guarantee uninterrupted service through every failure.

<a id="updates-administration-and-recovery"></a>

#### Updates, administration, and recovery

- **Updates:** verify signed release metadata and artifacts, stage updates, check disk space and compatibility, and apply in a disclosed maintenance window with security-update notices. Back up state before migrations; test interrupted power/network and provide a known-good recovery path. Roll back only across compatible state versions; do not silently downgrade to known-vulnerable software.
- **Administration:** unique credentials or passkey enrollment, least-privilege services, health/storage/update alerts, and redacted opt-in diagnostic exports. Remote administration is explicitly enabled and authenticated, not an open dashboard.
- **Recovery:** guide encrypted backup/export of creator identity, media-key envelopes, analytics keys if enabled, manifests, policies, and configuration to creator-selected storage. Keep recovery secrets outside the appliance and test restoration. Configuration/key backup is not a video-library backup; maintain the required serving cloud replica plus a separate versioned recovery-copy policy (§4.7).
- **Replacement device:** restore onto a supported replacement, verify library integrity and ownership, revoke the lost appliance's device/delegation credentials, rebind endpoints, and preserve title identities where possible. Prevent concurrent stale instances from publishing conflicting updates. Lost keys without a valid creator recovery mechanism are not recoverable through a CDF password reset.

<a id="nontechnical-first-publish-acceptance-test"></a>

#### Nontechnical first-publish acceptance test

1.  A participant who does not administer servers starts with a supported blank appliance device or a supported PC containing unrelated files, and follows only the supplied installer/image instructions and wizard. No shell, manual certificate work, or engineer intervention is permitted.
2.  The participant pairs the browser, selects library storage, connects their cloud backup instance with disclosed costs, completes recovery and replication checks, imports a supplied short reference clip, chooses a free unlock template, and publishes a title with a thumbnail only after cloud readiness is verified.
3.  A separate viewer on an external connection discovers or opens the watch link, fulfills the chosen requirement, and plays the encrypted video to completion. Neither a same-LAN-only test nor preview-only playback counts as success.
4.  Repeat on a direct connection and a simulated carrier-grade-NAT/blocked-inbound connection, then unplug the local appliance with peers/edges disabled. Existing playback and a fresh unlock must work from the publisher cloud path without terminal commands. Declining cloud costs incurs no charge and leaves the import as a draft, not a ready published title.
5.  After reboot, confirm persistent identity, catalog, and playback. Exercise a failed/interrupted update and restore onto a replacement device using the recovery kit; confirm unrelated files survive installation and keys remain outside operator custody.

Record unassisted completion rate, active setup time separately from image downloads and encoding, external playback success, fallback cost disclosure, and restore success for each supported profile. Publish the test conditions and pass thresholds before release; a supported profile must pass the functional steps above. No measured usability or performance result is claimed by this design.

<a id="publisher-pages"></a>

### 6.11 Publisher pages, highlighted videos, and owned feedback forums

**Every video publisher has a public home, comparable in purpose to a YouTube channel, but defined by the publisher.** The publisher chooses its content, presentation, highlighted videos, and community rules. CDF indexes the page and its eligible public content; it does not take editorial ownership of the page or forum.

- **Page content:** publisher name, verified identity reference, banner/avatar, about text, announcements, public links, video library, and ordered collections. Use a guided editor and constrained templates; page ownership is not permission to run arbitrary scripts, tracking pixels, or unsafe embeds.
- **Publisher-picked highlights:** choose featured/pinned videos, an introduction, topic shelves, and their order. Clearly label external recommendations and link to the original publisher/offer. The platform must not substitute paid placements or its own recommendations inside publisher-authored highlights. Featuring a title never bypasses its access rules or safety status.
- **Human niche curation:** market these pages as a home for expertise and personally selected work, with attributed collections and selection notes. Publishers may use editorial tools, but automated selections must be disclosed; do not claim all collections are human-selected. Viewers can separately ask their own AI agent to organize discovery (§4.8).
- **Feedback forum:** publisher operates the community space, optionally enabled, with publisher-level and video-linked topics, replies, pinned guidance, and moderation tools. They set posting/join rules, choose moderators, and can lock, hide, remove, or archive discussions under disclosed rules. A page may show public highlights while keeping its forum members-only; a paid video unlock alone grants no undisclosed forum access.
- **Ownership means stewardship and portability:** publisher controls forum hosting, configuration, moderation, and lawful export/migration. Contributors retain rights to their own posts subject to disclosed terms; publisher ownership does not mean owning members' identities or unrestricted rights to sell their data. Support author edit/delete requests and applicable privacy/retention duties.
- **Publisher hosting and continuity:** page versions and forum data live under publisher control with cloud continuity (§4.7). Page assets can be replicated like static content; forum writes need an authoritative writer, transactional backup/replay, and fenced failover to prevent split-brain, duplicate posts, or resurrection of deleted content. Show read-only mode during uncertain recovery rather than accepting conflicting writes.
- **Safety and privacy:** sanitize posts/links, rate-limit posting, challenge spam, and provide member block/report and moderator audit trails with scoped roles. Apply network/legal reporting obligations (§15); ordinary forum disagreement is not automatically a network strike. Public post/profile visibility is explicit and separate from private viewer analytics; do not expose watch histories to forum moderators or AI agents.
- **Indexing and consent:** publish only the approved public page/collection metadata and explicitly public, indexing-enabled forum material to discovery. Private threads, member lists, credentials, and moderation logs are not public metadata. Page/forum notices are not injected video overlays; any overlay remains subject to both parties' prior consent.

**MVP acceptance:** a publisher edits and publishes their page, orders featured videos, opens a forum topic, delegates a scoped moderator, and exports/reimports page/forum data with authorship and access controls preserved. Verify another publisher cannot edit it, the platform cannot silently reorder publisher highlights, private discussions remain out of search/agent reads, and cloud failover does not lose acknowledged posts or undo deletions. This defines the feature, not an implemented channel service.

<a id="recommendation-publishing"></a>

### 6.12 Viewers become publishers when sharing recommendations

A viewer who wants to recommend content to another viewer uses their own publishing setup, **local to them or in their chosen cloud account**. The recommendation is a signed record from that user, not an anonymous platform message, an automatic endorsement by the original video creator, or a transfer of viewing keys.

- **Lightweight publishing mode:** create/reuse a publisher identity and operate a small endpoint/feed for recommendations, reviews, and collections. A local client/appliance may publish while reachable; a cloud instance may host the same records without requiring an always-on home PC. Show reachability, queued delivery, and failed sends honestly. No media transcoder, video bucket, payout wallet, or Key Agent is needed just to recommend a title.
- **Scope of infrastructure:** the mandatory cloud media replica (§4.7) applies to locally originated videos, not metadata-only recommendations. If this publisher later hosts media, the normal origin/backup/key obligations apply. A local-only recommendation source may be unavailable while offline; do not represent central indexing as permanent hosting of its private feed.
- **Recommendation record:** signed sender identity, original publisher/title id and optional version, comment/review or selection reason, timestamp/expiry, revision, intended audience, and canonical content location. Recommend the source title; do not rehost another creator's media or publish secret fetch/grant URLs.
- **Recipient control:** private recommendations go only to addressed recipients or an approved audience and are not placed in a public index. Known senders can appear in the recipient's trusted recommendation inbox; unknown invitations remain hidden/quarantined until explicitly inspected. Trust in the recommender does not automatically trust the original publisher or enable that publisher's full catalog.
- **Provenance:** preserve the original video publisher and each recommending publisher as distinct identities. Carry human/agent assistance labels and source references without exposing a private forwarding chain. Paid/sponsored endorsements disclose their relationship; neither endorsement counts nor central popularity override local trust.
- **Trust decision:** the recipient or their explicitly authorized policy accepts a recommendation, then separately trusts the original publisher or approves a named title for one-time inspection. No unsolicited preview/autoplay, purchase, or publisher-wide subscription is implied by receipt.
- **Separate from gifts:** a recommendation is free to publish apart from hosting costs. Attaching a purchased gift uses §9.13 entitlements, normal recipient consent, and new grants. A gift does not buy attention, trust-list placement, or a recommendation notification that bypasses sender blocks.

**Acceptance:** user A publishes a signed recommendation from local mode and then cloud mode; user B receives it under their own trust policy, inspects provenance, and accepts or blocks it. Verify offline queuing, audience isolation, signature/replay checks, no automatic trust of the original publisher, and no copied media keys. Independent review publishing remains possible even when the video's publisher does not feature that review.

**One-liner:** Content creators host and gate video on xjet-swarma-video and expect transparent, near-real-time micropayment when viewers watch—while keeping files, keys, pricing power, and their own public page and community.
<a id="s7"></a>

<a id="live-vs-vod-media-object-model"></a>

## 7) Live vs VOD + media object model

<a id="presentation-modes"></a>

### 7.1 Presentation modes

| Mode | Manifest behavior | Key behavior | Notes |
|----|----|----|----|
| **VOD** | Immutable or versioned complete timeline | Per-segment CEKs; rolling KeyGrants | Primary design center |
| **Live** | Growing window; DVR buffer optional | Keys for recent segments; short TTL | Key Agent must keep up with segment cadence |
| **Live-to-VOD** | Finalize snapshot → new immutable version | Optional re-key or retain live CEKs | Publish as ordinary VOD title version |

<a id="object-model"></a>

### 7.2 Object model

- **Title:** stable uid, metadata, access Policy, delivery Policy, current manifest pointer.
- **Manifest (versioned):** ordered timeline of SegmentRefs; availability window for live; checksum of structure; creator signature.
- **Rendition / ABR ladder:** one or more video renditions (resolution, bitrate, codec) sharing aligned segment boundaries where possible.
- **Audio track:** language, codec, channels; may be muxed per segment or separate segmented tracks.
- **Subtitle/caption track:** language, format (e.g. WebVTT/TTML), forced/SDH flags; can be unencrypted for accessibility if creator allows, or encrypted under separate keys.
- **Segment:** guid, time range, rendition id, storage URLs, size, checksum, key id, optional thumbnail sprite ref.
- **Preview pack:** poster, short clear or pre-authorized clip, chapter list, “good part” segment set for prefetch.
- **Attachment:** chapters, descriptions, content warnings, language of primary audio.

<a id="packaging-principles"></a>

### 7.3 Packaging principles

- GOP/segment alignment across ABR rungs preferred for seamless switching.
- Use HLS playlists over aligned media segments, targeting fMP4/CMAF packaging with a validated HLS encryption profile; no mandatory vendor DRM. WebTorrent transports the same ciphertext as HTTPS (§7.7).
- Client selects rendition by bandwidth/device; KeyGrants authorize segment ids (and optionally rendition families) not raw bitrates alone.
- Captions: default path supports hard-of-hearing; encryption optional so edges can cache accessibility tracks aggressively when public.

<a id="live-specific-rules"></a>

### 7.4 Live-specific rules

- Segment duration short enough for latency targets; Key Agent autoscaling or delegated mode strongly recommended.
- Attestation may unlock a *time window* (“next 2 hours of this live uid”) rather than thousands of individual pre-grants.
- Late join and DVR: Policy states how far back keys are available.
- Publisher feedback forums (§6.11) are a separate page/community surface; real-time live chat remains out of scope unless explicitly added.

<a id="versioning-and-updates"></a>

### 7.5 Versioning and updates

- Edits publish Manifest vN; old versions remain fetchable for open grants until expiry or forced invalidate.
- Re-encode adds renditions without changing title uid.
- Content warning and rating fields are first-class metadata for discovery filters and review (§15).

<a id="embedded-sponsorship-overlays-and-quality-questionnaires"></a>

### 7.6 Embedded sponsorship, overlays, and quality questionnaires

**The creator–viewer relationship is not platform advertising inventory.** CDF, player operators, and ISP/edge nodes must not insert, replace, or splice advertising into the media or use overlays to bypass this rule. The platform may introduce quality questionnaires, not commercial interruptions.

- **Creator-embedded material:** sponsor reads, product placements, and banners already encoded by the creator are part of the published video, not platform injections or optional overlay tracks. Disclose sponsorship; do not promise that payment removes it unless the creator supplies an appropriate alternate edit.
- **Optional overlays:** creator-provided or creator-authorized text/HTML popups are separate presentation metadata, not a new video codec. Bind them to a creator-signed title/manifest version; caches may deliver but never alter or inject them.
- **Two affirmative permissions:** before any optional overlay is shown, require creator authorization and explicit viewer opt-in to the disclosed overlay scope (title/creator, purpose, and categories). Default off; missing, stale, or unverifiable permission means do not display. An initial consent prompt uses neutral player settings, not a preview of the promotional overlay.
- **Withdrawal and changes:** either side can revoke permission; hide active overlays and stop future ones. Material changes outside the agreed scope require renewed consent. Do not treat buying a view, accepting a gift, or choosing another unlock path as implied permission.
- **Safe rendering:** render text and allowlisted HTML formatting through constrained player UI; no scripts, iframes, tracking pixels, automatic navigation, or arbitrary remote resources. Overlays must not imitate payment, gift, safety, or player controls, or obstruct captions and accessibility controls.
- **Quality questionnaires:** clearly identify platform-origin questions about content/playback quality, keep them brief, accessible, dismissible, and frequency-limited. They must not contain ads, sponsor solicitations, or disguised commercial surveys. Answers are voluntary, not a payment or KeyGrant requirement; minimize response data and do not repurpose it for advertising profiles.
- **Operational boundaries:** captions, requested accessibility features, essential player controls, and required safety/legal notices are not optional commercial overlays. Do not label promotions as operational notices or quality questions to evade consent.
- **Acceptance checks:** test all four creator/viewer consent combinations; only both-enabled displays optional overlays. Also test revocation during playback, changed scope, absent consent offline, gift redemption without consent, and cache attempts to inject unsigned overlays.

<a id="webtorrent-hls"></a>

### 7.7 WebTorrent / HLS delivery basis

**Technology direction:** build on HLS (HTTP Live Streaming) for adaptive media presentation and HTTPS delivery, with WebTorrent-based WebRTC peer assistance for reusable encrypted segments. HLS describes the stream; WebTorrent supplies an additional delivery path. Neither replaces creator Policy, Attestations, KeyGrants, or the separate delivery ledger.

<a id="packaging-and-player-integration"></a>

#### Packaging and player integration

- **One media representation:** CEA produces HLS multivariant and media playlists, aligned rendition segments, audio/caption tracks, and initialization objects where required. A creator-signed manifest binds playlist versions, segment identities, ciphertext checksums, key ids, and the peer transport mapping. Serve playlists and objects over HTTPS with appropriate CORS and range support.
- **Reference player:** use HLS.js on compatible MSE/Managed Media Source browsers with a segment-delivery adapter. Evaluate WebTorrent-compatible HLS integration such as P2P Media Loader rather than assuming a raw WebTorrent client can consume an HLS playlist directly. Using WebTorrent signaling alone does not establish generic BitTorrent wire compatibility; pin and test the chosen engine/protocol.
- **Startup and fallback:** start using HTTPS while peer discovery proceeds; use peers only when they can meet playback deadlines. Missing pieces, corrupt segments, tracker failure, peer disconnects, or disabled WebRTC fall back to HTTP without changing unlock policy or charging a second view.
- **Native HLS:** permit native playback only where the selected encryption/key adapter preserves access controls. Native HLS does not automatically support our wrapped KeyGrants or JavaScript peer loader; certify each browser/device path, use tested HTTP-only playback where appropriate, and report unsupported combinations instead of silently publishing clear media.

<a id="ciphertext-and-key-boundaries"></a>

#### Ciphertext and key boundaries

- **Identical shareable bytes:** origin, peers, and edges deliver the same encrypted object for a given title version/rendition/segment. Viewer binding wraps authorization and keys, not a different ciphertext copy per viewer. Per-viewer re-encryption or byte-changing watermarking requires separate swarms or disabling P2P for that representation.
- **Key path:** key loading is separate from the peer segment loader and checks Policy, funding, quota, and KeyGrant scope. Never place plaintext keys, wrapped viewer grants, payment proofs, or analytics payloads in shared playlists, torrents, trackers, or peer caches. Any HLS key URI is an authorized key-service reference, not a public origin key file; key responses must not enter shared caches.
- **Encryption profile gate:** select and test the HLS method, container, key rotation, IV/nonce rules, and client adapter together. HLS AES-128 full-segment encryption is a candidate, not a substitute for the existing wrapped-grant protocol. Do not label arbitrary encrypted blobs or unsupported SAMPLE-AES/container combinations as interoperable HLS. Authenticate ciphertext against the creator-signed digest before accepting peer bytes for decryption.

<a id="swarm-operations-and-viewer-choice"></a>

#### Swarm operations and viewer choice

- **Stable identity:** derive swarm/segment identities from signed title/version/rendition/object mappings, never viewer ids or expiring presigned URLs. For torrent-based engines bind infohash, file/piece ranges, and checksums; for manifest-driven engines bind the equivalent sequence/range mapping. Live uses bounded rolling segment windows, not a mutable whole-stream torrent.
- **Compatible seeds:** browser peers require WebRTC-capable counterparts. Appliance/edge seed support must explicitly match the chosen engine; a TCP/uTP-only BitTorrent client cannot directly seed browser WebTorrent peers. Until compatibility is verified, the appliance remains a valid HLS HTTPS origin.
- **Discovery:** production uses selected operated or contracted WebTorrent-compatible WSS trackers and STUN services, not an implicit dependency on public test trackers. Trackers exchange signaling, not video keys. Peer connectivity failure uses HTTP; any TURN relay is an explicit costed option, not a requirement for ordinary playback or a solution to origin availability.
- **Privacy and resources:** disclose that peers can learn network addresses and swarm membership even when media is encrypted. Offer HTTP-only viewing and explicit peer-sharing controls, upload/memory/disk caps, and metered/mobile restrictions. Do not send playback analytics or stable account identifiers to trackers. Overlay consent is not consent to contribute bandwidth.
- **Existing enforcement:** creator cache permissions, fill leases for participating edges, blocklists, and purge directives govern this transport too. Stop compliant seeding on removal; do not promise deletion from hostile peers. Peer byte counts are not independent Proof of Delivery or evidence of a human view.

**Acceptance gate:** demonstrate encrypted HLS HTTP-only playback first, then two compatible peers exchanging verified ciphertext with seek, ABR, captions, key rotation/expiry, and no double billing. Test absent/hostile peers, tracker loss, blocked WebRTC, no-sharing mode, revoked grants, and browser/native HLS compatibility. Measure origin bytes and rebuffering rather than assuming peer savings; dependency versions, codec/encryption profiles, and appliance seed compatibility remain release-tested choices.

Technical references: [WebTorrent FAQ](https://webtorrent.io/faq/), [HLS.js](https://github.com/video-dev/hls.js), and [P2P Media Loader](https://github.com/Novage/p2p-media-loader). These establish the integration direction, not a claim that this repository already implements it.

<a id="s8"></a>

<a id="requirements-and-attestations-access-path"></a>

## 8) Requirements and attestations (access path)

<a id="requirement-types-extensible"></a>

### 8.1 Requirement types (extensible)

- `goodwill_ack` — consent / good faith; typically low trust, tight caps.
- `puzzle_solve` — human challenge or calibrated proof-of-work.
- `email_verify` — mailbox control; optional domain rules.
- `social_like` (or follow/share) — proof via platform API or delegated attest service.
- `crypto_payment` — receipt of transfer to creator-controlled destination; configurable chain, asset, amount, confirmations.
- `watch_ad` — optional creator-arranged sponsor path, never platform-injected advertising. Any overlay presentation requires bilateral consent under §7.6 before display; selecting an unlock path alone is not consent. Display/timing telemetry is not proof of human attention.
- `allowlist_token` — code, pass, subscription, token-gate, creator credential.
- Additional types register schema + verifier + UX copy only.

<a id="access-policy-model"></a>

### 8.2 Access Policy model

- Boolean composition (`anyOf` / `allOf`) over requirements.
- Per-requirement `min_trust`, optional weights/score targets.
- Grant scope: number of segments or time window, TTL, optional caps (max plays, segment caps, geo/time windows, cooldowns).
- Preview rules: keyless or pre-authorized intro segments.
- Publisher chooses minimal verification (e.g. goodwill only) or stacked high-assurance paths.

<a id="attestation-model"></a>

### 8.3 Attestation model

- Signed by verifier issuer; bound to viewer subject (e.g. public key / device binding), content scope, requirement type, proof blob, trust score, issued/expiry, nonce, signature.
- Short-lived; replay-protected; minimal PII (e.g. email hashed with creator salt when needed).

<a id="keygrant-model"></a>

### 8.4 KeyGrant model

- Creator-signed; segment- or window-scoped; viewer-bound; expiry; wrapped CEKs or key references; policy hash.
- Independent per segment so edges can cache ciphertext while unlock remains granular.

<a id="s9"></a>

<a id="creator-monetary-experience-pennies-per-view-live-balance"></a>

## 9) Creator monetary experience (pennies-per-view, live balance)

Creators should feel paid **as viewing starts**, not after a monthly black box. Default economic expectation is **micropayments—pennies (or fractions of a penny) per view, per minute, or per unlocked segment window**—with a dashboard that updates in near real time. Large fixed prices remain available; they are not the default mental model.

<a id="design-goals"></a>

### 9.1 Design goals

- **Immediate visibility:** when a viewer begins a paid watch path, the creator balance ticks within seconds (target p95 \< 5s for ledger credit events).
- **Pennies-scale pricing:** first-class support for sub-dollar unlocks and ongoing per-time accruals (e.g. \$0.01–\$0.10 per view, or \$0.001–\$0.01 per minute).
- **Creator-controlled rails:** funds route to creator-owned destinations; CDF is not the merchant of record for access value by default.
- **Honest UX:** separate *pending*, *available*, and *withdrawable* so creators are not surprised by confirmations, chargebacks, or failed viewer payments.
- **Aligned with playback:** money can accrue on unlock, on first decrypted media, and/or continuously while segments play—not only on abstract “click.”

<a id="pricing-primitives-creator-configured"></a>

### 9.2 Pricing primitives (creator-configured)

| Primitive | Typical scale | When value moves |
|----|----|----|
| `per_view` | Pennies per successful start (e.g. after N seconds or first paid segment) | Once per viewer session / title (anti-refresh rules apply) |
| `per_minute` / `per_segment` | Fractions of a penny to a few cents per unit | Streams while playback continues under a funded session |
| `unlock_window` | Small flat (e.g. \$0.05 for next 10 minutes) | On KeyGrant issuance for that window |
| `tip` / `bonus` | Viewer-chosen; often still small | On voluntary tip attestation |
| `fixed_price` | Dollars when creator opts out of micro defaults | On paid requirement completion |
| `free_path` | \$0 (goodwill, puzzle, ad, email, etc.) | No access funds; optional separate sponsor/ad revenue later |

Access Policy may still offer non-pay paths. **Monetary paths** are requirement types (or composite paths) that produce a *Payment Attestation* plus a *Ledger Credit* event.

<a id="funds-as-soon-as-they-start-viewing"></a>

### 9.3 “Funds as soon as they start viewing”

Recommended default paid flow (micro):

1.  Viewer selects a penny-scale path (or auto-selects if only one paid path).
2.  **Session fund:** viewer wallet/rail authorizes a small open amount (e.g. cap \$0.25) or prepaid micro-balance—not a surprise card capture of large holds.
3.  On **watch start** (first paid segment decrypt or T+3s playback heartbeat): emit `view_started` → creator ledger **pending credit** for `per_view` baseline.
4.  While playing: emit metered ticks (`per_minute` / segment) → additional pending credits up to session cap.
5.  Key Agent issues/extends KeyGrants only while session funding and Policy remain satisfied.
6.  When rail confirms (instant internal ledger, L2/LN instant, or after N chain confs): pending → **available**.

**Product promise:** creators see the counter move when real viewing begins. Engineering truth: show *pending* immediately from signed playback/payment signals; move to *available* when the chosen rail’s finality rules say so. Never imply irreversible cash before finality.
<a id="ledger-model-creator-facing"></a>

### 9.4 Ledger model (creator-facing)

- **Pending:** view/payment observed; awaiting rail finality or anti-fraud hold (seconds to minutes for micro-rails; longer only if creator accepts slow chains).
- **Available:** counted toward balance; may still have short clawback window for proven fraud.
- **Withdrawable / pushed:** already sent to creator external wallet or payout endpoint.
- **Reversed:** failed payment, double-spend, chargeback-like event on a rail that supports it—explicit line items, not silent edits.

Each line item links: `title_id`, optional `segment_id`/`session_id`, `viewer_pseudonym` (opaque), amount, currency/asset, rail, attestation ids, timestamp. Dashboards aggregate by title, hour, and geography without exposing unnecessary viewer PII.

<a id="who-holds-the-money-rails"></a>

### 9.5 Who holds the money (rails)

| Rail | Fit for pennies | Creator sees funds “now” | Notes |
|----|----|----|----|
| **Lightning / instant L2 / payment channels** | Excellent | Yes—available ~immediately | Preferred for true micropayments; pay-per-view and stream ticks |
| **Prepaid viewer credits** (non-custodial voucher or creator-specific tab) | Excellent | Yes—on tick against prepaid | Viewer tops up once; spends pennies per title without per-tick chain fees |
| **Stablecoin on low-fee chain** | Good in batches | Pending on submit; available on confs | Batch many pennies into one on-chain settle to creator |
| **Direct on-chain L1** | Poor per penny | Slow / expensive | Use for larger unlocks or withdrawals, not per-minute ticks |
| **Optional CDF micro-ledger** | Excellent UX | Instant internal available | Only if creator opts in; still not “access card processor” monopoly—periodic sweep to creator wallet. Disclose custody clearly. |

Default recommendation: **viewer micro-balance or LN/L2 → creator wallet**, with CDF emitting only signed metering and settlement *hints*. Optional **opt-in custodial micro-ledger** exists purely for UX (instant pennies, low fees), with automatic sweep rules (e.g. daily or at \$1 available).

<a id="anti-fraud-and-penny-economics"></a>

### 9.6 Anti-fraud and penny economics

- **View definition:** configurable—e.g. 3 continuous seconds of decrypted media, or first paid segment grant + progress beacon.
- **Replay protection:** one `per_view` per viewer-root per title per cooldown; metered ticks require monotonic playback proofs (sampled).
- **Bot/farm resistance:** tie paid ticks to device binding + attestation quality; rate-limit anonymous ephemeral identities on paid paths.
- **Minimums:** creators set floor price and session cap; network may publish suggested penny defaults by genre/length.
- **Fee display:** show rail fee vs creator receive amount on both viewer and creator sides (“viewer pays \$0.03 · you receive \$0.028”).
- **Dust:** sub-cent accruals roll up; withdrawable when above rail dust threshold.

<a id="creator-console-ux"></a>

### 9.7 Creator console UX

- **Live ticker:** running available + pending today; sparkline of last 60 minutes.
- **Per-title cards:** views started, paid watch-time, effective eCPMv (earnings per thousand paid views), refund/reverse rate.
- **Price editor:** presets—“pass the hat (free paths only)”, “pennies per view”, “pennies per minute”, “small unlock window”, “custom”.
- **Payout panel:** destination wallets/endpoints, sweep schedule, last push tx ids.
- **Expectations banner:** plain language that typical per-view amounts are cents or less unless the creator sets higher; virality = many pennies, not automatic dollars per play.
- **Alerts:** first earnings on a title, pending stuck \> threshold, reverse spike, Key Agent down blocking paid unlocks.

<a id="viewer-ux-so-pennies-feel-fair"></a>

### 9.8 Viewer UX (so pennies feel fair)

- Up-front meter: “~\$0.02 to start · ~\$0.01/min · cap \$0.15 this session.”
- Running session spend while watching; hard stop at cap unless viewer raises it.
- No dark patterns: paid vs free paths labeled; stop payment stops new KeyGrants after grace buffer.
- Receipt: tiny itemized session bill exportable as attestation trail.

<a id="relation-to-freenon-pay-requirements"></a>

### 9.9 Relation to free/non-pay requirements

- Goodwill, puzzle, email, social, ad-watch paths produce **no** access ledger credits (unless a separate sponsor pays the creator—an optional future “subsidy attestation”).
- Creators may offer a disclosed sponsor-supported path alongside a paid path, but the platform injects no ads. Optional overlays require both parties’ prior opt-in (§7.6). “No additional overlays” does not mean creator-embedded sponsorship has been removed; paid and gifted access never imply overlay consent.
- Delivery rebates to ISPs (§11) remain a **cost** line, never confused with view earnings.

<a id="signals-apis-descriptive"></a>

### 9.10 Signals & APIs (descriptive)

- `POST /v1/money/sessions` — open funded watch session (cap, rail, title).
- `POST /v1/money/events` — `view_started`, `meter_tick`, `session_end` (client + optional edge-signed).
- `GET /v1/creator/ledger` — pending/available/withdrawable, filters by title/time.
- `GET /v1/creator/ledger/stream` — SSE/WebSocket live credits for console ticker.
- `POST /v1/creator/payouts/sweep` — push available balance to external destination.
- Ledger events are signed and idempotent; KeyGrant issuance may reference `session_id` + payment attestation.

<a id="defaults-opinionated"></a>

### 9.11 Defaults (opinionated)

- New title template: `per_view = $0.02` after 3s paid play, optional `per_minute = $0.005`, session cap `$0.20`, free preview first segment.
- Live ticker on for all creators with any monetary path enabled.
- Suggest LN/L2 or prepaid micro-balance; discourage L1 per-tick.
- MVP may implement prepaid credits + internal ledger sweep before full streaming LN.

<a id="non-goals"></a>

### 9.12 Non-goals

- Guaranteeing “YouTube RPM” parity or ad-market CPMs.
- Hiding fees inside unexplained “algorithm” bonuses.
- Forcing every viewer to pay—free requirement paths remain core.
- Silent CDF seizure of creator balances.

<a id="gifted-views-userxyz-bought-you-a-view"></a>

### 9.13 Gifted views — “userxyz bought you a view”

A viewer may recommend a title through their own local/cloud publishing setup (§6.12) and purchase a **gift entitlement** for another viewer. Recommendations alone remain free apart from hosting costs; a paid gift adds creator-defined access. This is entitlement gifting, **not transfer of content keys**, trust-list placement, or a general-purpose messaging feature.

1.  **Purchase:** sender selects a creator-enabled gift offer for a title, with explicit scope and total cost: one view, a fixed access window, or a capped playback allowance. The payment rail routes access value to the creator; delivery settlement remains separate.
2.  **Address:** gift targets a recipient account or an unguessable, single-use claim link when the recipient is unknown. Link possession authorizes claiming an untargeted gift; targeted gifts additionally require the intended account. Bearer tokens must not appear in analytics, referrers, or ordinary logs.
3.  **Accept:** recipient sees “userxyz bought you a view of \[Title\]” with preview, scope, expiry, Accept, and Decline. Redemption proves recipient account/device control and atomically binds the entitlement to that recipient; concurrent claims cannot redeem it twice.
4.  **Unlock:** the creator Key Agent validates the redeemed entitlement and remaining requirements, then issues fresh recipient-bound KeyGrants. Neither the sender’s keys nor their existing grants are shared.

- **Additional purchase by default:** gifting does not duplicate the sender’s own paid access. A creator may separately permit transfer of an unused entitlement, atomically disabling redemption by its previous holder.
- **No surprise spend:** gifts disclose included playback and any expiry before purchase and acceptance. Metered gifts stop at their funded cap; recipient funds are never charged without separate explicit authorization.
- **Normal enforcement:** moderation blocks, age/region rules, watch quotas, and device/concurrency limits still apply. Creator Policy explicitly states which requirements a gift satisfies; gifting is not a bypass.
- **Recipient safety:** unsolicited gift notifications are opt-in and rate-limited, with sender blocking and reporting. Do not allow arbitrary sender links or attachments; display names are untrusted text, not proof of identity.
- **Payment integrity:** verify funding before enabling redemption; bind payment proof to creator, title/offer, amount/asset, and unique gift reference. Purchase and claim retries are idempotent; one payment cannot fund multiple gifts accidentally.
- **Failure and refunds:** each offer discloses rules for unclaimed, declined, expired, removed, or unavailable titles before purchase. Preserve a retryable entitlement when unlock temporarily fails; reconcile payment, redemption, and grant issuance before refund or credit so retries cannot create both free access and reimbursement. Refunds, where supported, return to the original payer, not a recipient cash-out balance.
- **Earnings and privacy:** show gift purchase, redemption, and any reversal as distinct ledger events without double-crediting watch start. Pending/available follows rail finality, not notification delivery. Do not reveal acceptance, watch status, or watch duration to the sender without recipient consent.

**Descriptive interfaces:** `POST /v1/gifts` creates a funded gift; `POST /v1/gifts/claim` atomically redeems a claim token or addressed gift; recipient-authorized accept/decline and reporting actions do not expose another account’s gift status. Key requests reference the redeemed entitlement, never the claim token as a content key.

<a id="s10"></a>

<a id="key-agent-availability-delegation"></a>

## 10) Key Agent availability & delegation

The catalog can be highly available while playback still depends on a reachable Key Agent. This section defines how keys stay under creator control without a single home PC becoming a hard outage.

<a id="responsibility-split"></a>

### 10.1 Responsibility split

- **CDF:** relays key requests, caches negative answers briefly, enforces global rate limits, never holds unwrapped content keys.
- **Key Agent:** evaluates Policy + Attestations and signs KeyGrants. Authoritative for unlock.
- **Creator master key material:** remains creator-controlled (local KMS/HSM or split control). Delegation never implies CDF custody of master keys.

<a id="deployment-modes"></a>

### 10.2 Deployment modes

| Mode | Where it runs | Availability posture | Who holds signing capability |
|----|----|----|----|
| **Local CEA** | Creator device/NAS | Best-effort; fine for small catalogs | Creator only |
| **Always-on self-host** | VPS/home server + watchdog | Creator SLA | Creator only |
| **Delegated Key Agent** | Hardened operator or multi-region workers | Target high availability | Creator-authorized agent keys; master still creator-held or HSM under creator policy |
| **Multi-agent quorum** | N agents, K-of-N grant signatures optional for high-value catalogs | Survives single agent loss | Split among creator-controlled principals |

<a id="delegation-model"></a>

### 10.3 Delegation model

- Creator issues a **Delegation Grant**: agent identity, allowed title set (or `*`), max grant TTL, max segments/hour, allowed requirement issuers, geo/policy constraints, expiry, revocation URI.
- Delegated agents sign KeyGrants with an **agent key** that chains to the creator root (certificate or signature chain). Clients and CDF verify the chain.
- Master content-key unwrap can use: local HSM; creator-held wrapped CEKs shipped to agent encrypted to agent key; or online unwrap API the creator runs separately.
- **Revocation:** creator publishes revocation to CDF; agents must stop; clients reject grants from revoked agents after short cache TTL.

<a id="offline-and-degraded-behavior"></a>

### 10.4 Offline and degraded behavior

- **Preview / free intro:** still works if Policy allows keyless or pre-authorized intro keys distributed as public preview material.
- **Pre-issued grant batches:** optional limited rolling window (e.g. next N segments, short TTL) issued while online; not a substitute for long offline binge unless Policy allows.
- **Queued requests:** CDF may queue unlock attempts and retry agents; client shows “creator unlock service temporarily unavailable.”
- **Emergency read-only:** creator may pre-declare a disaster Policy (e.g. goodwill-only short grants, or freeze all paid unlocks).
- **No silent CDF unlock:** fabric must not mint content keys if agents are down.

<a id="health-slos-and-client-ux"></a>

### 10.5 Health, SLOs, and client UX

- Agents heartbeat to CDF: latency, queue depth, signing success rate, policy version.
- Title page shows unlock-path health: healthy / degraded / offline.
- Recommended SLO classes: Hobby (no formal SLO), Standard (e.g. 99% monthly unlock API), Professional (multi-region delegated).

<a id="compromise-response"></a>

### 10.6 Compromise response

- Revoke agent keys; rotate segment CEKs for affected titles when feasible; invalidate outstanding grants; watermark-assisted leak investigation if enabled.
- Re-publish manifests with new key ids; edges keep ciphertext if re-encrypted objects are versioned.

<a id="s11"></a>

<a id="isp-edge-cache-incentives-delivery-path"></a>

## 11) ISP / edge cache incentives (delivery path)

<a id="goal"></a>

### 11.1 Goal

See also [§5 Business order & multi-ISP cache-fill model](#s5) for normative payment order, diversity incentives, and fill leases.

Motivate ISPs and neutral edges to hold and serve ciphertext near viewers so origins shed egress and viewers get low latency—**without** moving keys or access payments into the cache.

<a id="value-exchange"></a>

### 11.2 Value exchange

| Party | Value |
|----|----|
| Viewer | Faster start, fewer stalls, often less upstream data use on-net |
| Creator | Lower origin egress; better completion; optional paid pin/prefetch |
| ISP/edge | Transit savings; optional revenue/credits; on-net experience |
| CDF | QoE without owning a classic media CDN or the files |

<a id="incentive-instruments"></a>

### 11.3 Incentive instruments

1.  **Transit savings (default, \$0):** On-net hits reduce ISP transit and creator egress; no settlement required. Sufficient for many independents and opportunistic caches.
2.  **Origin-egress rebate pool:** Creator sets \$/GB and caps; CDF meters verified cache-served bytes; edges claim proportional share. Separate from unlock crypto/goodwill/etc.
3.  **Storage pin stipend:** \$/GB-month for reserved disk on pinned title sets; time-bounded contracts; revocable on delist.
4.  **Prefetch bounties:** Pay to warm intro / “good part” segment sets before spikes; optional boost on delivery rate for those IDs; creator opt-in; may use popularity thresholds only as *proposals*.
5.  **Swarm assistance:** Credits for stable seeding (peer-hours or valid piece-bytes) with anti-sybil caps.
6.  **QoE bonuses:** Extra pool when regional join latency / rebuffer beats baseline for committed titles (aggregate, privacy-preserving).
7.  **Delivery Credits:** Internal credits redeemable for control-plane fees, routing preference, or cash-out—optional ecosystem currency.
8.  **Public/grant tracks:** Education/news/open catalogs funded by consortia/CSR using the same metering path.

<a id="explicit-non-incentives-for-caches"></a>

### 11.4 Explicit non-incentives for caches

Cache rewards are **not** tied to: successful unlock, ad view attestations, email capture, social likes, or creator access revenue—unless a completely separate verifier contract exists. **Delivery Settlement ≠ Access Attestation.**

<a id="proof-of-delivery-pod"></a>

### 11.5 Proof of Delivery (PoD)

- Serve bytes matching creator checksum/Merkle leaf.
- Optional short-lived **fetch tokens** authorizing ciphertext GET (not keys).
- Sampled signed delivery receipts: segment, bytes, edge id, region, time, token id.
- Caps per edge/ASN/day; penalties for integrity or fraud failures.
- Delist/takedown SLA; non-compliance affects eligibility and stakes.

<a id="pricing-primitives-creator-configurable"></a>

### 11.6 Pricing primitives (creator-configurable)

| Primitive | Unit | Typical use |
|----|----|----|
| `delivery_rebate` | currency / GB | General hit traffic |
| `storage_pin` | currency / GB-month | Always-warm libraries |
| `prefetch_bounty` | currency / segment-set warm | Intros / trailers / “good parts” |
| `seed_assist` | currency / peer-hour or piece-GB | Swarm health |
| `qoe_bonus` | currency / region-day if SLA met | Premium creators |
| `budget_cap` | currency / title or month | Hard stop |

Suggested market comps may be published; creators override, including all-zero (transit-only).

<a id="edge-tiers"></a>

### 11.7 Edge tiers

| Tier | Commitment | Earns |
|----|----|----|
| **Opportunistic** | Cache on demand, small disk | Delivery rebate only (if creator enabled) |
| **Regional pin** | Min disk + uptime SLA | Storage stipend + delivery |
| **Prefetch partner** | Honors bounty manifests quickly | Bounties + boosted delivery rate |
| **Seed backbone** | Always-on P2P seed + HTTP | Seed assist + delivery |

<a id="creator-delivery-modes-ux"></a>

### 11.8 Creator delivery modes (UX)

1.  **Free speed** — caching allowed, \$0 budgets.
2.  **Offset my egress** — rebate + cap.
3.  **Pin this catalog** — storage stipend.
4.  **Launch boost** — time-boxed prefetch bounties.

<a id="routing"></a>

### 11.9 Routing

- Clients combine origin URLs, edge bases, and swarm hints; prefer by RTT, integrity score, price, and creator allow/deny ASN lists.
- Multi-edge competition; no mandatory exclusive ISP lock-in.
- **Prefetch places ciphertext only.** Instant play still needs access Policy (free intro and/or KeyGrants). Intro keys may be pre-authorized **to viewers**, never deposited at the ISP.

<a id="economic-safeguards"></a>

### 11.10 Economic safeguards

- Budget caps and soft-pause of *paid* claims (cache may still serve unpaid).
- Optional anti-duplication signals for cold segments in one metro.
- Escrow/prepaid for pin and bounty windows so edges are not stranded after warm-up.
- Barriers (trust/stake) before junk titles enter paid prefetch pools.

<a id="trusted-peer-exchange"></a>

### 11.11 Trusted-peer video asset exchange and compensation

**A publisher's videos are assets.** The publisher can authorize trusted peers to transfer, hold, or serve a specific asset for agreed compensation. This is a controlled asset-distribution transaction, not an unsolicited download or an automatic claim on viewer payments. Viewer trust for recommendations (§12.7), operator trust for custody/delivery, and ownership/licensing rights are separate decisions.

<a id="asset-identity-and-integrity"></a>

#### Asset identity and integrity

- **Signed asset manifest:** bind publisher identity, asset/title id, immutable version, renditions/tracks, ordered file/segment inventory, sizes, key ids, and cryptographic digests (SHA-256 or a specified approved equivalent). Bind per-chunk hashes or a Merkle root for resumable transfer plus whole-object hashes and a package root covering inventory/order. An unsigned hash supplied by the sending peer is not authoritative.
- **Exact content:** peers exchange the publisher's immutable ciphertext plus authorized manifests and assets, using the same bytes as origin/HLS delivery. Source and destination verify against the publisher-signed expected digest; filenames, matching lengths, and a matching title are insufficient. A re-encode, re-encryption, changed caption, or metadata/package edit creates a new version/root and cannot silently replace the contracted asset.
- **What a match proves:** a verified cryptographic hash establishes byte identity with the signed reference, not that a caption is truthful, that a peer owns copyright, or that ciphertext depicts what its title claims. Publisher-side packaging validates clear-source-to-encrypted-output mapping; any rights/content inspection needs separately authorized access, never routine plaintext disclosure to caches.

<a id="trade-agreement-and-transfer-flow"></a>

#### Trade agreement and transfer flow

1.  **Authorize the counterparties:** publisher selects source/destination operator identities or scoped delegated operators. Both peers accept the relationship and authenticate control of their keys; no transitive trust merely because they share a tracker, viewer, ASN, or recommendation source.
2.  **Agree the contract:** sign a unique contract/order id binding the asset root/version, payer/payee, source/destination, transfer or hosting rights, permitted onward distribution, price/asset/currency, byte/storage caps, retention/availability term, expiry, and rejection/dispute rules. Identify whether compensation buys verified transfer, continuing storage/serving, or an explicitly licensed right. Hosting or copying alone does not sell copyright, exclusivity, or viewer unlock authority.
3.  **Reserve funding and capacity:** verify destination free space and bounded transfer budget, reserve funds through the agreed rail or optional disclosed delivery escrow, and obtain a fill lease when applicable (§5). No uncapped payment for duplicate cold copies; count a contracted completion once, and deduplicate overlapping fill/transfer claims unless the contract explicitly buys separate work.
4.  **Move and verify:** use authenticated HTTPS/range transfer or the validated WebTorrent-compatible transport (§7.7), with short-lived scoped fetch authorization. Stage partial data, check chunks, resume only against the same root, and verify the full required inventory before marking it complete. Reject/quarantine corrupt bytes and retry a permitted donor; never advertise partial or mismatched assets as complete.
5.  **Acknowledge:** receiver signs a receipt binding contract id, asset root, source/destination identities, accepted inventory/bytes, and completion time. Persist the verified asset before acknowledging durability; submit a signed HAVE/location advertisement only for authorized verified content. A later storage/uptime payment requires ongoing probes or retention evidence, not merely this one receipt.
6.  **Settle:** match authorization, reserved budget, verified completion evidence, and contract conditions; append an idempotent delivery/asset-transfer ledger event. Release compensation or enter the agreed hold/dispute path. Partial transfers are unpaid unless priced explicitly; refund/expiry behavior is disclosed. Receipts are evidence, not a guarantee against colluding peers or a promise of trustless atomic exchange.

<a id="rights-privacy-and-operational-safeguards"></a>

#### Rights, privacy, and operational safeguards

- **Publisher control:** ordinary peers get ciphertext, not creator master keys, grant-signing authority, private analytics, forum member records, or unrelated library access. A publisher's cloud instance may separately run a scoped Key Agent (§4.7/§10); that authority is not conferred by an asset-transfer contract.
- **Separate economics:** transfer, storage, and delivery compensation uses the explicitly funded asset/delivery ledger. Never silently skim per-view earnings or pay recommendation counts as if they proved delivery. Any sale/license of rights needs its own agreement and rights records; moving verified bytes is not that agreement.
- **Private counterparties:** share contract terms and receipts only with authorized parties and necessary settlement services. Public location records expose only approved serving information; do not publish trust relationships, secret endpoints/tokens, or private commercial terms to the discovery library.
- **Revocation and recovery:** expired/revoked transfer rights stop new fetches and onward offers; blocked content cannot initiate new paid distribution. Handle retained copies, required deletion/restriction, and claims according to the contract and legal duties. Short TTLs do not remotely erase already received bytes. On peer failure, reconcile receipts and funds before retrying another paid order.

**Acceptance:** complete and settle a publisher-authorized transfer between two trusted peers; confirm signed manifest/root and received bytes match. Reject an unauthorized peer, forged manifest, one-byte corruption, omitted/reordered segments, wrong version, and a replayed receipt. Verify interrupted resume, duplicate-claim prevention, capped spending, disk-full handling, dishonest receiver disputes, and that no public metadata or ciphertext-only peer receives content keys. An agreed implementation must measure throughput and settle through real tested rails before claiming this market works.

<a id="part-c-—-viewer-experience"></a>

<a id="part-c-viewer-experience"></a>

## Part C — Viewer experience

**Watch without the hustle tax.** Browse in your language. Preview when the creator allows. Unlock with a simple path—goodwill, a quick challenge, an email, or pennies with a hard session cap. No platform-injected ads; optional overlays appear only after both creator and viewer opt in. The platform may ask brief quality questions. No surprise card holds for pocket-change video. Captions and quality that just work. If something is spam, scummy, or unlawful, say so in one tap. You came to watch, not to fund a black box.

<a id="journey-viewer"></a>

<a id="viewer-journey-discover-to-watch-to-report"></a>

## Viewer journey (discover to watch to report)

This is the viewer-facing path. System internals stay out of the way unless something breaks.

1.  **Find and trust publishers** — arrive via any chosen link, community, directory, or recommendation; explicitly review publisher identity and build a local catalog. Untrusted publishers do not populate the normal feed or autoplay. [§12.7](#local-catalog)
2.  **Device identity** — ephemeral or recoverable keypair; multi-device if signed in. [§12](#s12)
3.  **Preview** — free intro/trailer when Policy allows (may already be edge-cached). [§13.2](#s13), [§7](#s7)
4.  **Choose unlock path** — free (goodwill, puzzle, email, social, ad, …) *or* paid with an upfront meter (“~\$0.02 to start · cap \$0.15”). [§8](#s8), [§9.8](#s9)
5.  **Accept a gifted view** — when someone buys you access, preview and accept or decline; accepted gifts unlock fresh device-bound grants within the disclosed scope, without surprise recipient charges. Suggest a title for free or buy an additional view for someone else. [§9.13](#s9)
6.  **Play** — KeyGrants roll forward; ABR + captions; bytes from edge, swarm, or origin. [§13.4](#s13), [§7](#s7)
7.  **Session spend** — running total on paid paths; stop raises stop new grants after a short grace. [§9](#s9)
8.  **Report** — spam, unlawful, misleading unlock, etc.; personal “hide” is not a network strike. [§15](#s15)
9.  **Share a recommendation** — use your own local or cloud publisher setup; the recipient decides whether to inspect the recommendation and trust its sources. [§6.12](#recommendation-publishing)
10. **Daily watch quota** — at most 48 hours of content timeline per day per account (shared devices); soft warnings then KeyGrants stop. [§16](#s16)

**Viewer promise:** honest unlock choices, no surprise large holds for penny video, playback works when the creator’s unlock path is healthy, and harmful content can be flagged without needing to understand ISPs or ledgers.
<a id="s12"></a>

<a id="identity-recovery-multi-device"></a>

## 12) Identity, recovery, multi-device

<a id="identity-layers"></a>

### 12.1 Identity layers

| Layer | Purpose | Required? |
|----|----|----|
| **Viewer root keypair** | Subject of Attestations and KeyGrants | Yes for unlock beyond pure public preview |
| **Device key** | Per-install binding; reduces grant export | Yes on capable clients |
| **Optional account handle** | Recovery UX, multi-device sync, support | No (anonymous viewing allowed where Policy permits) |
| **Creator root / org** | Publish signatures, delegation, payout endpoints | Yes to publish |
| **Edge / verifier operator ids** | Settlement and attestation issuer trust | Yes for those roles |

<a id="viewer-registration-postures"></a>

### 12.2 Viewer registration postures

- **Ephemeral:** keypair generated on device; lost on reinstall; suitable for goodwill/puzzle paths.
- **Recoverable account:** root key wrapped with user secret, passkey, or social recovery; encrypted backup blob optional (client-chosen storage).
- **Linked email/social:** only when user opts in or Policy requires `email_verify` / social proofs; not mandated by CDF globally.

<a id="multi-device"></a>

### 12.3 Multi-device

- Account (if any) authorizes a small set of device keys; each device has its own binding in KeyGrant `aud`.
- Attestations may be portable to a root identity with a fresh content nonce; grants remain device-bound by default.
- Device limit and concurrent playback limits are creator Policy knobs (anti-account-sharing), not a global DRM vendor rule.
- Adding a device: prove control of root (passkey/secret); revoke lost devices immediately.

<a id="recovery"></a>

### 12.4 Recovery

- **Viewer:** recover root → re-enroll devices → prior grants do not automatically transfer (re-request keys with existing valid Attestations if still unexpired).
- **Creator:** offline master backup (paper/HSM/split shamir); recovery runbook required before “Professional” unlock SLO claims.
- **Delegation recovery:** revoke all agents, issue new Delegation Grants, rotate agent keys.
- CDF does not offer “reset password = get content keys.”

<a id="creator-organizations"></a>

### 12.5 Creator organizations

- Roles: Owner, Publisher (metadata/manifest), Policy Editor, Key Operator, Finance (delivery budgets), Moderator (respond to notices).
- Separation of duties recommended: Policy Editor ≠ sole Key Operator for large catalogs.
- Audit log of policy changes, delists, delegation, and budget edits.

<a id="privacy-defaults"></a>

### 12.6 Privacy defaults

- Playback analytics use creator-scoped viewer pseudonyms, not global account identifiers. Per-viewer detail is creator-private (§20.1); a pseudonym alone does not anonymize a behavioral history. Global advertising profiles are a non-goal.
- Age and jurisdiction signals: prefer local client declarations + creator Policy over central dossiers.

<a id="local-catalog"></a>

### 12.7 Viewer-owned local catalogs, publisher trust, and reviewing agents

**The ordinary viewing catalog is local and trust-gated.** AI can generate unlimited uploads or metadata without earning a place in a viewer's feed. The viewer chooses publisher identities and recommendation sources; central indexes supply shared records, not compulsory attention. This is an attention-control model, not a guarantee that trusted content is truthful or that spam no longer costs infrastructure resources.

- **Local ownership:** store selected publisher keys/endpoints, trust/block decisions, catalog entries, collections, and agent review notes in viewer-controlled local storage. Permit export/import and optional encrypted sync/backup to a viewer-chosen destination; never upload the trust graph or catalog history as a default central profile.
- **Many discovery routes:** publishers can be found through direct links, websites, real-world contacts, forums, external search, signed recommendations, or centralized metadata libraries. No single directory is the exclusive enrollment path. Direct import still verifies identity and does not bypass network safety/access constraints.
- **Default visibility:** normal browsing, notifications, previews, and autoplay use trusted publisher sources only. Put unknown identities in a separate discovery or invitation-review mode that the viewer must request. An empty catalog starts with an explicit choice of sources, not a silently subscribed platform list; suggested starter lists are opt-in and identify their curator.
- **Scoped trust:** let viewers trust media publishers and recommendation/review publishers separately, by topic or named title where appropriate. Receiving a trusted person's recommendation does not transitively trust its target. Trust is personal, revocable, and distinct from identity verification, verifier scores for unlock, community moderation, or a platform badge.
- **Agent review:** viewer-selected local agents can review permitted shared descriptions, closed captions, reviews, and already-authorized media, then annotate/rank within the viewer's rules. A remote agent requires explicit disclosure and authorization for any viewer-owned data sent to it. Do not buy media access, release secrets, run downloaded code, subscribe to publishers, or lift trust restrictions merely because source content asks an agent to do so; treat captions/reviews as untrusted data, not instructions.
- **Explainability:** show why a title is present, the original publisher, recommending/reviewing identities, source versions, human/agent provenance, and review limits. Missing captions or incomplete inspection must be visible; neither a shared review nor an agent summary proves the video matches its description.
- **Revocation and freshness:** removing/blocking a publisher stops new imports and normal presentation; undo inherited suggestions without deleting unrelated user data. Retain audit/history only under viewer settings. Handle signing-key changes with authenticated continuity or renewed approval, not trust in a reused display name; propagate title withdrawal independently of publisher trust.
- **Flood resistance:** bound per-source imports, agent work, caption size, notifications, and local disk use; deduplicate records and quarantine abnormal bursts even from trusted publishers. Central ingestion still needs publisher authentication, quotas, abuse detection, and resource limits. A compromised trusted source can still abuse earned attention, so provide fast mute/revoke/report controls.

**Acceptance:** flood the shared index with untrusted publishers and confirm no change to the ordinary feed, notifications, or autoplay. Verify explicit new-publisher inspection, trusted-source import, a recommendation that does not grant transitive trust, malicious caption instructions ignored by the agent, trust revocation/key rotation, bounded trusted-source floods, and local export/restore without disclosure of the private trust graph.

<a id="s13"></a>

<a id="end-to-end-flows"></a>

## 13) End-to-end flows

<a id="publish"></a>

### 13.1 Publish

CEA segments → encrypts → uploads to local and publisher-operated cloud origins → verifies complete cloud copy and independent unlock health → registers ready metadata, access Policy, optional delivery Policy → optional seed → optional pin/prefetch declarations. Incomplete replication remains a draft (§4.7).

<a id="discover-and-preview"></a>

### 13.2 Discover and preview

Viewer finds publishers through chosen routes, approves identities or a named-title inspection, and browses their trust-filtered local catalog. Authorized agents review publisher-shared metadata/captions/reviews. Preview/intro plays only on an allowed path per Policy (keyless or pre-authorized); bytes may come from local/cloud origin, swarm, or edge caches (§12.7).

<a id="fulfill-requirements"></a>

### 13.3 Fulfill requirements

Viewer picks a path; verifiers issue Attestations; publisher-defined strictness applies. No credit-card-centric funnel required.

<a id="unlock-and-stream"></a>

### 13.4 Unlock and stream

Key Agent checks Policy + trust + replay limits → KeyGrants → client fetches ciphertext (P2P/HTTP/edge) → decrypts locally → rolling window of grants.

<a id="cache-warm-path"></a>

### 13.5 Cache warm path

Popularity or creator bounty → edge fetches ciphertext from origin or peers → serves regionally → optional PoD → settlement if budgets exist. Keys unchanged.

<a id="takedown-delist"></a>

### 13.6 Takedown / delist

Creator or process flags title/segments → registry updates → edges ACK purge within SLA → paid eligibility affected on failure. Access path stops issuing new grants as Policy demands.

<a id="s14"></a>

<a id="internationalization-and-accessibility"></a>

## 14) Internationalization and accessibility

- Localized UI and requirement disclosure before action.
- RTL and caption/subtitle pipelines.
- Clear statement of unlock scope (“next N minutes / M segments”) and whether caching improves speed only.

<a id="s15"></a>

<a id="viewer-feedback-content-review-abuse-spam-unlawful"></a>

## 15) Viewer feedback & content review (abuse, spam, unlawful)

This subsystem lets viewers and trusted reporters flag problems, routes them through severity-based review, and can **pull very unacceptable content** from discovery, edges, and—via creator duty—origin availability. It complements creator sovereignty: the network cannot silently decrypt private media, but it **can** stop amplifying and locating it.

<a id="goals"></a>

### 15.1 Goals

- Fast path for illegal and severe harm.
- Noise-resistant handling of spam and taste disputes.
- Transparent outcomes for reporters and creators (with privacy and safety limits).
- Auditability for regulators and internal appeals.
- No requirement that CDF host or re-encode the underlying bytes.

<a id="report-object"></a>

### 15.2 Report object

- **Target:** title_id, optional segment/time range, preview asset, creator_id, metadata field, user profile/comment if those exist later.
- **Category:** spam/scam, copyright, unlawful_severe, unlawful_other, harassment, sexual_exploitation, self_harm, hate_violent, misleading_dangerous, age_inappropriate, other.
- **Severity hint:** reporter-selected; system may escalate via classifiers.
- **Evidence:** free text, screenshots hashes, URLs, optional content hash if reporter fetched bytes, timestamp, locale.
- **Reporter:** anonymous token, viewer root id, or registered trusted flagger; reputation weight.
- **Idempotency:** duplicate reports coalesce into one case.

<a id="in-product-feedback-channels"></a>

### 15.3 In-product feedback channels

- **Report** on title, creator, preview, and unlock-offer screens.
- **Not interested / hide** (personalization only; not a trust-safety strike by itself).
- **Misleading requirement** (unlock path bait-and-switch, phishing-like external demands).
- **Broken/malware suspicion** for hostile origins.
- **Trusted flagger** API for NGOs, hotlines, rights-holders with signed assertions.

<a id="severity-classes-and-default-actions"></a>

### 15.4 Severity classes and default actions

| Class | Examples | Default system action | Human review |
|----|----|----|----|
| S0 — Emergency | CSAM; imminent violent threats; active malware distribution via catalog | Immediate delist from search/catalog; freeze further publish for actor; edge purge order; preserve case file; mandatory reporting where law requires | Parallel human confirmation ASAP; false positive rollback path |
| S1 — Urgent unlawful / severe | NCII; credible illegal content; valid court order | Soft-block discovery within minutes; notify creator; edge purge on confirm; Key Agent relay may refuse new grants for title while blocked | Prioritized queue SLA (e.g. hours) |
| S2 — Rights & serious policy | Copyright notice; doxxing; graphic content without labels | Hold-out of recommendations; temporary geo or label; standard notice-and-action to creator | Standard SLA (e.g. days) |
| S3 — Spam / quality | Keyword stuffing; duplicate floods; engagement farms | De-rank, rate-limit publish, challenge creator, limit previews | Mostly automated + sampled audit |
| S4 — Subjective / taste | “I dislike this,” political disagreement without policy violation | Personal hide / reduce similar; no network delist | None unless pattern of weaponized reporting |

<a id="case-workflow-content-review-process"></a>

### 15.5 Case workflow (content review process)

1.  **Intake:** validate schema; fingerprint reporter; attach target snapshot (metadata + hashes + policy version).
2.  **Auto-triage:** match known bad hashes/URLs; spam classifiers; trusted-flagger boost; burst detection (raid reporting).
3.  **S0/S1 automatic shield:** provisional delist or “under review” interstitial while queued.
4.  **Evidence pack:** for reviewers—previews, reporter notes, prior strikes, creator response history. Reviewers do not receive master keys. If byte inspection is required, use reporter-submitted samples, crawler-fetched *public ciphertext + public previews*, or creator-provided clear samples under legal process.
5.  **Decision:** no_action \| label \| age_gate \| de_rank \| geo_restrict \| temp_delist \| permanent_delist \| creator_strike \| verifier/edge sanctions \| refer_law_enforcement.
6.  **Execute pull (very unacceptable):**
    - Registry: remove or tombstone title; strip search/recommend; mark `availability=blocked`.
    - Edges: fan-out **Purge Directive** for segment ids / title uid; require ACK; fail settlement if ignored.
    - Key path: CDF may refuse to relay key requests for blocked titles; creators should also stop granting.
    - Origin: notice orders creator to delete or restrict objects; repeated refusal → broader account sanctions.
    - Caches of metadata/CDN for previews purged.
7.  **Notify:** reporter (status), creator (reason code + appeal link), edges (purge), optional public transparency event (aggregated).
8.  **Appeal:** creator or reporter appeals with deadline; independent reviewer when resources allow; restore path reverses purge directives if overturned.
9.  **Retain:** case timeline under retention policy for audit; minimize media sample storage.

<a id="pull-mechanics-vs-creator-hosted-bytes"></a>

### 15.6 Pull mechanics vs creator-hosted bytes

**Pull means network refusal, not magical remote wipe of every USB stick.** Very unacceptable content is pulled from the *addressable network*: catalog, search, previews, edge caches, key relay, and settlement. Creators remain responsible for origin deletion. Non-compliance is handled with strikes, unlisting, and legal process—not by CDF taking master keys.

- **Addressability kill-switch:** title uid and segment ids enter a global (or regional) block list distributed to clients and edges.
- **Hash lists:** optional industry/hotline hash sharing for S0; match on preview and clear samples; ciphertext-only match when creators publish content hashes.
- **Mirror resistance:** new uploads with same perceptual/preview hash auto-queue as S0/S1.

<a id="creator-duties-and-strikes"></a>

### 15.7 Creator duties and strikes

- Respond to S1/S2 notices within published SLA.
- Strike ladder: warning → limited discovery → publish freeze → permanent exclusion from CDF.
- Willful reupload of S0 material: immediate permanent exclusion and preservation for law enforcement.
- Good-faith rapid compliance reduces residual penalties.

<a id="anti-abuse-of-the-reporting-system"></a>

### 15.8 Anti-abuse of the reporting system

- Rate limits; costliness for brand-new anonymous reporters on S2/S3.
- Detection of coordinated false reporting; reverse penalties for proven bad-faith.
- Trusted flaggers have higher weight but are audited; abuse of status revokes privilege.
- Competitors cannot delist via volume alone without evidence thresholds.

<a id="automation-and-human-review-mix"></a>

### 15.9 Automation and human review mix

- Automation: spam, duplicate detection, known-hash S0, phishing URL patterns, sudden metadata spikes.
- Humans: borderline S1/S2, contextual harm, satire/news exceptions, appeals.
- Reviewer tools: well-being features, access control, no bulk download of unrelated catalogs.
- Quality: dual-review for permanent S0/S1 when feasible; sampled QA on automated S3.

<a id="transparency-and-metrics"></a>

### 15.10 Transparency and metrics

- Periodic report: volume by category, median time-to-shield, time-to-decision, overturn rate on appeal, edge purge compliance.
- Creator dashboard: open cases, required actions, strike status.
- User: confirmation that report was received and closed category (without leaking sensitive details).

<a id="apis-descriptive-1"></a>

### 15.11 APIs (descriptive)

- `POST /v1/reports` — create report.
- `GET /v1/reports/{id}` — status for reporter.
- `POST /v1/trusted-flagger/assertions` — signed high-trust reports.
- `GET /v1/moderation/cases` — reviewer queue (authz).
- `POST /v1/moderation/cases/{id}/decision` — apply outcome.
- `POST /v1/moderation/appeals` — appeal.
- `POST /v1/edge/purge` / `ACK` — purge directives.
- `GET /v1/blocklist/delta` — client/edge block list updates.

<a id="relation-to-other-sections"></a>

### 15.12 Relation to other sections

- §8 Requirements: “misleading unlock” reports can freeze a Policy version.
- §11 Edges: purge SLA and settlement coupling.
- §18 / §17: legal skeleton and ToS hooks.
- §10: blocked titles skip key relay regardless of agent uptime.

<a id="s16"></a>

<a id="account-watch-quotas-max-48-hours-of-content-per-day"></a>

## 16) Account watch quotas (max 48 hours of content per day)

End accounts are limited to a **reasonable daily diet of streams**: by default no more than **48 hours of media timeline** per quota day, shared across devices, with a small concurrent-stream cap. This deters farm-scale re-streaming while remaining generous for real fans.

<a id="goals-1"></a>

### 16.1 Goals

- Cap abuse and industrial scraping of unlock + play paths.
- Keep casual and heavy human viewing comfortable (48h/day is a high ceiling).
- Enforce at **KeyGrant** time so ciphertext alone is not a loophole.
- Prefer **watch time** over crude “number of titles opened.”

<a id="primary-meter-watch-time"></a>

### 16.2 Primary meter: watch time

| Meter | Definition | Default limit |
|----|----|----|
| **Watch-time budget** | Seconds of media timeline advanced under an active unlock (playhead / grant window) | **48 hours** = 172,800 seconds per quota day |
| **Concurrent sessions** | Simultaneous active quota leases / grant sessions per account | **3** |
| **Session starts** (optional soft) | Distinct play sessions started | Soft warn only in MVP |

**Quota day:** account-local calendar day when timezone is known; otherwise UTC calendar day. Rolling 24h is an allowed alternate but must be disclosed in UX.

<a id="what-counts-toward-48-hours"></a>

### 16.3 What counts toward 48 hours

- **Counts:** decrypted playback progress on unlocked titles (VOD timeline or live tune-in wall clock while grants are active).
- **Charge basis:** media timeline (ABR does not multiply hours by bitrate).
- **Minimum progress:** optional grace (e.g. first 30 seconds) to ignore aborted starts.
- **Exempt when Policy says so:** previews/trailers marked `quota_exempt`.
- **Does not fully charge:** buffering stalls (use media time, not wall clock for VOD); failed unlocks.
- **Seeking (v1):** charge playhead advances with simple anti-spam; refine later if needed.

<a id="who-owns-the-bucket"></a>

### 16.4 Who owns the bucket

| Identity | Budget |
|----|----|
| Recoverable viewer root (end account) | One shared 48h pool across all enrolled devices |
| Ephemeral / anonymous device | Lower guest cap (default **4 hours**/day, **1** concurrent) |
| Devices under one root | Share the account pool; concurrency still capped |

Paid pennies **do not** bypass the network watch-time ceiling by default (otherwise bots purchase infinite play). A higher cap requires an explicit product SKU (e.g. “pro pass”), not silence.

<a id="enforcement-path"></a>

### 16.5 Enforcement path

1.  Viewer opens or renews playback → client requests a **quota lease** for `session_id`.
2.  Quota service (CDF-hosted or creator-delegated under network rules) returns remaining seconds or `429 QUOTA_EXCEEDED`.
3.  Key Agent issues/extends KeyGrants only with a valid lease and remaining budget ≥ next window.
4.  Client heartbeats media seconds advanced; lease consumes budget.
5.  On exhaust: finish current short grace (e.g. ≤ 2 minutes / current segment), then no new grants until reset.

**Authoritative gate = KeyGrant path.** Edges may still hold ciphertext; without keys, over-quota accounts cannot play.
<a id="concurrent-streams"></a>

### 16.6 Concurrent streams

- Each active lease holds one concurrency slot.
- Heartbeat expiry (e.g. 1–2 minutes) frees slots when players die.
- Over concurrency → deny new leases even if watch-time remains (stops “3 hours × 20 TVs” tricks against a naive wall-clock counter).

Note: watch-time should accrue **per active session** (parallel streams burn budget faster), which further discourages fan-out.

<a id="network-vs-creator-policy"></a>

### 16.7 Network vs creator policy

- **Network ceiling:** 48h/day and concurrency defaults (anti-farm floor).
- **Creators may tighten** per title or catalog (e.g. max 6h/day on my content).
- **Creators may not exceed** the network ceiling without a special program flag.
- Title-level `quota_exempt` only for short previews or explicitly allowed public packs.

<a id="defaults-normative-mvp"></a>

### 16.8 Defaults (normative MVP)

| Knob                         | Default                        |
|------------------------------|--------------------------------|
| `watch_time_limit_per_day`   | **48 hours**                   |
| `quota_period`               | Account-local day (else UTC)   |
| `max_concurrent_sessions`    | **3**                          |
| `anonymous_watch_time_limit` | **4 hours**                    |
| `anonymous_concurrent`       | **1**                          |
| `grace_after_exceeded`       | ≤ 2 minutes or current segment |
| `preview_exempt`             | Yes when Policy marks exempt   |
| `paid_bypasses_quota`        | **No**                         |

<a id="ux"></a>

### 16.9 UX

- Account page: used / remaining hours; reset time.
- Soft warnings near 80% and 95% of daily budget.
- Hard stop copy: “Daily watch limit reached (48 hours). Resets at …”.
- Concurrency conflict: “Too many devices playing—stop one to continue.”

<a id="apis-descriptive-2"></a>

### 16.10 APIs (descriptive)

- `GET /v1/quota/me` — used, limit, concurrent, resets_at.
- `POST /v1/quota/leases` — open session lease or 429.
- `POST /v1/quota/heartbeat` — media seconds advanced; returns remaining.
- `POST /v1/quota/leases/{id}/close` — release concurrency.
- KeyGrant requests reference `lease_id` + account binding.

<a id="anti-bypass"></a>

### 16.11 Anti-bypass

- Budget on viewer root, not cookies alone.
- Leases bound to device key + session id.
- Ephemeral identity churn from one device/IP → challenges and guest caps.
- Velocity limits on lease minting.
- Optional later: fetch tokens for ciphertext tied to lease (byte-leech friction).

<a id="relation-to-other-sections-1"></a>

### 16.12 Relation to other sections

- [§12](#s12) Identity — recoverable root owns the 48h pool.
- [§10](#s10) Key Agent — refuses grants without quota lease.
- [§9](#s9) Money — pennies do not auto-lift quota.
- [§8](#s8) Policy — creator tighten + preview exempt flags.
- [Viewer journey](#journey-viewer) — soft warnings during play.

**Normative one-liner:** Each end account may unlock and advance at most 48 hours of media timeline per day (shared across devices), with a small concurrent-stream cap; Key Agents refuse further KeyGrants when the quota lease is exhausted.
<a id="part-d-network-trust-operations"></a>

## Part D — Network, trust & operations

**Trust is a product feature.** The fabric earns its keep as a neutral town square—not as your bank and not as your vault. Clear terms. Real teeth on the worst material: delist, purge caches, stop the unlock relay, escalate. Security, privacy, and uptime so creators can promise fans the door will open when it should— and the public can believe the network is not a free-for-all dumpster fire.

<a id="s17"></a>

<a id="cdf-business-funding-tos-trust-safety-skeleton"></a>

## 17) CDF business, funding, ToS & trust-safety skeleton

<a id="what-cdf-may-charge-for-illustrative"></a>

### 17.1 What CDF may charge for (illustrative)

- Control-plane metered API (registry publishes, search, key relay).
- Optional verified-creator or custom domain features.
- Delivery settlement processing fees when creators fund ISP rebates (not a cut of access crypto to creators).
- Grants, memberships, or public funding for the neutral fabric.

CDF **does not** take custody of viewer access payments or tip funds meant for creators *by default*. Creators may opt into a disclosed micro-ledger for instant penny UX with scheduled sweeps—see [§9 Creator monetary experience](#s9).

<a id="contractual-surfaces-skeleton"></a>

### 17.2 Contractual surfaces (skeleton)

| Document | Parties | Covers |
|----|----|----|
| CDF Terms of Service | Users ↔ CDF operator(s) | Acceptable use of registry/APIs; no warranty on third-party media |
| Creator Agreement | Creators ↔ CDF | Accurate metadata, notice response SLAs, key-agent honesty, illegal-content prohibitions |
| Viewer Terms | Viewers ↔ CDF | No circumvention, abuse-report honesty, age requirements |
| Edge Operator Agreement | Edges ↔ CDF | PoD honesty, delist SLA, settlement KYC as needed |
| Verifier Code of Practice | Issuers ↔ CDF | Trust scores, fraud response, privacy minima |
| Creator ↔ Viewer terms | Set by creator | Access requirements, refunds for that title—CDF is not the merchant of record for access |

<a id="trust-safety-pillars"></a>

### 17.3 Trust-safety pillars

- **Metadata-plane enforcement:** delist, de-rank, freeze publish rights, label, geo-hide pointers.
- **Creator-plane enforcement:** notices to remove or restrict objects in origin storage; non-response escalates to registry removal and edge purge.
- **Edge-plane enforcement:** mandatory purge of flagged segment ids; settlement eligibility tied to compliance.
- **Client-plane signals:** warning interstitials, age gates, reduced discovery—not a replacement for delist of illegal material.

<a id="prohibited-and-restricted-classes-skeleton"></a>

### 17.4 Prohibited and restricted classes (skeleton)

- **Zero-tolerance illegal:** e.g. CSAM, certain terrorism content—immediate delist, edge purge, account freeze, preserve evidence under law, report to appropriate authorities where required.
- **Rapid takedown:** clear piracy per valid notice, malware/phishing pretenses, violent threats, non-consensual intimate imagery per policy.
- **Policy-restricted:** adult content, graphic violence, medical misinformation, etc.—labeling, age-gating, regional limits, optional discovery exclusion rather than always global delete.
- **Spam / scams:** deceptive metadata, engagement farming, fraudulent requirement funnels—rate limits, publish freezes, verifier blocks.

Exact legal definitions are jurisdiction-specific; the system supplies *severity-based workflows* (§15) so operators can map local law without redesigning the fabric.

<a id="data-protection-skeleton"></a>

### 17.5 Data protection skeleton

- Lawful basis and retention limits for reports, emails, PoD receipts, logs.
- Export/delete for account-linked PII; on-device keys remain user-controlled.
- Breach notification process for CDF-held personal data.

<a id="s18"></a>

<a id="governance-moderation-compliance"></a>

## 18) Governance, moderation, compliance

- CDF holds pointers and policy, not the media corpus; creators remain custodians of bytes and keys.
- Abuse reporting on metadata/previews; jurisdictional hints and geofence *tools* for creators.
- Notice workflows to creators; edges honor delist for cached ciphertext.
- Legal risk of metadata indexes remains an open operational/legal design area.

See also [§17 CDF business / ToS / trust-safety](#s17) and [§15 Viewer feedback & content review](#s15) for operational enforcement, severity classes, and pull processes.

<a id="s19"></a>

<a id="security-privacy-abuse"></a>

## 19) Security, privacy, abuse

- Signatures on metadata, manifests, attestations, key grants, edge registration, and PoD claims.
- Viewer binding on attestations and grants; nonces; short TTLs.
- Verifier reputation + creator min_trust; revocation lists.
- Rate limits on low-trust paths (especially goodwill).
- Optional per-grant watermark salts.
- Cache fraud controls: checksum audits, claim sampling, ASN caps.
- Minimal PII; device bindings rotate.

<a id="s20"></a>

<a id="observability-reliability-slas"></a>

## 20) Observability, reliability, SLAs

- Anycast/control-plane multi-region; idempotent APIs.
- Soft SLAs on verifiers with fallback unlock paths where Policy allows.
- Edge uptime/integrity SLAs by tier.
- Creator dashboards: completion, unlock conversion by path, origin vs edge GB, rebate spend, swarm health.
- Targets (product intent): control plane very high availability; media plane best-effort with degradation to origin.

<a id="centralized-view-logging-and-creator-private-detail"></a>

### 20.1 Centralized view logging and creator-private detail

**One central analytics service receives playback telemetry; both the content creator and platform operator can see the aggregate overview. Only the relevant content creator can decrypt per-viewer behavioral detail.** This analytics boundary does not grant an operator a viewer-history drill-down and does not expose one creator’s viewer detail to another.

<a id="events-and-interpretation"></a>

#### Events and interpretation

- **Views:** session start, first media played, progress, pause/resume, completion, and explicit stop. Keep buffering separate from active playback.
- **Skipping:** seek start/end positions and direction, skipped timeline intervals, playback-rate changes, and fast-forward/rewind intervals. Distinguish a seek from continuous accelerated playback; preserve media time separately from elapsed time.
- **Leaving:** last observed media position, explicit close/navigation where detectable, foreground/background transitions, and heartbeat timeout. A timeout is an inferred end, not proof of why someone left; a hidden tab does not prove absence or inattention.
- **Embedded-link departure:** for player-managed links in permitted overlays or link metadata, record the link id, title position, activation, and observable navigation outcome. Distinguish opening a new tab from leaving playback. Do not track subsequent browsing or capture destination query strings containing personal data or tokens. A URL merely pictured or spoken inside video cannot reliably be observed as a click.
- **Event envelope:** creator/title/manifest version, creator-scoped viewer pseudonym, session id, unique event id, monotonic sequence, media position/range, elapsed time, event type, and applicable disclosure/consent version. Detailed timestamps and link ids belong in the encrypted payload, not operator-visible request logs.
- **Delivery:** batch events to the central ingestion endpoint with bounded retry/offline queues, deduplication, sequence-aware handling, and explicit gaps. Browser shutdown/crash and telemetry blocking mean collection is best-effort; analytics must not claim complete observation.

<a id="visibility-and-protection"></a>

#### Visibility and protection

- **Shared overview:** views, completion and retention curves, skip/fast-forward hotspots, exit positions, link activation/departure rates, and playback-quality summaries. Display sample size, reporting interval, and uncertainty; aggregates must not expose individual session traces.
- **Creator-only detail:** detailed event payloads are encrypted on the client to a published creator analytics public key, separate from media keys. The central server stores ciphertext; the creator decrypts in a trusted creator-controlled client or processor. Platform operators, support staff, and ordinary server jobs do not hold those decryption keys.
- **Aggregate production:** a creator-controlled processor decrypts event batches and returns coarse, versioned rollups to the central dashboard service. Central collection does not imply central plaintext processing. Rollups are creator-produced, not independently verified audience measurements, and cannot alone authorize payouts.
- **Small audiences:** suppress or combine low-count buckets and restrict time/geography/link filters and repeated queries to limit singling out or differencing attacks. No raw viewer ids, exact individual timestamps, or low-count session exports in operator reports.
- **No identity promise:** creator access to a pseudonymous timeline does not automatically reveal a viewer’s name, email, or legal identity. Do not add cross-creator identity mappings to telemetry.
- **Residual exposure:** ingestion infrastructure can still observe source IP, routing metadata, and arrival timing; minimize retained metadata, batch where practical, and restrict operational log access. Encryption does not conceal all traffic correlation or prevent an operator controlling player code from changing future collection. Review the client/update trust model before claiming protection against a malicious platform operator.

<a id="purpose-retention-and-controls"></a>

#### Purpose, retention, and controls

- Disclose collection and creator-versus-operator visibility before collection; honor applicable analytics consent/opt-out requirements. Overlay opt-in is separate from analytics permission and does not silently authorize behavioral logging.
- Limit use to disclosed creator insight and service quality; no platform advertising profiles or resale of per-viewer histories. Publish retention periods for encrypted details, aggregates, ingress metadata, and creator exports, with export/deletion workflows and narrow documented legal holds.
- Analytics outages do not interrupt otherwise authorized playback. Keep billing, quota reservations, security logs, and delivery settlement on explicitly scoped operational paths; none may become an undocumented copy of the private analytics timeline. Client telemetry is not proof of human attention or payment eligibility.
- Validate duplicate/out-of-order events, abrupt departure, new-tab link clicks, blocked telemetry, consent withdrawal, creator key rotation/recovery, cross-creator isolation, operator inability to decrypt stored details, and low-count aggregate privacy before enabling collection.

<a id="s21"></a>

<a id="scalability-and-cost-posture"></a>

## 21) Scalability and cost posture

- Long tail: origin HTTP + small swarms + opportunistic cache.
- Hits: large swarms + pin/prefetch + paid or unpaid regional caches.
- Segment sizing and grant TTLs tuned for UX and cache hit rate.
- Creator calculators: storage, origin egress, verification friction vs conversion, optional delivery budgets.

<a id="part-e-—-build-contract"></a>

<a id="part-e-build-contract"></a>

## Part E — Build contract

**From vision to shipped software.** Data shapes, APIs, diagrams, glossary, and a staged roadmap— so engineers, ISPs, and partners build the same product the pitch describes. Start with publish + pennies + play. Then resilience. Then multi-ISP warmth at scale. Open questions stay honest; they do not block the first great release.

<a id="s22"></a>

<a id="data-model-conceptual"></a>

## 22) Data model (conceptual)

- **Creator:** ids, public keys, payout endpoints for *access* crypto (non-custodial), verifier allow/deny lists, delivery budgets and pin prefs, locales.
- **PublisherPage / CuratedCollection:** owner/editor identity, stable id, signed version, approved presentation fields, ordered title references, visibility, human/agent selection provenance, and canonical page/forum location (§6.11).
- **LocationAdvertisement:** publisher/title/version scope, origin/replica role, protocol and endpoint reference, signer, health/readiness evidence, last check, and expiry; no secret storage credentials or content keys (§4.8).
- **DiscoveryShare / SharedCaption / SharedReview:** publishing identity, source author/rights, asset/reference, title/version, language, audience, permitted indexing/agent use, publication/revocation version, and selection provenance; store only the assets the publisher lawfully selects for sharing (§4.8).
- **LocalCatalog / TrustRule / AgentReview:** viewer-local publisher identities, trust scopes, imported records and provenance, review outputs and limits, revocation state; not a default centralized user profile (§12.7).
- **Recommendation:** recommending publisher identity and signature, original publisher/title reference, reason/review, human/agent provenance, audience, expiry/revision; recipient acceptance and original-publisher trust remain separate (§6.12).
- **AssetManifest / PeerTransferContract / TransferReceipt:** publisher-signed immutable asset inventory/digests/root; trusted operator identities, scope, rights and onward restrictions; agreed payer/payee, pricing/caps/rail, expiry and dispute terms; signed accepted inventory and idempotent settlement state (§11.11).
- **Forum / Thread / Post:** publisher owner, stable ids, author attribution, access rules, revision/tombstone, moderation state, and replication/writer epoch. Public discovery summaries are separate from private membership, posts, and moderator audit data.
- **Title:** uid, manifest, metadata, **access Policy**, **delivery Policy**, preview assets.
- **Segment:** guid, size, checksum, storage URLs, encryption envelope refs, privacy-preserving popularity.
- **Attestation / KeyGrant:** as in §8.
- **GiftEntitlement:** unique gift id, creator/title and offer/policy version, sender, optional intended recipient, protected claim-token hash, payment reference, access scope/funded cap, expiry, redemption binding and timestamps, and refund/reversal references. Track funding and redemption states separately; atomic redemption and idempotent ledger events prevent double claims and double credits. Claim tokens are not content keys. See §9.13.
- **Edge:** operator id, keys, regions, tier, integrity score.
- **DeliveryClaim:** PoD evidence, amounts, status.
- **DelistEvent:** scope, urgency, ACKs from edges.
- **PlaybackEventBatch:** minimal routing/version envelope, creator analytics key id, and creator-encrypted session events for views, skips, speed changes, departures, and managed-link activations. Per-viewer identities and event detail remain inside the encrypted payload (§20.1).
- **PlaybackAggregate:** creator/title, coarse reporting window, metric buckets, sample sizes, suppression flags, provenance, and rollup version; shared with creator and platform operator without per-viewer drill-down.

<a id="s23"></a>

<a id="apis-interface-descriptions-not-code"></a>

## 23) APIs (interface descriptions, not code)

<a id="discovery"></a>

### 23.1 Discovery

Catalog search; title metadata; manifest summary; preview policy; localized offer copy.

Publisher-selected shared metadata/captions/reviews, page/collection lookup, filtered paginated queries and change feeds for local catalogs/agents, and fresh location resolution (§4.8). Viewer clients apply local trust rules (§12.7); read access never grants trust, posting, key access, payment authority, or private telemetry access.

<a id="requirements-broker"></a>

### 23.2 Requirements broker

- **Offer** current access Policy and unlock path UX.
- **Start / complete** actions → challenges and Attestations.
- **Fetch** attestation status; idempotency keys throughout.

<a id="key-brokering"></a>

### 23.3 Key brokering

- **Request** KeyGrants with Attestations + viewer binding → grants or reasons.
- **Revoke** grants (creator-initiated); short cache TTLs on clients.

<a id="edge-delivery-control"></a>

### 23.4 Edge / delivery control

- Edge **register** (region, ASN, capacity, protocols, tier).
- **Hints** feed: popularity, pin sets, bounty manifests, delists.
- **PoD claim** submission and dispute window.
- Settlement statements for Delivery Credits / rebates.
- No key material in these APIs.

Trusted asset exchange (§11.11): publish/verify signed asset manifests; negotiate and authorize transfer orders; inspect/resume progress; submit signed acceptance receipts; settle/dispute once; register verified HAVE/location only after completion. Separate transport authorization, ownership/licensing records, and payment state.

<a id="publisher-pages-and-forums"></a>

### 23.5 Publisher pages and forums

Versioned authorized page edits, ordered featured/collection updates, public page reads, scoped forum membership/posting/moderation, and privacy-aware export/import (§6.11). Separate public metadata lookup from authenticated write/admin endpoints; enforce ownership and thread visibility on every request.

Local/cloud publisher endpoints also publish and retrieve signed, audience-scoped recommendation records (§6.12). A recipient's local trust/catalog interfaces remain viewer-owned and are not implicitly exposed as central APIs.

<a id="s24"></a>

<a id="interoperability-contracts-summary"></a>

## 24) Interoperability contracts (summary)

- Viewer identity abstraction (keypair/DID-friendly).
- Attestation envelope (issuer, subject, scope, expiry, nonce, proof, trust, sig).
- KeyGrant envelope (creator sig, viewer aud, scope, expiry, wrapped keys).
- Deterministic Policy evaluation with explicit failure reasons.
- Verifier registry (issuer id, types, trust calibration, status).
- Edge identity + PoD claim schema + delivery Policy document on titles.
- Hard separation: **attestation ledger** vs **delivery settlement ledger**.

<a id="s25"></a>

<a id="extensibility"></a>

## 25) Extensibility

- New requirement types: schema, verifier, UX, Policy ops.
- New chains/wallets for crypto receipts.
- New transports (e.g. WebTransport).
- New settlement instruments for delivery without touching access Policy.

<a id="s26"></a>

<a id="architecture-diagrams"></a>

## 26) Architecture diagrams

<a id="system-context"></a>

### 26.1 System context

Control plane vs media plane

**Creator + CEA** — Origin storage · Key Agent ↔ **CDF** — Catalog · Verify · Keys relay · Moderation · Edges ↔ **Viewer** — Requirements · Decrypt · Report

**S3 / MinIO** — Ciphertext segments → **P2P swarm** — Piece exchange → **ISP / Edge** — Cache ciphertext · Purge → **Viewer** — Fetch bytes

Metadata, attestations, grants, reports, and purge orders travel on the CDF plane. Encrypted media moves on origin, swarm, and edge paths.

<a id="unlock-sequence"></a>

### 26.2 Unlock sequence

**1. Discover** — Catalog + preview → **2. Fulfill** — Requirement path → **3. Attest** — Verifier signature → **4. Key request** — CDF → Key Agent → **5. Play** — Fetch + decrypt

If title is moderation-blocked, steps 4–5 fail closed even when bytes still exist somewhere offline.

<a id="report-review-pull"></a>

### 26.3 Report → review → pull

**Viewer / flagger** — Report + evidence → **Intake & triage** — S0–S4 class → **Shield** — Provisional delist → **Review decision** — Human / auto → **Pull** — Registry · Edge purge · Key relay deny · Creator notice

**Appeal** — Creator or reporter → **Restore or uphold** — Reverse purge if needed

Very unacceptable content is removed from network addressability quickly; origin deletion is enforced through creator duty and strikes.

<a id="pennies-per-view-money-path"></a>

### 26.5 Pennies-per-view money path

**Viewer session** — Cap · micro-rail → **Watch start** — Decrypt / T+3s → **Ledger** — Pending → Available → **Creator console** — Live ticker → **Sweep** — Creator wallet

KeyGrants follow Policy + payment attestation; ISP delivery rebates stay on a separate cost ledger.

<a id="key-agent-delegation"></a>

### 26.4 Key Agent delegation

**Creator root** — Master policy & keys → **Delegation Grant** — Scope · TTL · caps → **Delegated agents** — Sign KeyGrants → **Viewer** — Verify chain

Revocation lists at CDF make compromised agents untrusted without moving master keys into the fabric.

<a id="multi-isp-cache-business-flow"></a>

### 26.6 Multi-ISP cache business flow

**1. Viewer pennies** — Creator ledger → **2. Heat / boost** — Delivery budget → **3. Fill leases** — Per cell · K primaries → **4. Many ISPs HAVE** — Diversity target → **5. Hit rebates** — Each serving ASN

Access earnings and delivery settlement stay on separate ledgers. Block/purge can halt step 3–5.

<a id="s27"></a>

<a id="glossary"></a>

## 27) Glossary

**Content creator**

Principal who publishes video and expects payment on paid views while retaining storage, keys, and policy control.

**ABR**

Adaptive bitrate ladder of renditions for varying network/device conditions.

**Attestation**

Signed claim that a viewer satisfied a Requirement, with trust score and expiry.

**Block list**

Distributed set of title/segment ids that clients and edges must not present or serve.

**CDF**

Coordination & Discovery Fabric — control plane for catalog, verification broker, key relay, edges, moderation.

**CEA**

Creator Endpoint App — ingest, encrypt, upload, optional seed, local or connected Key Agent.

**CEK**

Content encryption key for a segment (or small set of segments).

**Delegation Grant**

Creator authorization for a third-party Key Agent to sign KeyGrants under constraints.

**Delivery Credits**

Settlement units for edge caching/seeding work; separate from access payments.

**HLS**

HTTP Live Streaming: playlist-based adaptive media presentation, used here over HTTPS with creator-controlled encrypted segments.

**WebTorrent**

Browser-capable peer delivery using WebRTC; the basis for HLS peer assistance, with engine-specific compatibility verified before release (§7.7).

**Key Agent**

Service that evaluates Policy and issues KeyGrants; may be local or delegated.

**Gift entitlement**

Purchased access offered to another viewer and redeemed into recipient-bound KeyGrants; never a transfer of the sender’s decryption keys. Creator-defined scope, normal safety checks, and recipient consent apply.

**KeyGrant**

Short-lived, viewer/device-bound authorization material to unwrap segment CEKs.

**Manifest**

Signed, versioned description of a title’s timeline, tracks, and segment refs.

**PoD**

Proof of Delivery — evidence used for edge settlement, not for unlock.

**Policy (access)**

Boolean requirements expression controlling when KeyGrants may issue.

**Policy (delivery)**

Caching, pin, prefetch, and rebate configuration for a title.

**Pull**

Network-side removal of addressability (catalog/edges/key relay), plus creator origin duties.

**Purge Directive**

Order to edges to delete cached ciphertext/previews for specified ids.

**Requirement**

A verifiable unlock condition (goodwill, puzzle, email, social, crypto receipt, etc.).

**S0–S4**

Moderation severity classes from emergency illegal to subjective taste.

**Segment**

Addressable media chunk with its own id, checksum, and usually its own CEK.

**Title**

Logical work users discover; stable uid over manifest versions.

**Trusted flagger**

Vetted reporter whose assertions receive higher routing priority and audit duties.

**Verifier**

Issuer that produces Attestations for a requirement type.

**Available balance**

Creator funds that have passed rail finality (and optional short fraud window).

**Ledger Credit**

Append-only earning event from a paid view, meter tick, unlock, or tip.

**Micro-ledger**

Optional opt-in balance book for penny-scale earnings before sweep to external wallet.

**Pending balance**

Earnings observed from viewing/payment signals not yet final on the rail.

**per_view / per_minute**

Penny-scale pricing primitives accruing when paid viewing starts or continues.

**Watch session**

Funded viewer period binding payment rail, title, caps, and KeyGrant extensions.
<a id="s28"></a>

<a id="mvp-roadmap"></a>

## 28) MVP roadmap

<a id="phase-0-foundations"></a>

#### Phase 0 — Foundations

Spike / weeks

- Segment encrypt/upload to MinIO/S3; signed metadata schema.
- Single-node registry + encrypted HLS web player (HTTPS only initially); validate HLS/container/encryption and KeyGrant adapter compatibility (§7.7).
- One requirement path (goodwill or puzzle) + local Key Agent.
- Appliance spike (§6.10): candidate hardware measurements, installer/image prototype, off-network probes, direct/relay fallback, and recovery/update failure tests.

<a id="phase-1-mvp-network"></a>

#### Phase 1 — MVP network

First useful product

- ABR VOD manifests; captions track; preview packs.
- Email + crypto-receipt verifiers (optional); Policy anyOf/allOf.
- Identity: device keypair + optional recoverable account.
- Basic report button → manual admin delist + edge purge stub.
- Creator console: publish, policy, simple analytics.
- Publisher-owned pages and feedback forums (§6.11): editable public home, ordered highlights, attributed human niche collections, scoped moderation, and export/cloud recovery; metadata/location library interfaces for public discovery and viewer-chosen read-only agent clients (§4.8).
- Trust-first discovery (§12.7): local catalog/trust rules, explicit unknown-source review, publisher-selected caption/review sharing, agent review controls, and lightweight local/cloud recommendation publishing (§6.12).
- Publisher cloud backup origin (§4.7): verified pre-publish replication, independent unlock continuity, automatic HLS origin failover/failback, health/cost disclosure, and unplugged-appliance acceptance tests.
- Turnkey creator appliance (§6.10): release support matrix, signed installer/images, guided storage/identity/recovery setup, disclosed connectivity fallback, secure updates, and passing nontechnical first-publish tests on each supported profile.
- Monetary MVP: penny `per_view` path, pending/available ledger, live ticker, sweep to creator wallet (prepaid or LN/L2 if ready).
- Gifted views (§9.13): creator-enabled gift offers, funded single-use redemption, recipient-bound grants, consent-based notifications, and disclosed expiry/refund rules. Validate concurrent claims, duplicate payment events, blocked titles, and capped playback before enabling paid gifting.

<a id="phase-2-scale-resilience"></a>

#### Phase 2 — Scale & resilience

Early growth

- WebTorrent/WebRTC-assisted HLS: compatible browser/appliance seeds, operated trackers, sharing controls, verified ciphertext, and reliable HTTPS fallback (§7.7); delegated Key Agent mode and health on title pages.
- Multi-device limits; org roles for creators.
- Moderation queue with S0–S4, trusted flaggers, appeals.
- Block list delta API to clients; strike ladder.

<a id="phase-3-edges-live"></a>

#### Phase 3 — Edges & live

Partners

- ISP edge registration, PoD, transit-only then rebate budgets.
- Trusted-peer asset exchange (§11.11): publisher-authorized compensated transfer/hosting contracts, signed checksummed inventories, resumable verification, receipts, and budgeted dispute-aware settlement.
- Multi-ISP model (§5): fill leases, replica targets, diversity bonuses, popular multi-home packages, optional matching pool.
- Live manifests + windowed grants; live-to-VOD finalize.
- Transparency reports; verifier code of practice enforcement.

<a id="phase-4-federation-hardening"></a>

#### Phase 4 — Federation & hardening

Maturity

- Multi-CDF or mirror policies; hash-list partnerships for S0.
- Quorum agents; advanced watermarking; formal conformance tests.
- Broader i18n and accessibility certification.

**MVP success bar:** a creator can publish encrypted VOD from their own bucket, set a non-card unlock rule, viewers play through HTTP, and severe abuse reports can delist and purge addressability without the CDF ever holding master keys or access funds.

<a id="s29"></a>

<a id="open-questions-and-risks"></a>

## 29) Open questions and risks

- Standard proof-of-attention without invasive tracking.
- Disputes/refunds when access value was goodwill, puzzle, or non-custodial crypto.
- Legal exposure of global metadata pointers.
- Offline playback with expiring per-segment keys.
- PoD ground truth (client vs edge vs probers) and cross-border tax on delivery rebates.
- Zero-rating / telco billing integrations as partner-specific extensions.
- Cooperative multi-ISP cold-start vs pure competition.
- Fair cache fill when many edges race to store the same cold object — addressed normatively in [§5](#s5) (fill leases, replica caps, diversity pay); residual: cell map politics and federated coordinators.
- Key Agent offline behavior under flash crowds (mitigations in §10; residual risk remains).
- False-positive rate of hash/match lists vs creator sovereignty.
- Who pays for human review at scale; appeals fairness across jurisdictions.
- Micropayment rail portability and tax reporting for penny balances across borders.
- How hard to claw back pending credits after bot rings without punishing legit creators.

**xjet-swarma-video** high-level design.

Reading order follows creator and viewer journeys; § numbers match the journey-first reading order.

High-level design document · implementation-agnostic · access path, delivery path, trust-safety pull path, and creator earnings ledger kept separate by design.

Parts A–E · sections §1–§29 in reading order · File: `creator-hosted-video-network-design.html`
