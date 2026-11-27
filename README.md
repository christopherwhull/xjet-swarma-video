# xjet-swarma-video

## Your publishers. Your catalog. Your choice.

**Creator-owned video. Human-led niche curation. Or discovery through your own AI agent.**

xjet-swarma-video is a design for a video network where **publishers own their content and communities, viewers control whose work reaches them, and trusted peers help deliver the video.**

The platform is a library of shared information and current content locations—not a warehouse that owns everyone's videos, and not a compulsory recommendation feed.

> **Project status: design and specification.** This repository contains documentation, not a working application or launched network. The capabilities below describe the intended product; there are no appliance downloads, production payment services, or measured scalability results yet.

**Start here:** [The model](#the-model-at-a-glance) · [Publishers](#publish-your-work-own-your-presence) · [Viewers](#trust-before-attention) · [Peer exchange](#video-assets-can-move-between-trusted-peers) · [Roadmap](#proposed-roadmap) · [Full documentation](#read-the-design)

## The model at a glance

| Participant | What they control or provide |
| --- | --- |
| **Video publisher** | The video library, encryption keys, access terms, prices, public page, highlighted videos, and feedback forum. |
| **Viewer** | A local catalog, trusted publisher identities, personal discovery preferences, and any agent they authorize to review content. |
| **Recommendation publisher** | Their own signed recommendations, reviews, or collections, published from a lightweight local or cloud setup. |
| **Trusted delivery peer** | Agreed transfer, storage, or serving capacity, with publisher authorization and verifiable asset integrity. |
| **Coordination platform** | Publisher-shared discovery information, current locations, verification/key-request brokering, safety workflows, and separately protected operational records. |

**Discovery is not permission to watch. Trust is not copyright. Delivering bytes is not ownership of the video.**

## Publish your work. Own your presence.

A publisher brings the work and the right to distribute it. They decide how it is presented and what viewers must do to watch.

- **Your library and keys:** media stays on publisher-controlled infrastructure, not in the platform's custody.
- **Your page:** a channel-like home with your introduction, selected videos, ordered collections, and announcements.
- **Your highlights:** the platform does not silently replace publisher-picked selections with promotions.
- **Your feedback forum:** set community rules, appoint moderators, and export or move the community data while respecting contributors' rights and privacy.
- **Your offer:** free access paths, penny-scale paid views, metered access, or other disclosed requirements.
- **Your earnings:** distinguish pending, available, and withdrawable amounts; payment follows publisher-selected rails.

Publishing is broader than making videos. **A viewer who shares recommendations becomes a publisher of those recommendations**, without acquiring the original video's rights, keys, or earnings.

See [publisher pages and forums (§6.11)](docs/design.html#publisher-pages) and [recommendation publishing (§6.12)](docs/design.html#recommendation-publishing).

## Trust before attention

**Publishing more content does not buy a place in someone's feed.**

Viewers find publishers through friends, communities, websites, direct links, external search, or shared directories. They choose which identities to trust and maintain their own local catalog.

- Untrusted publishers do not populate ordinary feeds, notifications, previews, or autoplay.
- Inspecting an unfamiliar publisher is a separate, explicit discovery action.
- Human niche curators can explain their selections and publish attributed collections.
- A viewer's chosen agent can review permitted metadata, closed captions, reviews, and already-authorized content within the viewer's rules.
- Trusting a recommender does **not** automatically subscribe the recipient to every original publisher they mention.
- Local trust lists and catalog histories are not default centralized user profiles.

AI can flood an index without earning attention. That does **not** eliminate infrastructure spam, compromised trusted accounts, or dishonest recommendations; limits, revocation, and reporting still matter.

See [viewer-owned catalogs and trust (§12.7)](docs/design.html#local-catalog).

## What the centralized servers hold

**What publishers choose to share—and where to find their content.**

The discovery library can contain:

- Publisher identities, public page information, and selected collections.
- Video descriptions, language/accessibility information, warnings, and viewing offers.
- Closed captions or transcripts the publisher explicitly chooses to share.
- Authorized reviews, excerpts, or references, with attribution and selection provenance.
- Signed media descriptions, ciphertext checksums, and fresh local/cloud/peer location records.

Full transcripts are optional: they can disclose the substance of paid video even while the media remains encrypted. Private forum data, media keys, and per-viewer histories are not public catalog entries.

Separate services still handle verification, key-request relaying, quotas, safety cases, applicable financial records, and encrypted analytics. **“Metadata library” describes discovery, not an excuse to ignore those private records.**

See [metadata and location libraries (§4.8)](docs/design.html#metadata-library).

## Dependable delivery without surrendering the library

The delivery basis is **HLS over HTTPS, assisted by WebTorrent/WebRTC peers**.

1. A guided creator appliance prepares, encrypts, and publishes the video.
2. Locally originated published titles have a verified serving replica on a **cloud instance operated and paid for by the publisher**.
3. The player can fetch matching encrypted segments from local/cloud origins, compatible peers, or eligible edge caches.
4. If the local appliance is unplugged, media falls back to the publisher's cloud origin. An independent authorized Key Agent path keeps new unlocks available.
5. HTTPS remains the baseline when peer assistance is unavailable or disabled.

The turnkey experience targets supported PCs and selected Raspberry Pi-class hardware, with safe installers/images, guided setup, signed updates, recovery, and an unassisted off-network first-publish test.

These are requirements, not shipped installers or certified hardware claims. Browser/encryption compatibility, failover timing, and actual peer savings must be tested. A cloud replica cannot generate missing live footage, and simultaneous failures can still cause an outage.

[Appliance requirements (§6.10)](docs/design.html#turnkey-appliance) · [Cloud backup (§4.7)](docs/design.html#cloud-backup-origin) · [WebTorrent/HLS basis (§7.7)](docs/design.html#webtorrent-hls)

## Video assets can move between trusted peers

Publishers can authorize trusted operators to **transfer, hold, or serve video assets for agreed compensation**.

- A publisher-signed manifest identifies the exact asset version, inventory, and cryptographic checksums.
- Transfers can resume, but only against the same verified asset identity.
- The receiver checks the required inventory and bytes before signing acceptance.
- Explicit contracts define counterparties, price, permitted use, storage term, onward distribution, spending caps, and dispute rules.
- Settlement is idempotent; duplicate receipts do not mean duplicate payments.

**Matching checksums prove matching bytes against the signed reference.** They do not prove copyright ownership, the truth of a description, or that someone watched. Copying/hosting does not transfer copyright or viewer unlock authority; any licence or sale of rights needs an explicit agreement.

See [trusted-peer asset exchange (§11.11)](docs/design.html#trusted-peer-exchange).

## Honest economics and viewer relationships

**No platform-injected ads or promotions.** Quality questionnaires are the only platform-inserted engagement and remain voluntary and noncommercial. Optional video overlays require **both publisher and viewer opt-in before display**.

Publisher-embedded sponsorship remains part of the video; paying does not remove it unless the offer explicitly provides an alternate edit.

The financial boundaries are equally explicit:

1. **Viewer → publisher:** paid access value; free paths can remain free.
2. **Publisher or another explicit funder → delivery operators:** separately funded transfer, storage, or delivery compensation—not an automatic ISP cut of view pennies.
3. **Users/operators → coordination services:** disclosed service fees, separate from access earnings and delivery budgets.

The platform is not the default custodian or merchant of record for access funds. Any optional custodial micro-ledger must be explicitly selected and disclosed. Safety blocks can stop new distribution and paid delivery claims.

**Gifted views:** “userxyz bought you a view” means a purchased entitlement redeemed into fresh recipient-bound grants—not shared decryption keys or purchased trust.

**Analytics:** publisher and platform operator share aggregate overviews. Detailed per-viewer playback events are encrypted for the relevant publisher, with disclosure, applicable consent, and retention controls.

[Pricing and gifts (§9)](docs/design.html#s9) · [Overlay rules (§7.6)](docs/design.html#s7) · [Analytics (§20.1)](docs/design.html#s20)

## Safety and limits

Creator ownership does not remove responsibility for rights, privacy, or unlawful content. The design includes reporting, severity-based review, notices, appeals, network delisting, and cache purge obligations.

Default watch quotas are **48 media-hours per account per day**, shared across devices, with **three concurrent sessions**; guests have lower limits. These gate new KeyGrants, not previously copied plaintext. Payment does not automatically bypass quotas.

[Review and enforcement (§15)](docs/design.html#s15) · [Watch quotas (§16)](docs/design.html#s16) · [Open risks (§29)](docs/design.html#s29)

## Proposed roadmap

| Phase | Intended focus—not completed milestones |
| --- | --- |
| **0 — Foundations** | Encrypted HLS/HTTPS playback, signed metadata, local Key Agent, appliance/connectivity and recovery prototypes. |
| **1 — First useful network** | Publisher pages/forums, local trust catalogs, recommendation publishing, shared metadata/captions/reviews, publisher cloud failover, turnkey setup, penny payments/gifts, and basic review tools. |
| **2 — Scale and resilience** | WebTorrent/WebRTC peer assistance, compatible seeds, sharing controls, delegated Key Agents, expanded moderation, and coordinated fills. |
| **3 — Delivery partners and live** | Compensated trusted-peer asset exchange, ISP/edge verification and incentives, multi-network replication, and live streaming. |
| **4 — Federation and hardening** | Independent/mirrored discovery services, conformance testing, quorum agents, and broader accessibility. |

Independent competing portals are **not yet implemented or fully specified**. Local catalogs and portable records reduce dependence on a central feed; they do not by themselves complete federation.

See [the full roadmap (§28)](docs/design.html#s28).

## Read the design

| Document | Purpose |
| --- | --- |
| **This README** | GitHub-native project introduction and current direction. |
| **[Executive overview](index.html)** | Publisher responsibilities, viewer choice, community ownership, and the business proposition. |
| **[Full design](docs/design.html)** | Architecture, journeys, proposed interfaces, economic boundaries, and acceptance criteria. |
| **[Video proposal comparison](docs/video-comparison.html)** | Timestamped original goals, design coverage, intentional differences, and gaps. |

The HTML links open repository files on GitHub. For the styled pages, open `index.html` locally after cloning; this README is intended to be readable directly on GitHub.

**Original inspiration:** [xjet — “At last, something bigger and better than YouTube”](https://www.youtube.com/watch?v=eEjYXw3j4pM). This is a proposal, not a demo of this repository. Our non-injection policy, access payments, and separate peer compensation deliberately differ from its portal pre-roll advertising model.

## License

Repository materials are licensed under [Apache-2.0](LICENSE). That does not grant rights to third-party videos or to media a future publisher distributes.
