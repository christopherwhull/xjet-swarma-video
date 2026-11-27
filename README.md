# xjet-swarma-video

## Your publishers. Your catalog. Your choice.

**Creator-owned video. Human-led niche curation. Or discovery through your own AI agent.**

xjet-swarma-video is a design for a video network where **publishers own their content and communities, viewers control whose work reaches them, and trusted peers help deliver the video.**

The platform is a library of shared information and current content locations—not a warehouse that owns everyone's videos, and not a compulsory recommendation feed.

> **Project status: design and specification.** This repository contains documentation, not a working application or launched network. The capabilities below describe the intended product; there are no appliance downloads, production payment services, or measured scalability results yet.

**Start here:** [Why this project](#why-i-am-creating-this-project) · [Definable goals](#clear-definable-goals) · [Video CC comparison](#video-closed-captions-vs-our-design) · [The model](#the-model-at-a-glance) · [Roadmap](#proposed-roadmap) · [Full documentation](#read-the-design)

## Why I am creating this project

I want a video network that serves the relationship between a publisher and a viewer, rather than owning that relationship.

- **Keep ownership with the publisher.** Videos are assets. Publishers should control their files, keys, viewing terms, public pages, highlighted work, and feedback communities—and be able to move them.
- **Let viewers decide who earns their attention.** An AI-generated content flood should not become an unavoidable feed. Viewers choose trusted publishers, maintain a local catalog, and can use human niche curators or their own reviewing agents.
- **Keep the platform out of the advertising relationship.** No platform-injected ads or promotions. Overlays require both sides' prior permission; quality questionnaires are not an excuse to insert commercial surveys.
- **Make payment understandable.** Publishers should see penny-scale earnings when paid viewing begins, with honest confirmation states and explicit fees—not an unexplained revenue allocation. Free viewing paths remain possible.
- **Distribute delivery without giving away the library.** Trusted peers can move matching, verified assets and earn agreed compensation. That must not silently surrender publishing rights or divert viewing revenue.
- **Make independence practical.** A creator should not need to be a server administrator. Guided setup, publisher-operated cloud backup, recovery, and working off-network playback are part of the product—not afterthoughts.
- **Keep central services useful but limited.** Central libraries hold what publishers choose to share, including metadata, captions, reviews, and locations. They must not become the owner of the media, the viewer's private trust graph, or the only way people find publishers.

The original xjet video is an inspiration, not a specification to copy unchanged. This project deliberately takes a different approach to portal advertising, payment, and viewer-local discovery. The comparison below makes those differences explicit.

## Clear, definable goals

These are **future acceptance criteria**, not claims that the software already passes them. Each goal must be demonstrated before the corresponding feature is described as delivered.

| Goal | What a demonstrable result looks like |
| --- | --- |
| **1. Publisher ownership and portability** | A publisher exports/restores their library metadata, keys, page, highlights, and authorized forum data onto another supported setup, preserving identities and permissions without transferring master keys to the platform. [§6](docs/design.md#s6) |
| **2. Nontechnical first publication** | A non-server-administrator follows the installer/wizard without terminal commands or engineer intervention; a separate off-network viewer unlocks and watches the reference video to completion. Report setup time and unassisted completion rate. [§6.10](docs/design.md#turnkey-appliance) |
| **3. Local trust controls attention** | Flood the shared index with untrusted publishers: the viewer's normal feed, notifications, previews, and autoplay do not change. Trusting, blocking, and explicitly inspecting a new source work independently. [§12.7](docs/design.md#local-catalog) |
| **4. Discovery and sharing remain user-controlled** | Import a publisher from a direct link and a directory; review permitted metadata/captions/reviews with a chosen agent; send a signed recommendation from both local and cloud publishing modes. Recipient acceptance does not create transitive trust. [§6.12](docs/design.md#recommendation-publishing) |
| **5. No commercial injection** | No platform ad is inserted. Test all four publisher/viewer overlay-consent combinations: only both-enabled displays an overlay, and revocation stops it. Quality questionnaires remain voluntary and noncommercial. [§7.6](docs/design.md#s7) |
| **6. Transparent access payments** | A funded paid session produces an idempotent pending credit, transitions according to rail finality, respects its cap, and reconciles failure/refund. A gifted view issues recipient-bound grants without copying sender keys. [§9](docs/design.md#s9) |
| **7. Local outages have a publisher-owned fallback** | Verify replication before publication; disable peers/edges and unplug the local appliance during playback. Cloud delivery and fresh authorized unlocks work; record failover/rebuffer time and test safe recovery. [§4.7](docs/design.md#cloud-backup-origin) |
| **8. Peer transfers preserve exact assets and agreed compensation** | Two authorized peers transfer the signed asset version, verify its complete inventory/checksums, and settle the agreed contract once. Reject corruption, wrong versions, unauthorized recipients, and replayed receipts. [§11.11](docs/design.md#trusted-peer-exchange) |
| **9. Shared information stays within its stated boundary** | Central discovery contains only the lawfully selected shared assets and necessary disclosed registration fields. Private forums, local trust lists, content keys, and per-viewer analytics do not appear in public responses; operators cannot decrypt creator-private analytics. [§4.8](docs/design.md#metadata-library), [§20.1](docs/design.md#s20) |
| **10. Distributed delivery earns its claims** | Demonstrate encrypted HLS over HTTPS first, then compatible WebTorrent peers with seeking, quality switching, captions, and HTTP fallback. Measure origin traffic and rebuffering against an HTTP-only baseline; publish results instead of assuming savings. [§7.7](docs/design.md#webtorrent-hls) |
| **11. Ownership coexists with safety and recovery** | Exercise reporting, review, appeal, withdrawal, and purge propagation across local/cloud origins and compliant peers. Returning nodes cannot resurrect removed content; document the limits for hostile or offline copies. [§15](docs/design.md#s15) |

Some numerical release thresholds—such as acceptable setup time and failover delay—still need to be selected and published under the design's test conditions. They are not replaced by a claim that something is simply “fast,” “easy,” or “scalable.”

## Video closed captions vs our design

Source: [xjet — “At last, something bigger and better than YouTube”](https://www.youtube.com/watch?v=eEjYXw3j4pM), English auto-generated closed captions, compared on **27 November 2026**. The source goals below are **paraphrases**, not verbatim quotations; automatic captions can mishear names and technical terms. [Caption-based transcript](https://www.withtranscript.ai/video/eEjYXw3j4pM).

**Coverage describes the document, not implemented software:** **Aligned** = explicitly covered; **Partial** = covered with unresolved details; **Different** = an intentional alternative; **Gap/deferred** = not fully specified or scheduled later.

| Goal from the CC contents | Video passage | What our design provides | Coverage and remaining work |
| --- | --- | --- | --- |
| **Creators own their video library** | [7:13–8:34](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=433): replace dependence on platform-owned hosting with creator servers. | Publisher-owned storage, keys, access terms, pages, and community data. [§2](docs/design.md#s2), [§6](docs/design.md#s6) | **Aligned.** Ownership does not guarantee discovery, reach, or income. |
| **Use an old PC or Raspberry Pi** | [7:58–9:07](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=478): inexpensive hardware and USB storage host modest catalogs. | PC and selected 64-bit Raspberry Pi-class targets with a required versioned support matrix. [§6.10](docs/design.md#turnkey-appliance) | **Partial.** No certified hardware, appliance image, or measured serving/encoding limits yet. |
| **Make installation turnkey** | [9:07–9:51](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=547), [13:53–14:30](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=833): install/flash, plug in, and follow a wizard. | Signed installer/images, browser setup, safe storage selection, updates, recovery, and a nontechnical first-publish test. [§6.10](docs/design.md#turnkey-appliance) | **Aligned at design level.** Downloads and successful user tests have not been delivered. |
| **Keep home-hosted video reachable** | [9:07–9:51](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=547): dynamic DNS handles changing addresses. | Required publisher-operated cloud replica, pre-publish verification, origin failover, and independent unlock continuity; NAT tunnels are only a connectivity aid. [§4.7](docs/design.md#cloud-backup-origin) | **Partial.** Goes beyond dynamic DNS; integration and measured failover remain unimplemented. |
| **Bring discovery together** | [9:51–10:29](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=591): a portal avoids checking thousands of servers individually. | Shared metadata/caption/review/location libraries feed viewer-owned, trust-gated local catalogs and reviewing agents. [§4.8](docs/design.md#metadata-library), [§12.7](docs/design.md#local-catalog) | **Different.** Unified information, but the viewer—not a compulsory portal feed—controls ordinary selection. |
| **Have many competing portals** | [11:11–13:53](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=671): independent portals compete for publisher participation. | Portable signed records and client interfaces; multi-CDF/mirror policies are placed in Phase 4. [§28](docs/design.md#s28) | **Gap/deferred.** Independent portal enrollment, cross-portal continuity, and federation are not complete. |
| **Use human niche curators** | [10:29–11:55](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=629): people with subject expertise choose useful videos. | Publisher-selected highlights and attributed collections; viewers may choose their own agent. Users share signed recommendations from local/cloud setups. [§6.11](docs/design.md#publisher-pages), [§6.12](docs/design.md#recommendation-publishing) | **Partial.** Editorial control is defined; independent portal governance and the working experience remain open. |
| **Pay creators through portal ad revenue** | [11:55–12:33](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=715), [16:45–17:30](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=1005): portals show pre-rolls and negotiate creator shares. | Publisher-controlled micropayments/free paths, explicit fees, and pending/available earnings; no platform-injected ads. [§9](docs/design.md#s9), [§17](docs/design.md#s17) | **Different.** Monetization is retained, not the pre-roll revenue-share model. Economics and payment demand need validation. |
| **Protect viewers from scam advertising** | [0:00–1:30](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=0), [2:23–3:02](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=143): an individual's ad blocker does not protect other viewers. | No platform commercial injection; overlays require bilateral consent; creator sponsorship and external links remain reportable. [§2](docs/design.md#s2), [§7.6](docs/design.md#s7) | **Different.** Removes platform ad inventory rather than rebuilding the video's later pre-roll model. Consent alone does not make a promotion safe. |
| **One portal cannot erase a creator's livelihood** | [12:33–13:53](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=753): other portals can continue carrying a rejected creator. | Files/keys stay with publishers and local catalogs are viewer-controlled, but network delists, key relays, and quotas still affect access. [§15](docs/design.md#s15), [§28](docs/design.md#s28) | **Partial.** Discovery/access independence across operators is not fully specified; safety and legal obligations remain. |
| **Replicate popular videos across peers** | [14:30–15:13](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=870): other home servers contribute copies and bandwidth. | WebTorrent/WebRTC-assisted HLS, ciphertext caches, signed asset identity, fill leases, and replica policies. [§7.7](docs/design.md#webtorrent-hls), [§5](docs/design.md#s5) | **Partial.** Seed interoperability, home-node operation, encryption adapters, and measured capacity still need delivery. |
| **Compensate peers for serving others' videos** | [15:13–16:07](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=913): peers receive a smaller share of advertising revenue. | Separately funded delivery incentives and trusted-peer transfer/hosting contracts with matching checksums, verified receipts, and explicit settlement terms. [§11.11](docs/design.md#trusted-peer-exchange) | **Different.** Compensation is contracted, not an automatic ad share. Fraud resistance and settlement must be tested. |
| **Publish once and notify participating portals** | [13:53–14:30](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=833), [16:07–16:45](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=967): publishing sends portals a thumbnail and availability notice. | Signed metadata publication and change feeds support catalogs; the full independent-portal enrollment/fan-out contract is not specified. [§13](docs/design.md#s13), [§23](docs/design.md#s23) | **Partial.** Portal discovery, participation agreements, and interoperable notification delivery remain work. |
| **Prevent bypassing the viewing requirement** | [16:45–17:30](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=1005): an encrypted link is proposed to enforce pre-roll viewing. | Actual encrypted media and publisher-issued, scoped viewer-bound KeyGrants. [§8](docs/design.md#s8), [§10](docs/design.md#s10) | **Different.** Controls key release, not proof of human attention; previously delivered keys/plaintext cannot reliably be recalled. |
| **Scale without one company's giant data center** | [1:30–2:23](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=90), [17:30–18:37](https://www.youtube.com/watch?v=eEjYXw3j4pM&t=1050): many small servers pool capacity at low individual cost. | Distributed publisher/cloud origins and peers, with a smaller coordination plane. [§4](docs/design.md#s4), [§21](docs/design.md#s21) | **Partial.** Distributed resources still cost money; aggregate link speed is not measured usable delivery capacity. |

**Beyond the video's proposal:** the design also specifies publisher-owned feedback forums, trust-gated local catalogs, gifted views, creator-private playback analytics, cloud failover, and explicit safety/appeal workflows. These are additions—not evidence that the video's original model has already been implemented.

The [detailed comparison](docs/video-comparison.md) provides the longer assessments. This table stays directly in the README for a quick source comparison.

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

See [publisher pages and forums (§6.11)](docs/design.md#publisher-pages) and [recommendation publishing (§6.12)](docs/design.md#recommendation-publishing).

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

See [viewer-owned catalogs and trust (§12.7)](docs/design.md#local-catalog).

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

See [metadata and location libraries (§4.8)](docs/design.md#metadata-library).

## Dependable delivery without surrendering the library

The delivery basis is **HLS over HTTPS, assisted by WebTorrent/WebRTC peers**.

1. A guided creator appliance prepares, encrypts, and publishes the video.
2. Locally originated published titles have a verified serving replica on a **cloud instance operated and paid for by the publisher**.
3. The player can fetch matching encrypted segments from local/cloud origins, compatible peers, or eligible edge caches.
4. If the local appliance is unplugged, media falls back to the publisher's cloud origin. An independent authorized Key Agent path keeps new unlocks available.
5. HTTPS remains the baseline when peer assistance is unavailable or disabled.

The turnkey experience targets supported PCs and selected Raspberry Pi-class hardware, with safe installers/images, guided setup, signed updates, recovery, and an unassisted off-network first-publish test.

These are requirements, not shipped installers or certified hardware claims. Browser/encryption compatibility, failover timing, and actual peer savings must be tested. A cloud replica cannot generate missing live footage, and simultaneous failures can still cause an outage.

[Appliance requirements (§6.10)](docs/design.md#turnkey-appliance) · [Cloud backup (§4.7)](docs/design.md#cloud-backup-origin) · [WebTorrent/HLS basis (§7.7)](docs/design.md#webtorrent-hls)

## Video assets can move between trusted peers

Publishers can authorize trusted operators to **transfer, hold, or serve video assets for agreed compensation**.

- A publisher-signed manifest identifies the exact asset version, inventory, and cryptographic checksums.
- Transfers can resume, but only against the same verified asset identity.
- The receiver checks the required inventory and bytes before signing acceptance.
- Explicit contracts define counterparties, price, permitted use, storage term, onward distribution, spending caps, and dispute rules.
- Settlement is idempotent; duplicate receipts do not mean duplicate payments.

**Matching checksums prove matching bytes against the signed reference.** They do not prove copyright ownership, the truth of a description, or that someone watched. Copying/hosting does not transfer copyright or viewer unlock authority; any licence or sale of rights needs an explicit agreement.

See [trusted-peer asset exchange (§11.11)](docs/design.md#trusted-peer-exchange).

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

[Pricing and gifts (§9)](docs/design.md#s9) · [Overlay rules (§7.6)](docs/design.md#s7) · [Analytics (§20.1)](docs/design.md#s20)

## Safety and limits

Creator ownership does not remove responsibility for rights, privacy, or unlawful content. The design includes reporting, severity-based review, notices, appeals, network delisting, and cache purge obligations.

Default watch quotas are **48 media-hours per account per day**, shared across devices, with **three concurrent sessions**; guests have lower limits. These gate new KeyGrants, not previously copied plaintext. Payment does not automatically bypass quotas.

[Review and enforcement (§15)](docs/design.md#s15) · [Watch quotas (§16)](docs/design.md#s16) · [Open risks (§29)](docs/design.md#s29)

## Proposed roadmap

| Phase | Intended focus—not completed milestones |
| --- | --- |
| **0 — Foundations** | Encrypted HLS/HTTPS playback, signed metadata, local Key Agent, appliance/connectivity and recovery prototypes. |
| **1 — First useful network** | Publisher pages/forums, local trust catalogs, recommendation publishing, shared metadata/captions/reviews, publisher cloud failover, turnkey setup, penny payments/gifts, and basic review tools. |
| **2 — Scale and resilience** | WebTorrent/WebRTC peer assistance, compatible seeds, sharing controls, delegated Key Agents, expanded moderation, and coordinated fills. |
| **3 — Delivery partners and live** | Compensated trusted-peer asset exchange, ISP/edge verification and incentives, multi-network replication, and live streaming. |
| **4 — Federation and hardening** | Independent/mirrored discovery services, conformance testing, quorum agents, and broader accessibility. |

Independent competing portals are **not yet implemented or fully specified**. Local catalogs and portable records reduce dependence on a central feed; they do not by themselves complete federation.

See [the full roadmap (§28)](docs/design.md#s28).

## Read the design

| Document | Purpose |
| --- | --- |
| **This README** | GitHub-native project introduction and current direction. |
| **[MVP open questions](openquestions.md)** | First-release decisions, proposed scope reductions, and measurable release criteria still to resolve. |
| **[Executive overview](docs/overview.md)** | Publisher responsibilities, viewer choice, community ownership, and the business proposition. |
| **[Full design](docs/design.md)** | Architecture, journeys, proposed interfaces, economic boundaries, and acceptance criteria. |
| **[Video proposal comparison](docs/video-comparison.md)** | Timestamped original goals, design coverage, intentional differences, and gaps. |

All document links above render directly on GitHub. Styled originals remain available as [executive HTML](index.html), [design HTML](docs/design.html), and [comparison HTML](docs/video-comparison.html); open those locally after cloning for the styled layout.

### Updating the documentation

The HTML pages are the editing source; their Markdown counterparts are generated for GitHub. After editing HTML, run `pwsh -NoProfile -File scripts/Sync-GitHubDocs.ps1` from the repository root and include the regenerated pages with the source changes. The script requires [Pandoc](https://pandoc.org/installing.html) (tested with 3.8.2.1); use `-PandocPath` if it is not on your PATH. It preserves section anchors and timestamps, rewrites local navigation, and converts CSS-dependent diagrams to text flows. Edit this README directly.

**Original inspiration:** [xjet — “At last, something bigger and better than YouTube”](https://www.youtube.com/watch?v=eEjYXw3j4pM). This is a proposal, not a demo of this repository. Our non-injection policy, access payments, and separate peer compensation deliberately differ from its portal pre-roll advertising model.

## License

Repository materials are licensed under [Apache-2.0](LICENSE). That does not grant rights to third-party videos or to media a future publisher distributes.
