> Generated from [index.html](../index.html). Edit the HTML source, then run `pwsh -NoProfile -File scripts/Sync-GitHubDocs.ps1` from the repository root.

<a href="overview.md" aria-current="page">Executive overview</a> [Full design](design.md) [Video goals vs design](video-comparison.md) [GitHub repository](https://github.com/christopherwhull/xjet-swarma-video)

xjet-swarma-video · Executive overview

<a id="the-publisher-provides-the-video.-the-network-provides-the-reach."></a>

# The publisher provides the video. The network provides the reach.

Human-led niche curation. Or discovery through your own AI agent. Your choice.

A video publisher is the person or organization that brings a video to the network, has the right to distribute it, sets the terms for watching it, and receives the earnings from paid access. The publisher keeps control of the library and its keys instead of handing the business to a platform.

Media publishers may be original artists or authorized rights-holders. Publishing is also how a viewer shares a recommendation or review: they operate their own lightweight local or cloud publishing setup, without acquiring rights to the original video.

**Current status: product and architecture design, not a launched service.** This page describes the intended experience and responsibilities. The appliance, payment services, cloud failover, and peer-assisted player still require implementation and validation.

<a id="promise"></a>

## Ownership, income, and a direct relationship

<a id="own-the-library"></a>

### Own the library

Choose where the videos live. Keep publishing authority, encryption keys, and the ability to move the library. The coordination platform does not take custody of the masters.

<a id="choose-the-offer"></a>

### Choose the offer

Offer free access, penny-scale paid viewing, or other clearly disclosed conditions. Set pricing, previews, access duration, and spending limits. Viewers may also buy a gifted view for someone else.

<a id="see-the-earnings"></a>

### See the earnings

See pending earnings as paid viewing begins, with available funds distinguished from payments still awaiting confirmation. Funds follow publisher-selected rails; audience size does not guarantee revenue.

<a id="publisher-home"></a>

## Your page. Your highlights. Your community.

Each publisher has a public home similar in purpose to a YouTube channel—but the publisher defines the content and presentation. Introduce your work, choose which videos to highlight, arrange collections, and explain why those selections matter. The platform helps people find the page; it does not take over its editorial choices.

<a id="human-led-niche-curation"></a>

### Human-led niche curation

Discover work selected by people who know their subject. Publisher-picked highlights and attributed curator collections put expertise and a recognizable editorial voice ahead of a compulsory platform feed.

<a id="or-let-your-own-agent-help"></a>

### Or let your own agent help

Viewers keep a local catalog of trusted publishers and may use their own agent to review shared captions, metadata, and reviews. Unfamiliar publishers stay outside the ordinary feed unless the viewer explicitly chooses to inspect them.

<a id="a-publisher-owned-forum"></a>

### A publisher-owned forum

Run a feedback space for your audience, set its rules, appoint moderators, and take its data with you when you move. Stewardship remains subject to contributors' rights, privacy choices, and safety obligations.

Public pages, member-only discussions, video purchases, and overlay permission are separate choices. Owning a community space does not mean owning its members or their personal data.

[Publisher pages and feedback forums](design.md#publisher-pages) · [Viewer-owned local catalogs](design.md#local-catalog)

<a id="provides"></a>

## What the video publisher provides

The publisher supplies more than a file. They provide a complete, watchable offer: the work, its presentation, permission to watch, and dependable access.

<a id="table-help"></a>

On smaller screens, scroll the table horizontally.

| Publisher provides | What that means for the business |
|----|----|
| The video and its rights | Original or properly licensed work, an accurate title and description, a thumbnail, previews, language/caption information, sponsorship disclosures, and appropriate content warnings. |
| The viewing offer | Clear free or paid access choices, the price and scope of a purchase or gift, any expiry, and the applicable refund or retry rules. No hidden switch from a free preview to an undisclosed charge. |
| Their page and community | The publisher defines page content, featured videos and collections, and the feedback forum's rules and moderators. The page and forum are portable; the platform does not silently replace publisher selections with promotions. |
| The publishing appliance | A supported PC or small appliance, library storage, and an internet connection. Guided software handles preparation and publishing without requiring the publisher to administer media protocols manually. |
| A cloud backup origin | A publisher-operated and publisher-funded cloud instance with a verified serving copy of published local-origin content. The cloud copy is ready before publication and serves viewers when the local appliance is unplugged. It is not the platform's video warehouse. |
| Authority to unlock | A reachable publisher-controlled or authorized Key Agent decides whether access conditions have been met. That unlock path must also survive local appliance failure; a media copy alone cannot issue new viewing permissions. |
| Business operations | Secure recovery material, working payout destinations, cloud bills, capacity monitoring, and timely responses to legitimate rights or safety notices. Serving replicas and independent recovery backups have different jobs. |

The publisher's contribution and accountability

[Publisher role and responsibilities](design.md#s6) · [Turnkey appliance requirements](design.md#turnkey-appliance) · [Cloud backup and failover](design.md#cloud-backup-origin)

<a id="network"></a>

## What the network contributes

**The centralized platform holds what each publisher chooses to share—not ownership of the video library.** That can include metadata, closed captions, selected reviews, and current content locations. A shared record helps a viewer or their agent investigate a publisher; it does not buy placement in the viewer's local catalog or confer trust.

<a id="discovery-and-trust"></a>

### Discovery and trust

The platform is one discovery source among many. Viewers can find publishers through friends, communities, websites, direct links, or search, then decide whom to trust. AI-generated upload volume cannot place an untrusted publisher in the ordinary viewing feed.

<a id="efficient-delivery"></a>

### Efficient delivery

HLS provides adaptive streaming over HTTPS. WebTorrent/WebRTC adds peer assistance; optional ISP and edge caches hold encrypted segments. Publisher cloud failover protects against a local-origin outage.

<a id="useful-visibility"></a>

### Useful visibility

Publisher and platform operator see aggregate retention, skips, exits, and player-managed link activity. Detailed per-viewer timelines are encrypted for the relevant publisher and use publisher-scoped pseudonyms—not an automatic disclosure of real identity.

The public library contains publisher-approved discovery fields and any captions/reviews they lawfully opt to share. Full transcripts are optional because they can reveal a paid video's substance. Private local catalogs, trust lists, forums, and viewing histories are not public discovery records.

Behind the catalog, separate operational services still handle verification, key-request relaying, safety cases, quotas, and the protected analytics store. Calling the platform a metadata library does not mean those private records disappear or become publicly searchable.

[Centralized metadata and location libraries](design.md#metadata-library)

<a id="relationship"></a>

## The viewer relationship is not advertising inventory

The platform does not inject ads or promotions between publisher and viewer. Quality questionnaires are the only platform-inserted engagement and remain brief, voluntary, and noncommercial. Optional overlays appear only after **both publisher and viewer explicitly opt in**; buying or accepting a gifted view does not count as that permission.

A sponsor read or banner already included by the publisher remains part of the video. Paid access does not remove it unless the publisher supplies a separate version and promises that in the offer. Analytics collection is disclosed separately from overlay permission.

[Media, sponsorship, and overlay rules](design.md#s7) · [Analytics visibility and privacy](design.md#s20)

<a id="local-discovery"></a>

## Trust is local. Recommendations have a publisher.

You choose the publishers in your catalog, and your agent works within that choice. New sources enter through an explicit discovery step—not an unsolicited global feed. Trusting a friend as a recommender does not automatically subscribe you to every creator they mention.

To share a recommendation, run a lightweight publishing setup on your own device or in your cloud account. Publish a signed reference and your reason for recommending it; the recipient chooses whether to inspect, accept, or block it. The original publisher retains the video, access terms, and revenue. No copied keys or reuploaded video are needed.

This protects attention, not the entire infrastructure from abuse. Trusted accounts can be compromised; import limits, source revocation, agent safeguards, and central anti-spam controls still matter.

[Local trust and reviewing agents](design.md#local-catalog) · [Local or cloud recommendation publishing](design.md#recommendation-publishing)

<a id="asset-exchange"></a>

## Video assets can move between trusted peers

A publisher can contract with trusted peers to move, hold, or serve their video assets for compensation. A publisher-signed inventory and cryptographic checksums identify the exact version; a receiving peer verifies the complete transfer before acknowledging acceptance. Matching bytes make replication verifiable—not an automatic transfer of copyright or viewing keys.

Price, permitted use, onward sharing, storage term, and payment conditions are agreed first. Compensation stays separate from viewer access earnings unless the publisher explicitly funds it. A receipt supports settlement; it does not eliminate collusion or disputes.

[Trusted-peer asset exchange and compensation](design.md#trusted-peer-exchange)

<a id="money"></a>

## Keep the economics understandable

1.  **Viewing value belongs to the publisher.** Paid access follows publisher-selected payment destinations; the platform is not the default merchant of record. Any optional custodial balance service must be explicitly chosen and disclosed.
2.  **Delivery is a separate cost.** The publisher pays for their cloud backup origin and may separately fund faster edge delivery. ISPs do not automatically take a percentage of viewing pennies.
3.  **Coordination has its own price.** Disclosed control-plane or service fees remain separate from access earnings and delivery budgets.

Free viewing choices remain possible, but running the publishing service is not cost-free. Creator-owned infrastructure moves responsibility and spending to the publisher; it does not eliminate them.

[Business order](design.md#s5) · [Earnings, pricing, and gifts](design.md#s9)

<a id="journey"></a>

## From first setup to a dependable published title

1.  **Set up:** install on supported hardware, create or recover the publisher identity, and complete a recovery check.
2.  **Connect the backup:** configure the publisher's cloud instance, accept its disclosed costs, and verify media and unlock availability.
3.  **Prepare the offer:** import the work, add its presentation and access terms, and let the appliance package, encrypt, and replicate it.
4.  **Publish when ready:** only advertise a local-origin title as ready after its complete cloud serving copy is verified. A viewer outside the publisher's home network must be able to unlock and watch it.
5.  **Operate:** monitor earnings, audience summaries, replication health, notices, and costs. Test playback and fresh unlocks with the local appliance unplugged—not just while everything is working.

**Control does not mean a guarantee of reach, profit, or uninterrupted service.** Both origins can fail; a live encoder outage cannot be repaired by replaying a cloud copy. Review and delisting obligations still apply. Independent competing portals remain a later design area, so ownership of files must not be confused with completed independence from discovery gatekeepers.

**The publishing proposition:** bring the work, set the offer, keep the library, operate its availability, and earn from the relationship. Use the network for discovery, trust, and delivery—not as the owner of the business.

[Read the full design](design.md) · [Compare with the original video proposal](video-comparison.md) · [Repository overview](../README.md)
