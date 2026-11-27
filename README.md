# xjet-swarma-video

**Creator-owned video. Fair unlocks. Pennies when they watch. Fast delivery on many networks.**

xjet-swarma-video is a **decentralized video publishing and delivery concept**: creators keep the files and the keys; fans unlock with free paths or micropayments; a thin coordination fabric handles discovery, proof, and trust—not a warehouse that owns the library.

| | |
|--|--|
| **Status** | High-level product and architecture design (not production software yet) |
| **Full design** | [`docs/design.html`](docs/design.html) — journey-first, Parts A–E, sections 1–27 |
| **Demo / pitch video** | [YouTube](https://youtu.be/eEjYXw3j4pM?si=yrF0K31CxAWU-tgl) |

---

## Executive summary — what the product does

A creator-owned video network where artists keep their files and keys, fans unlock with fair free paths or **pennies per view**, and the open internet—plus many ISPs—delivers the bits fast. We coordinate discovery, trust, and cashflow visibility. **We do not become the next warehouse that owns your library.**

| Audience | What they get |
|----------|----------------|
| **Creators** | Publish from your own storage. Set the door policy. Watch earnings tick when people actually watch. Optionally buy multi-network speed—without surrendering the masters. |
| **Viewers** | Find something worth watching. Preview freely when allowed. Unlock with goodwill, a puzzle, an email, a tip of pennies—or whatever the creator asked. Report the worst stuff. Play. |
| **ISPs and the network** | Cache encrypted hits near subscribers. Save transit. Earn on **delivery**, not by skimming creator pennies. Many networks can warm the same popular title—fairly. |

### Normative money order (do not invert)

1. **Viewer to Creator** — access value (pennies per view / other requirements). Live pending to available balance.
2. **Trust-safety** — block/pull can stop addressability before more cash warms bad content.
3. **Creator to ISPs** — optional delivery budgets (hits, diversity, pins)—**never** a default skim of view pennies.
4. **Anyone to coordination fabric** — thin control-plane fees only. Not the merchant of record by default.

---

## The story in five parts

Open [`docs/design.html`](docs/design.html) for the full narrative.

### Part A — Frame

**The pitch.**  
This is not "another YouTube." Creators host their own video and keep the keys. The global fabric only does what a platform must: help people find work, prove a fair unlock, move pennies in the open, and keep the worst content off the rails. Part A locks the promise, the rules, and who gets paid in what order.

### Part B — Creator experience

**Make it. Price it. Get paid when they watch.**  
Ship from your bucket or home MinIO. Free doors or penny doors. Balance moves as views start—not in a mystery month-end envelope. Stay unlock-online even when the laptop sleeps. When a title breaks out, spend a **clear** delivery budget so many ISPs warm your intro. You own the library, the relationship, and the upside.

### Part C — Viewer experience

**Watch without the hustle tax.**  
Browse in your language. Preview when allowed. Unlock simply—goodwill, a quick challenge, an email, pennies with a hard session cap. No surprise large holds for pocket-change video. Report spam or unlawful content in one tap.

### Part D — Network, trust and operations

**Trust is a product feature.**  
The fabric is a neutral town square—not your bank and not your vault. Clear terms. Real teeth on the worst material: delist, purge caches, stop unlock relay, escalate. Security and uptime so the door opens when it should.

### Part E — Build contract

**From vision to shipped software.**  
Data shapes, APIs, diagrams, glossary, staged roadmap. First: publish + pennies + play. Then resilience. Then multi-ISP warmth at scale.

---

## Architecture at a glance

```text
Creator (CEA)                 Coordination fabric (CDF)              Viewer
  transcode/segment     -->     catalog / discovery            <--  browse and preview
  encrypt per segment   -->     requirement attestations       <--  unlock path
  S3 / MinIO origin     -->     key grant relay                -->  decrypt and play
  Key Agent (local or   -->     moderation / block list        <--  report abuse
   delegated)                   edge fill-leases and settlement     P2P + HTTP + edge
```

| Piece | Role |
|--------|------|
| **CEA** | Creator endpoint: segment, encrypt, upload, seed, policy, Key Agent |
| **Origin storage** | Creator-owned S3-compatible ciphertext (e.g. MinIO) |
| **CDF** | Discovery, verifiers, key relay, moderation, edge coordination—not media host |
| **Viewer app** | Requirements UX, P2P/HTTP fetch, local decrypt, reports |
| **ISPs / edges** | Cache **encrypted** segments; PoD settlement; purge on takedown |
| **Verifiers** | Pluggable proofs (email, puzzle, social, crypto receipt, ad attention, and more) |

**Keys never live at the ISP.** Delivery settlement and access earnings are **separate ledgers**.

---

## Creator journey (short)

1. Identity and optional team roles
2. Run CEA — encrypt — upload to your bucket
3. Publish metadata and preview
4. Set access policy (free and/or paid)
5. Set penny defaults; watch the live ticker
6. Keep Key Agent healthy (local or delegated)
7. Optional: multi-home / launch boost delivery budget
8. Operate: analytics, notices, sweeps

## Viewer journey (short)

1. Discover (localized catalog)
2. Device identity (ephemeral or recoverable)
3. Preview when allowed
4. Choose unlock path (free or metered pennies)
5. Play (ABR, captions; edge/swarm/origin)
6. Session spend stays honest and capped
7. Report when needed

---

## What makes xjet different

| Typical big platform | xjet-swarma-video |
|----------------------|-------------------|
| Platform holds the masters | Creator holds storage and keys |
| Ads/subscription black box | API-described unlock requirements |
| Month-end mystery RPM | **Pennies as viewing starts** (pending to available) |
| One CDN gravity well | **Many ISPs** via hit rebates, diversity, and fair fill leases |
| Trust-and-safety opacity | Severity classes, pull of addressability, appeals |
| Platform is the bank | No default merchant of record; optional disclosed micro-ledger only |

---

## MVP roadmap (summary)

| Phase | Focus |
|-------|--------|
| **0** | Segment encrypt to MinIO; one requirement; local Key Agent; HTTP play |
| **1** | ABR VOD and captions; penny per-view and live ledger ticker; basic report/delist |
| **2** | P2P assist; delegated Key Agent; full S0–S4 moderation; fill-lease at $0 |
| **3** | ISP PoD, multi-home packages, diversity pay, live streaming |
| **4** | Federation, hash-list partnerships, conformance |

Details: [`docs/design.html`](docs/design.html) section 25.

---

## Repository layout

```text
xjet-swarma-video/
  README.md           -- executive pitch and architecture spine
  LICENSE
  docs/
    design.html       -- full high-level design (source of truth for depth)
```

There is **no application runtime in this repo yet**. This repository captures the **product concept and design**. Implementation can land later without changing the economic order above.

---

## Design source of truth

| Document | Use when |
|----------|----------|
| **This README** | Pitch, onboarding, "what is xjet?" |
| **[`docs/design.html`](docs/design.html)** | Architecture, policies, APIs (descriptive), ISP model, money, trust and safety |

The HTML is organized **journey-first** (creator and viewer before build-contract appendices). Section numbers are stable anchors.

---

## Open questions (honest backlog)

Still active in the full design: proof-of-attention without invasive tracking; micropayment tax/portability; bot rings vs clawbacks; fill-cell politics across ISPs; offline play with expiring keys. See section 16 in the full design.

---

## License

See [LICENSE](LICENSE).

---

*xjet-swarma-video — creator-owned video delivery concept. Full design in `docs/design.html`.*
