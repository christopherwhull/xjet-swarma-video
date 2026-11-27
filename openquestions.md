# Open questions for the minimum viable product

The biggest unanswered question is **what the first product must prove**. The current [Phase 1 roadmap](docs/design.md#phase-1-mvp-network) is broad enough to be several releases, while its [MVP success bar](docs/design.md#s28) is much narrower.

These questions should be resolved before implementation. Recommendations below are proposals, not approved changes to the design or claims of delivered software.

## 1. Who is the first customer?

- Are we starting with a small, invited group of existing creators and their audiences?
- What makes them willing to install this instead of uploading elsewhere?
- Is success initially **independent publishing**, **earning money**, or **viewer-controlled discovery**?

**Recommendation:** invited niche creators with an existing audience. First prove they can publish independently and their viewers can reliably watch.

## 2. What is the smallest complete experience?

Can the first release be:

> A publisher installs the software, publishes one video with a verified publisher-owned cloud copy, shares their page, and a viewer explicitly trusts that publisher and watches—even after the publisher's home appliance is unplugged.

That demonstrates the core ownership, trust, usability, and availability promises. Decide whether **real paid viewing** must also be in that first release.

## 3. What hardware and client do we support first?

- One Windows PC profile, one Linux appliance, or Raspberry Pi?
- Which browsers and devices must play successfully?
- What video formats, maximum duration, resolution, and library size are supported?
- Does the appliance transcode video or initially accept a prescribed format?

**Recommendation:** one publisher hardware/OS profile and a small, explicit browser support list. Avoid promising every PC and Pi immediately.

## 4. How does publisher-owned cloud backup become turnkey?

The cloud replica is already a requirement, not an optional feature. What remains:

- Which cloud provider is supported first?
- How does a nontechnical publisher provision and connect their own account?
- Who pays, and what cost estimate and spending warnings do they see?
- Where does the independent Key Agent run?
- What happens when billing fails or storage fills?

**This is a major product decision:** requiring creators to administer cloud infrastructure would undermine the turnkey promise.

## 5. What does access—and payment—mean?

- Is the pilot free, paid, or both?
- If paid, which **single payment rail and currency** are supported?
- Does a purchase buy one playback, a time window, or repeat access?
- When is payment committed, and what happens if playback fails?
- Who handles refunds, disputes, fees, and applicable tax obligations?

**Recommendation:** free access for the technical pilot, then one paid path before calling it a commercial MVP. Do not build several payment systems at once.

## 6. What is the minimum trust and discovery experience?

- Can viewers initially find publishers through direct links and a small directory?
- How do they verify, trust, block, and remove a publisher?
- Where is their local catalog stored, and how is it recovered?
- Are manually ordered publisher highlights enough, without agent integration?

**Recommendation:** explicit trust, direct links, local catalog, and publisher-selected highlights first. No compulsory feed; AI agents can follow later.

## 7. What survives a lost device?

- How are publisher identity and encryption keys backed up and recovered?
- Can a replacement appliance restore the published library?
- What happens after key compromise?
- Can a viewer recover their catalog—and purchases, if enabled?

Recovery must work before people entrust valuable libraries or payments to the product.

## 8. Who operates safety and support?

- Is enrollment invitation-only initially?
- Which jurisdiction and content rules govern the pilot?
- Who receives reports, makes removal decisions, and handles appeals?
- How quickly must delisting and withdrawal propagate?
- Who helps a creator whose publication or recovery fails?

**Recommendation:** manual operations are acceptable at pilot scale; undefined responsibility is not.

## 9. What analytics are actually required at launch?

- Are basic views and playback failures sufficient?
- Must detailed retention, skipping, and link-departure logging ship immediately?
- If collected, what are the consent, retention, and creator-only decryption arrangements?

**Recommendation:** collect the minimum needed to operate the pilot. Do not collect plaintext behavioral histories as a shortcut around the documented privacy boundary.

## 10. What measurable result permits release?

Set concrete thresholds for:

- Unassisted setup and first publication.
- Successful playback on supported clients.
- Startup time and rebuffering.
- Playback and fresh unlocks after unplugging the local appliance.
- Identity/library recovery.
- Withdrawal and safety-block propagation.
- Publisher monthly operating cost at a stated audience size.

The [README](README.md#clear-definable-goals) already identifies these goals, but several numerical pass/fail thresholds remain undecided.

## What I would defer

Unless explicitly made first-release requirements:

- WebTorrent peer assistance and ISP incentives.
- Compensated peer trading.
- Live streaming.
- Federation and competing portals.
- Multiple payment rails, gifted views, and elaborate access-policy combinations.
- Full forums and AI-agent integrations.

**Deferring these would narrow the current Phase 1 commitments; it would not remove them from the long-term design.**

## First decision to make

**Do we launch an invitation-only, free publishing pilot first, or must the first usable product demonstrate real publisher earnings?**

That choice determines much of the minimum scope.
