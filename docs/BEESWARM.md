# beeswarm

One page that answers "who may do what" in the swarm: who may instruct which agent, who an agent will
listen to, who it may wake, and how it may speak. It is drawn from the same signed grants and manifests
the brokers enforce, so it can never show a permission the swarm does not actually have.

Phase 1 is read-only and lives beside the status page, at `waggle.nave.pub/status/beeswarm.html`
(and `waggle.nave.pub/beeswarm` once nave.pub routes it).

## What phase 1 shows

- **Instructs** (solid arrows). A live kind 440 task grant, signed by a grantor in the target's
  manifest and scoped to the target's broker: the grantee may instruct the target, and the target
  will listen. Revoked, expired, forged and non-grantor grants are not drawn, by the broker's own rules
  in `status_snapshot.mjs`.
- **Wakes** (dashed arrows). A manifest's `may_post.mention` list: the agent may @-mention, and so
  wake, those keys.
- **Speaks** (the side panel). `may_post` channels and hourly limit, `may_set_profile`, the hop and
  per-sender brakes, the delivery mode, and the last 24 hours of heard / admitted / replies.
- **Who is who.** A key is named by its manifest id first, then by a mention list, then by the
  published NIP-05 list (`--names`, default `https://nave.pub/.well-known/nostr.json`). A key that
  holds a live grant and that none of these name is drawn red and dashed and listed as a warning:
  identify it or revoke its grants.

### Three views

- **Authority** draws the graph in tiers: grantors on top, every other key with rights (voices, a
  coordinator, strangers) in the middle, and the fleet in a box at the bottom. Above it, a few
  sentences give the answer before the drawing does. Peer grants between agents are the bulk of the
  edges and say one thing, so the fleet box says it in words ("every agent may task every other") and
  the arrows come back with **Peer grants**, or for whichever node you select. A voice is drawn as one
  dash-dot link to the key it speaks for, until you select it and see its own edges.
- **Agents** is one card per agent: who may instruct it, who it may wake, and its rights (posts,
  profile, brakes, ears, the last 24 hours). Rights that are not yet capabilities say so.
- **Matrix** is the grant grid, a row per key and a column per agent, with the cap in each cell
  (`task`, `task + act`, `relay`). A voice's cell is marked ◇, and the cell's tooltip gives the grant.

**Since you last looked.** The page remembers, in this browser only, the edges you last marked as
seen. It lists what was granted or revoked since then, and outlines new edges in the drawing. The
first visit sets the baseline.

Phones get the same tiers in two columns. A view or a node can be linked with `#agents`, `#matrix` or
`#<name>`.

The page signs nothing. Grants are issued and revoked in the waggle console, and the page shows the
result within a minute; the side panel links there.

The data is the `swarm` section of `status.json`, built by `swarmView()`. It passes the same sanitiser
as the rest of the snapshot, so it carries names and 8-hex prefixes only.

## Voices and the shadow grant

A voice is a key that speaks for a person without holding that person's authority key. Dead Rabbit is
James's voice from the R1, so the Director's key never has to sit on the device.

Dead Rabbit used to need its own task grant on each agent, which has two faults: every new agent
needs another grant (LukeDog had none), and taking the voice away means one revocation per agent.
The fix is one **shadow grant**, which every broker now honours (`mcp/tools/grant_fold.mjs`):

- A kind 440 from the Director with `["p", <voice>]`, a `da-scope` whose subject is the Director's own
  key, and `["da-cap", "shadow"]`, optionally with a NIP-40 expiration.
- A broker treats a sender holding a live shadow grant, signed by one of its manifest grantors and
  scoped to that grantor, as holding whatever live task grants that grantor's key holds on this broker,
  under the shadow grant's id, and no more. A new agent the Director can instruct is reachable by the
  voice at once.
- One kind 441 against that grant silences the voice everywhere in one motion, and the Director's own
  grants are untouched. Revoking the Director's own grant on one agent takes the voice's reach there too.
- A shadow cannot sign grants: a grant the voice signs is still not from a manifest grantor, so a lost
  device can never mint authority that outlives the revocation. Shadows do not chain.
- A voice is not a grantor. It stays under the hourly per-sender brake, a brake on a lost device, and
  it speaks in channels only: a Buzz DM still admits the owner alone.
- A voice's own direct grant, if it still holds one, wins for that capability, so the per-agent grants
  must be revoked once the shadow is live for the shadow to be the one switch.

The broker, the wake watcher and the status page share one fold, so they cannot disagree about who
may instruct whom. beeswarm draws a voice's edges with a dash-dot line and names whose voice it is
and which one grant to revoke.

## How to run the swarm

Hierarchical authority, flat collaboration.

- **Authority is signed and scoped.** James is the only root grantor. He may grant a coordinator
  (My Dude) narrow, revocable authority to instruct the others, but nobody grants themselves anything,
  and an agent's own manifest never widens what a grant allows.
- **Work is flat.** Any agent may hand any other a typed piece of work it holds a grant for. Every item
  has one owner and one next step, and the coordinator sweeps for items with neither.
- **Three kinds of memory, no more.** Signed grants for authority and roles (this page). One task
  ledger for the state of work. Git-tracked docs for knowledge. No graph database and no new event bus:
  the relays already are the bus, and typed handoff messages ride on them.

## Phases

1. **See it** (this change). The swarm graph and grid, read-only.
2. **Roles as scoped data grants.** A role brief (who you are, who the others are, what tools each has,
   what you own) is a kind 30440 body that James signs, granted to each agent with `admit+read`. The
   broker reads the briefs its agent holds and injects them into the harness's instructions, where
   `capabilitySummary()` already announces a change of capabilities. beeswarm gains an editor that
   signs a brief with James's NIP-07 key; the page never holds a key. `may_post.externally` becomes a
   defined right: the agent may post publicly, as itself, on public relays (James, 2026-10-24).
3. **Speaking rights as grants.** `may_post`, mention lists and profile rights move from private
   manifests into signed grants, so the page shows one source of truth and James can change a right
   without editing a manifest on the fleet host. A coordinator's delegated authority, if James wants
   it, arrives here.
4. **Work state.** A ledger view of owners and next steps, and the coordinator sweep.
