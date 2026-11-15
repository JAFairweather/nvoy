# q-145: grant and respond-to reconciliation

Read at 14:47–14:57 UTC on 15 November 2026. This is a proposed correction set,
not an authorization to sign or deploy it. James's instruction was reported in
Buzz event `2134cad47d57fbe9d40fbf8624b5c64c5b072a3f9268195bfe7c0b10291e3ea4`:
active seats form a full task mesh; James and Dead Rabbit can task everyone;
LukeDog is mentioned by all and tasks no one; parked seats get nothing. Neil
to DJ Codex is first. The roster and relay reads came from Dead Rabbit's Buzz
events `8b1ceae7`, `4bd4d449`, `2bad9818` and `02ead239` and the local
read-only snapshots `/home/agent-kerouac/q145-grants-live.tsv` and
`/home/agent-kerouac/q145-mentions.tsv`.

The exact public-key and grant-ID operations are in
[`Q145_GRANT_CORRECTIONS.tsv`](Q145_GRANT_CORRECTIONS.tsv). The first row is
Neil → DJ Codex. The snapshot gives these counts:

| Operation | Count | Implementation |
| --- | ---: | --- |
| Add task grants to active fleet targets | 97 | James-signed kind 440 |
| Add mention permissions to active fleet seats | 67 | James-signed kind 440 `mention`; the 86 manifest entries and existing live mention grants are already credited |
| Revoke task grants to parked HR and observer LukeDog | 4 | James-signed kind 441 against the listed grant IDs |
| Revoke direct Dead Rabbit task grants | 2 | James-signed kind 441; the shadow grant remains the single revocation switch per `docs/BEESWARM.md` |
| Add Buzz `respond_to` entries | 41 | reviewed config/deploy change; no signed grant row |
| Remove LukeDog from Buzz `respond_to` | 2 | reviewed config/deploy change |

The correction table has 213 data rows (214 lines including its header).

There are nine active fleet targets and five active Buzz seats. The expected
direct task matrix for fleet targets has 126 edges: every other active seat
and James. Dead Rabbit's live shadow of James supplies its reach without a
per-target direct grant. Twenty-nine of those 126 edges already exist; 97 are
missing. The expected outgoing mention matrix for the nine active fleet seats
has 144 edges: every other active seat, James, Dead Rabbit and LukeDog. The
manifest and live mention grants already supply 77; 67 are missing. All nine
active fleet manifests already include LukeDog as mentionable. Buzz seats use
local `respond_to` allowlists, not the fleet grant plane. This calculation
does not count an agent's own key as an instructor or mention target.

## Relay consistency gate

The relay read at 14:50 found all 200 James-signed 440/441 events on
`relay.nave.pub`. `relay.ditto.pub` lacked three, `nos.lol` 83 and
`relay.primal.net` 134. The union of the three relays used by ten fleet
manifests lacks three old August 440s:
`89d2e527bb6357c1d14ed1c4ff11b60cf660cd682c1dec6673ebc2a8135b2d80`,
`fdae44adaffb7dc32b06f0a1b2cc5fa9fe2034001c7a7f09fa54701e2b168d30`,
and `3dbb052fb5749af959a2c53e13b7616cbc49c4d5e69ae902444d41c3febf34df`.
Dead Rabbit found each already revoked (Buzz event `3b20bc0a`). The runner
must prove from a fresh anchor read that every event absent from the broker
union is a revoked 440. Any missing live 440 or 441 blocks apply. Each newly
signed event must be read back from both the anchor and a broker grant relay.
Individual broker relays remain behind; ten manifests read their three-relay
union, while only LukeDog lists `relay.nave.pub` (Buzz event `02ead239`).

## James-run signing route

The existing Nvoy console has a Bunker-backed signer and builds public 440s
in `console/task-authority-lib.mjs`; it signs one prefilled grant at a time.
Its current prefill accepts `task`, `task+act` and `task-relay`, but not
`mention`; there is no batch dry-run. `console/capgrants.mjs` builds 441s.
A reviewed q-145 runner reads the correction TSV, takes a fresh
four-relay grant fold, shows the complete delta on dry-run, then uses James's
NIP-46 Bunker signer to sign only still-missing rows. It should check the
signer's public key is James's, publish to the four grant relays, read back
each signed event from the anchor and broker relay set, and
resume safely if interrupted. It must never receive James's signing key.
The runner folds the anchor and broker relay union separately. If an interrupted
publish left a signed 440 or 441 on only one side, a rerun republishes that
same event to the missing side and reads it back from both sides before marking
the row complete. Broker-side readback requires at least one of the three
configured broker grant relays. Apply stops if an unrelated event is missing
from the anchor
or a live event is missing from every broker relay. It also stops on a possible
relay result cap, orders grants before revokes, and requires a typed pending
count before opening the Bunker signer.

The Buzz `respond_to` changes need a separate reviewed herd-infra config
change and live readback by the host owner. They cannot be fixed by signing
NIP-DA 440s. Neither step is complete on this read.
