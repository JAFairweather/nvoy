import { strict as assert } from 'node:assert'
import { finalizeEvent, generateSecretKey, getPublicKey, nip44 } from 'nostr-tools'
import * as nip19 from 'nostr-tools/nip19'
import { buildJoin, decodeFragment, latestCoordinateEvent, openBundle, parseInviteLink, verifyColdJoin } from '../mcp/tools/concord_link_lib.mjs'
import * as lib from '../mcp/tools/concord_lib.mjs'

const owner = generateSecretKey(), ownerPk = getPublicKey(owner), salt = generateSecretKey(), root = generateSecretKey(), link = generateSecretKey(), linkPk = getPublicKey(link)
const cid = lib.communityId(lib.hex(ownerPk), salt)
const token = new Uint8Array(16).fill(7)
const fragment = Buffer.from(Uint8Array.from([4, 0, 1, 2, ...token])).toString('base64url')
const naddr = nip19.naddrEncode({ kind: 33301, pubkey: linkPk, identifier: '' })
const invite = parseInviteLink(`https://armada.example/invite/${naddr}#${fragment}`)
assert.equal(invite.linkSigner, linkPk); assert.deepEqual(decodeFragment(fragment).relays, ['wss://asia.vectorapp.io/nostr'])
const bundle = { community_id: cid, owner: ownerPk, owner_salt: lib.toHex(salt), community_root: lib.toHex(root), root_epoch: 0, channels: [], relays: ['wss://asia.vectorapp.io/nostr'], name: 'Test meadow', creator_npub: ownerPk, label: 'test' }
const live = finalizeEvent({ kind: 33301, created_at: 1, tags: [['d', ''], ['vsk', '6']], content: nip44.v2.encrypt(JSON.stringify(bundle), lib.hex(lib.inviteBundleKey(token))) }, link)
assert.deepEqual(openBundle(latestCoordinateEvent([live], invite), invite), bundle)
const revoked = finalizeEvent({ kind: 33301, created_at: 2, tags: [['d', ''], ['vsk', '9']], content: '' }, link)
assert.throws(() => openBundle(latestCoordinateEvent([live, revoked], invite), invite), /revoked/)
const member = generateSecretKey(), memberPk = getPublicKey(member)
const signer = { getPublicKey: async () => memberPk, signEvent: async e => finalizeEvent(e, member) }
const join = await buildJoin(bundle, signer)
assert.equal(join.rumor.pubkey, memberPk); assert.equal(join.rumor.content, 'join'); assert.equal(join.wrap.kind, 1059)
assert.equal(verifyColdJoin([join.wrap], join.group, join.rumor), true)
assert.throws(() => parseInviteLink(`https://armada.example/invite/${naddr}`), /missing its fragment/)
console.log('concord-link: all passed')
