// Shared Concord derivation primitive — CORD-02 Appendix A, corrected.
//
// A.1/A.6: "The `id` is always present, 32 bytes, all-zeroes where a label has no
// meaningful id. The epoch is the *only* omittable field."
//
// Our earlier helpers omitted BOTH when absent. `buildInfo` below defaults the id to
// 32 zero bytes and keeps the epoch omittable — the asymmetry the spec actually has.
// Amethyst quartz reaches the same place differently: its raw buildInfo omits a null
// id, but every typed call site (banlistCoordinate / inviteBundleKey) passes
// ByteArray(32) explicitly, so its public API is never wrong. Defending it in the
// primitive is safer for us, since our scripts call the primitive directly.
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { nip44 } from 'nostr-tools';

// `hex` is the PRODUCER every value in this system passes through — cid, root, owner,
// salt and channel_id all arrive as hex strings in the 3313 invite JSON. Every guard
// below inspects its OUTPUT, so a decoder that fails silently defeats all of them at
// once: it hands back a well-formed 32-byte Uint8Array that is simply the wrong value.
// The old one-liner `h.match(/.{1,2}/g).map(b => parseInt(b,16))` had four silent modes,
// each measured rather than imagined (mydude_hex_decoder_check.mjs):
//   'g' typo   -> parseInt NaN -> Uint8Array coerces to 0: ONE byte silently becomes 00
//                 in the middle of otherwise-correct data. Maximum plausibility.
//   odd length -> the trailing single char parses as one byte; 63 chars yield 32 bytes
//   non-hex    -> every byte 0: a 32-zero "key" that passes length AND ascii-hex checks
//   '\n'       -> `.` does not match a newline, so trailing whitespace vanishes unseen
// Only the leading-space case was loud, and only because it shifted the length to 33.
export const hex = h => {
  if (typeof h !== 'string') throw new TypeError(`hex: expected a string, got ${typeof h}`);
  const s = h.trim();                       // trimming is a deliberate allowance, not silence
  if (s.length === 0) throw new Error('hex: empty string');
  if (s.length % 2) throw new Error(`hex: odd length ${s.length} — hex is 2 chars per byte`);
  if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error(`hex: contains non-hex characters`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
};
export const toHex = u => [...u].map(b => b.toString(16).padStart(2, '0')).join('');
const ZERO_SALT = new Uint8Array(32);
export const ZERO_ID = new Uint8Array(32);

/** info = utf8(label) || 0x00 || id[32] || epoch_be8?   — id ALWAYS present. */
export function buildInfo(label, id = ZERO_ID, epoch = null) {
  if (id == null) id = ZERO_ID;                       // absent id means zeroes, never omitted
  if (id.length !== 32) throw new Error(`id must be 32 bytes, got ${id.length}`);
  const lb = new TextEncoder().encode(label);
  const epLen = epoch == null ? 0 : 8;                // epoch is the only omittable field
  const out = new Uint8Array(lb.length + 1 + 32 + epLen);
  out.set(lb, 0); out[lb.length] = 0x00; out.set(id, lb.length + 1);
  if (epLen) new DataView(out.buffer).setBigUint64(lb.length + 1 + 32, BigInt(epoch), false);
  return out;
}

// Content check at the chokepoint every derivation funnels through — typed export or
// bare primitive. The per-export LENGTH guards below cannot catch every slip, because
// 64 bytes is a *legal* secret length (`concord/recipient-pseudonym`, 02.md A.6): the
// utf8-hex of a 32-byte community_id is 64 bytes and passes every length check we have.
// Content settles what length can't. Key material is uniform random, so the odds that
// all N bytes land in the ASCII-hex alphabet are (22/256)^N — the alphabet is 22 values,
// not 16, because this accepts upper-case too: 0-9, a-f, A-F. That is ~2^-113 at N=32
// and ~2^-56 at N=16. A secret that is entirely ASCII hex is an undecoded hex string,
// never a key.
const isAsciiHex = u => u.length >= 16 && u.length % 2 === 0 &&
  u.every(b => (b >= 48 && b <= 57) || (b >= 97 && b <= 102) || (b >= 65 && b <= 70));

export const hkdf32 = (secret, info) => {
  if (!(secret instanceof Uint8Array)) throw new Error(`secret must be a Uint8Array, got ${typeof secret}`);
  if (isAsciiHex(secret)) throw new Error(
    `secret is ${secret.length} ASCII-hex bytes — decode it first (hex(x), not Buffer.from(x))`);
  // An all-zero secret is never key material — it is what a failed decode leaves behind
  // (the old loose `hex` returned 32 zero bytes for a non-hex string, with no error).
  // Zeroes pass the length AND ascii-hex checks, so this is the one shape that slips both.
  if (secret.every(b => b === 0)) throw new Error(
    `secret is all zero bytes — a failed decode upstream, not a key`);
  return hkdf(sha256, secret, ZERO_SALT, info, 32);
};

const ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const validSk = sk => { const n = BigInt('0x' + toHex(sk)); return n > 0n && n < ORDER; };

export function deriveSecretKey(secret, info) {
  const first = hkdf32(secret, info);
  if (validSk(first)) return first;
  const ext = new Uint8Array(info.length + 1); ext.set(info);
  for (let c = 0; c <= 255; c++) { ext[info.length] = c; const cand = hkdf32(secret, ext); if (validSk(cand)) return cand; }
  throw new Error('no valid secp256k1 scalar');
}

export function groupKey(label, secret, id, epoch) {
  const sk = deriveSecretKey(secret, buildInfo(label, id, epoch));
  const pub = toHex(schnorr.getPublicKey(sk));
  return { sk, pub, conv: nip44.v2.utils.getConversationKey(sk, pub) };
}

// `communityId` is the ONE derivation in this file that does not route through hkdf32, so
// the outbox engineer's chokepoint content check never sees it — and it takes the two most hex-native
// arguments in the protocol (both arrive as hex strings in the 3313 invite JSON). Unguarded
// it was worse than silent: `[...'4010ac…']` spreads a STRING into characters, which
// Uint8Array coerces to NaN -> 0, so a hex string produced a deterministic, plausible,
// entirely wrong community_id with no error at all. That value is the secret for
// dissolved/banlist/grant/invite-links AND the invite's self-certification anchor, so one
// slip here re-addresses everything downstream at once.
const arg32 = (v, who) => {
  if (!(v instanceof Uint8Array)) throw new Error(`communityId: ${who} must be a Uint8Array, got ${typeof v}` +
    (typeof v === 'string' ? ' — a hex string silently becomes 32 zero bytes here; use hex(x)' : ''));
  if (v.length !== 32) throw new Error(`communityId: ${who} must be 32 bytes, got ${v.length}`);
  if (isAsciiHex(v)) throw new Error(`communityId: ${who} is ASCII hex — decode it first`);
  return v;
};
export const communityId = (ownerXOnly, ownerSalt) =>
  toHex(sha256(new Uint8Array([...new TextEncoder().encode('concord/community'),
    ...arg32(ownerXOnly, 'ownerXOnly'), ...arg32(ownerSalt, 'ownerSalt')])));

// --- secret (ikm) guards. buildInfo guards the `id` at 32 bytes because A.6 gives the
//     id ONE length. The secret does not have one length, so the same guard cannot live
//     in the primitive: A.6 secrets are 32 bytes EXCEPT `concord/invite-key` (the unlock
//     token is 16 bytes, 05.md:35) and `concord/recipient-pseudonym`
//     (rotator_xonly ‖ recipient_xonly = 64, 02.md:209). HKDF accepts any ikm length, so
//     a wrong-length secret derives a valid-looking wrong address in silence — the same
//     failure the id guard catches, on the argument nobody guarded. It belongs per-export,
//     where the length is known. (Quartz's lesson again: shape checks go in the typed layer.)
const sec = (n) => (s, who) => {
  if (!(s instanceof Uint8Array)) throw new Error(`${who}: secret must be a Uint8Array, got ${typeof s}`);
  // only claim "utf8 hex" when the bytes really are ASCII hex — a length coincidence is not
  // evidence (a 32-byte secret handed to inviteBundleKey is 2x16 and is not hex at all)
  const asciiHex = s.length === 2 * n && s.every(b => (b >= 48 && b <= 57) || (b >= 97 && b <= 102) || (b >= 65 && b <= 70));
  if (s.length !== n) throw new Error(`${who}: secret must be ${n} bytes, got ${s.length}` +
    (asciiHex ? ' — the bytes are ASCII hex; decode it first' : ''));
  return s;
};
const sec32 = sec(32), sec16 = sec(16);

// --- plane keys (CORD-02/03) ---
export const controlPlane   = (root, cid, epoch) => groupKey('concord/control',   sec32(root, 'controlPlane'),   cid, epoch);
export const guestbookPlane = (root, cid, epoch) => groupKey('concord/guestbook', sec32(root, 'guestbookPlane'), cid, epoch);
export const publicChannel  = (root, channelId, rootEpoch) => groupKey('concord/channel', sec32(root, 'publicChannel'), channelId, rootEpoch);
export const privateChannel = (channelKey, channelId, channelEpoch) => groupKey('concord/channel', sec32(channelKey, 'privateChannel'), channelId, channelEpoch);

// --- keyless control-entity coordinates (CORD-04/05). These are the ones the old
//     omit-the-id helper silently got wrong. They are `eid`s carried by editions ON
//     the Control Plane (CORD-04 §4, examples.md:464-466) — raw 32-byte values, not
//     keys. hkdf32 is the right shape for all four. ---
export const grantCoordinate       = (cid, memberXOnly)  => toHex(hkdf32(sec32(cid, 'grantCoordinate'),       buildInfo('concord/grant',        memberXOnly)));
export const banlistCoordinate     = (cid)               => toHex(hkdf32(sec32(cid, 'banlistCoordinate'),     buildInfo('concord/banlist',      ZERO_ID)));
export const inviteLinksCoordinate = (cid, creatorXOnly) => toHex(hkdf32(sec32(cid, 'inviteLinksCoordinate'), buildInfo('concord/invite-links', creatorXOnly)));
// 16, not 32 — 05.md:35: "a random 16-byte unlock token". A blanket 32-byte guard would
// have rejected every real invite link.
export const inviteBundleKey       = (token)             => toHex(hkdf32(sec16(token, 'inviteBundleKey'),     buildInfo('concord/invite-key', ZERO_ID)));

// --- dissolution is the ONE label in that A.6 block that is NOT a coordinate. ---
// 02.md:149 spells it out: `dissolved_pk = group_key("concord/dissolved", community_id, 0…0).pk`
// — a stream PUBKEY, an author to query, with the tombstone edition's own `eid` literally
// all-zeroes (02.md §9's example). A.6 files it under the same "address" wording as the four
// above, which is what made me export it as hkdf32 first; the two disagree by a full derivation
// step (deriveSecretKey's counter retry, then schnorr) and address different places on the wire.
// Quartz cannot arbitrate: it has the DISSOLVED label constant and no typed helper at all.
export const dissolvedPlane = (cid) => groupKey('concord/dissolved', sec32(cid, 'dissolvedPlane'), ZERO_ID, null);
