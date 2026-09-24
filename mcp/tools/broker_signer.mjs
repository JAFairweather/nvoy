// The broker's signer, built from its credential files exactly as the wrapped-mail broker builds
// it. In production the credential is the NIP-46 transport key and the Bunker holds the identity;
// a local nsec remains only for development fixtures. `attentionEnv` is what attention.mjs needs
// to reach the same signer, so a policy check and the act it gates use one identity.

import { existsSync, readFileSync } from 'node:fs'
import { getPublicKey, finalizeEvent } from 'nostr-tools/pure'
import { decode } from 'nostr-tools/nip19'
import { makeBunkerSigner } from './nip46-signer.mjs'

export function brokerSigner(die, options = {}) {
  const credential = process.env.NVOY_BROKER_CREDENTIAL
  if (!credential || !existsSync(credential)) die('broker credential file is unavailable')
  let raw
  try { raw = readFileSync(credential, 'utf8').trim() } catch { die('cannot read broker credential') }
  if (!/^nsec1[023456789acdefghjklmnpqrstuvwxyz]+$/.test(raw) && !/^[0-9a-f]{64}$/i.test(raw)) die('broker credential is not an nsec or hex key')
  const uriPath = process.env.NVOY_BUNKER_URI_FILE || ''
  if (uriPath) {
    let uri
    try { uri = readFileSync(uriPath, 'utf8').trim() } catch { die('cannot read Bunker URI credential') }
    if (!/^bunker:\/\//i.test(uri)) die('Bunker URI credential is invalid')
    return { signer: makeBunkerSigner(uri, raw, options), attentionEnv: { NVOY_BUNKER_URI: uri, NVOY_NIP46_CLIENT_NSEC: raw } }
  }
  const sk = raw.startsWith('nsec1') ? decode(raw).data : Uint8Array.from(Buffer.from(raw, 'hex'))
  return { signer: { getPublicKey: async () => getPublicKey(sk), signEvent: async event => finalizeEvent(event, sk) },
    attentionEnv: { NVOY_NSEC: raw } }
}
