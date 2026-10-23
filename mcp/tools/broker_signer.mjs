// The broker's signer, built from its credential files exactly as the wrapped-mail broker builds
// it. In production the credential is the NIP-46 transport key and the Bunker holds the identity;
// a local nsec remains only for development fixtures. `attentionEnv` is what attention.mjs needs
// to reach the same signer, so a policy check and the act it gates use one identity.
//
// A Bunker46 session can die while the process lives: after the 10-16 fleet reboot every broker
// kept a session that answered nothing, and every watcher login timed out for three days. So a
// run of consecutive timeouts tears the session down and opens a fresh one from the same stored
// credentials, already in memory. It never re-pairs and never touches the credential files.

import { existsSync, readFileSync } from 'node:fs'
import { getPublicKey, finalizeEvent } from 'nostr-tools/pure'
import { nsecEncode } from 'nostr-tools/nip19'
import { makeBunkerSigner } from './nip46-signer.mjs'
import { secretKey } from './secret_key.mjs'

export const HEAL_AFTER_TIMEOUTS = 3

export function selfHealingSigner(open, { healAfter = HEAL_AFTER_TIMEOUTS, log = m => console.error(m) } = {}) {
  let session = open(), timeouts = 0, rebuilds = 0
  const call = method => async (...args) => {
    const used = session
    try {
      const result = await used[method](...args)
      if (used === session) timeouts = 0
      return result
    } catch (error) {
      // Only the live session's timeouts count: calls stranded on a retired session fail as closed.
      if (used === session && /timed out/.test(String(error?.message)) && ++timeouts >= healAfter) {
        timeouts = 0; rebuilds++
        try { used.close?.() } catch { /* already dead */ }
        session = open()
        log(`broker-signer: Bunker46 session rebuilt after ${healAfter} consecutive timeouts (rebuild ${rebuilds}; same credentials, no re-pair)`)
      }
      throw error
    }
  }
  return Object.freeze({ get pubkey() { return session.pubkey }, close: () => session.close?.(),
    getPublicKey: call('getPublicKey'), signEvent: call('signEvent'), nip44Encrypt: call('nip44Encrypt'), nip44Decrypt: call('nip44Decrypt') })
}

export function brokerSigner(die, options = {}) {
  const credential = process.env.NVOY_BROKER_CREDENTIAL
  options = { clientSource: `broker credential ${credential}`, ...options }
  if (!credential || !existsSync(credential)) die('broker credential file is unavailable')
  let raw
  try { raw = readFileSync(credential, 'utf8').trim() } catch { die('cannot read broker credential') }
  if (!/^nsec1[023456789acdefghjklmnpqrstuvwxyz]+$/.test(raw) && !/^[0-9a-f]{64}$/i.test(raw)) die('broker credential is not an nsec or hex key')
  const uriPath = process.env.NVOY_BUNKER_URI_FILE || ''
  if (uriPath) {
    let uri
    try { uri = readFileSync(uriPath, 'utf8').trim() } catch { die('cannot read Bunker URI credential') }
    if (!/^bunker:\/\//i.test(uri)) die('Bunker URI credential is invalid')
    // Every transport-key reader downstream decodes an nsec, so a hex key is encoded once here.
    const client = raw.startsWith('nsec1') ? raw : nsecEncode(Uint8Array.from(Buffer.from(raw, 'hex')))
    return { signer: selfHealingSigner(() => makeBunkerSigner(uri, client, options)), attentionEnv: { NVOY_BUNKER_URI: uri, NVOY_NIP46_CLIENT_NSEC: client } }
  }
  let sk
  try { sk = secretKey(raw, `broker credential ${credential}`) } catch (error) { die(error.message) }
  return { signer: { getPublicKey: async () => getPublicKey(sk), signEvent: async event => finalizeEvent(event, sk) },
    attentionEnv: { NVOY_NSEC: raw } }
}
