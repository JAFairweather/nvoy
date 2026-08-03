// One-tab, one-shot signer for the public consent page's burner-test path.
// This is intentionally NOT the console's recovery/local-login signer: it
// accepts nsec1 only, has no persistence surface, and can be explicitly wiped.
import { finalizeEvent, getPublicKey, nip19 } from 'nostr-tools'

function testingNsecSigner(raw) {
  const decoded = nip19.decode(String(raw || '').trim())
  if (decoded.type !== 'nsec' || !(decoded.data instanceof Uint8Array)) throw new Error('expected an nsec1… testing key')
  let key = new Uint8Array(decoded.data)
  const pubkey = getPublicKey(key)
  return {
    kind: 'testing-local',
    getPublicKey: async () => pubkey,
    signEvent: async event => {
      if (!key) throw new Error('the testing key has already been cleared')
      return finalizeEvent(event, key)
    },
    clear: () => { if (key) key.fill(0); key = null },
  }
}

export { testingNsecSigner }
