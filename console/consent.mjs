// consent.mjs — public click-through signer for waggle mirror consent.
// The request is in location.hash so a static host, its logs, and referrers
// never receive the draft.  The page owns no key: the participant selects a
// NIP-07 extension or their NIP-46 bunker and publishes the signed 440.

import { nip19, verifyEvent } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import { nip07Signer, nip46Signer } from '../lib/nave-connect.mjs'
import { loadConfig } from './config.mjs'
import { decodeConsentRequest, validateConsentRequest, termsHash } from './consent-request.mjs'

const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const relays = loadConfig().relays
let request, signer

function showError(message) { $('error').hidden = false; $('error').textContent = message }
function setStatus(message) { $('status').textContent = message }
function npub(hex) { return nip19.npubEncode(hex) }

async function connect(s) {
  try {
    setStatus('Connecting to your signer…')
    const pubkey = await s.getPublicKey()
    signer = s
    $('identity').textContent = `Signing as ${npub(pubkey)}`
    $('sign').disabled = false
    setStatus('Review the boundary, then sign if you agree.')
  } catch (err) { setStatus(''); showError(`Could not connect to your signer: ${err.message}`) }
}

async function signAndPublish() {
  if (!signer) return
  $('sign').disabled = true
  try {
    setStatus('Asking your signer to approve the consent…')
    const signed = JSON.parse(JSON.stringify(await signer.signEvent(request.prefill)))
    if (!verifyEvent(signed)) throw new Error('your signer returned an invalid signature')
    const relay = new LiveRelay(relays)
    setStatus('Publishing your signed consent to Nostr relays…')
    const receipt = await relay.publish(signed)
    relay.close()
    $('success').hidden = false
    $('success').innerHTML = `Consent published to ${receipt.acks}/${receipt.of} relay(s). waggle can now mirror future public posts into <strong>${esc(request.hive.name)}</strong>. You can revoke this later with your own signer.`
    setStatus('')
  } catch (err) { setStatus(''); showError(`Nothing changed: ${err.message}`); $('sign').disabled = false }
}

try {
  request = validateConsentRequest(decodeConsentRequest(location.hash))
  if (await termsHash(request.terms) !== request.tos) throw new Error('the request terms do not match its signed hash')
  $('hive').textContent = `${request.hive.name} · ${request.hive.handle}`
  $('scope').textContent = request.hive.id
  $('bridge').textContent = npub(request.bridge)
  $('terms').textContent = request.terms
  $('terms-link').href = request.hive.termsUrl
  $('request').hidden = false
} catch (err) { showError(`This consent link is not valid: ${err.message}`) }

$('nip07').onclick = () => {
  if (!window.nostr) return showError('No NIP-07 signer was found. Use a Nostr extension, or connect a bunker below.')
  connect(nip07Signer())
}
$('bunker-go').onclick = () => {
  const uri = $('bunker-uri').value.trim()
  if (!uri) return showError('Paste your bunker:// or nostrconnect:// URI first.')
  connect(nip46Signer(uri, { onAuthUrl: url => { $('bunker-auth').hidden = false; $('bunker-auth').href = url } }))
}
$('sign').onclick = signAndPublish
