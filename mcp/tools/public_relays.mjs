// One round trip to a public relay: read a filter, or publish an already-signed event.
// A relay that asks for NIP-42 is answered only when a signer is given, and only once.
import WebSocket from 'ws'

const authEvent = (url, challenge) => ({ kind: 22242, created_at: Math.floor(Date.now() / 1000),
  tags: [['relay', url], ['challenge', challenge]], content: '' })

// Resolves { events, answered }: answered is true only when the relay said EOSE, so an empty read
// can be told apart from a relay that never answered.
export function queryRelay(url, filter, { signer = null, ms = 10000 } = {}) {
  return new Promise(resolve => {
    const events = []; let done = false, authed = false, ws
    const finish = answered => { if (done) return; done = true; clearTimeout(timer); try { ws.close() } catch {} ; resolve({ events, answered }) }
    const timer = setTimeout(() => finish(false), ms)
    try { ws = new WebSocket(url) } catch { return finish(false) }
    ws.on('open', () => ws.send(JSON.stringify(['REQ', 'q', filter])))
    ws.on('message', async data => {
      let frame; try { frame = JSON.parse(data.toString()) } catch { return }
      if (frame[0] === 'AUTH' && signer && !authed) {
        authed = true
        try { ws.send(JSON.stringify(['AUTH', await signer.signEvent(authEvent(url, frame[1]))])) } catch { return finish(false) }
        return
      }
      if (frame[0] === 'OK' && authed) { ws.send(JSON.stringify(['REQ', 'q', filter])); return }
      if (frame[0] === 'EVENT' && frame[1] === 'q') events.push(frame[2])
      else if (frame[0] === 'EOSE' && frame[1] === 'q') finish(true)
      else if (frame[0] === 'CLOSED' && frame[1] === 'q' && !String(frame[2] || '').startsWith('auth-required')) finish(false)
    })
    ws.on('error', () => finish(false))
    ws.on('close', () => finish(false))
  })
}

// Resolves { relay, accepted, answered, message }. answered is true when the relay said OK either way,
// so a refusal (final) can be told apart from a timeout or a dropped connection (worth retrying).
// A relay that wants a login before accepting gets one.
export function publishRelay(url, event, { signer = null, ms = 10000 } = {}) {
  return new Promise(resolve => {
    let done = false, authed = false, ws
    const finish = (accepted, message, answered = false) => { if (done) return; done = true; clearTimeout(timer); try { ws.close() } catch {} ; resolve({ relay: url, accepted, answered, message }) }
    const timer = setTimeout(() => finish(false, 'timeout'), ms)
    try { ws = new WebSocket(url) } catch (error) { return finish(false, error.message) }
    const send = () => ws.send(JSON.stringify(['EVENT', event]))
    ws.on('open', send)
    ws.on('message', async data => {
      let frame; try { frame = JSON.parse(data.toString()) } catch { return }
      if (frame[0] === 'AUTH' && signer && !authed) {
        authed = true
        try { ws.send(JSON.stringify(['AUTH', await signer.signEvent(authEvent(url, frame[1]))])) } catch (error) { finish(false, error.message) }
        return
      }
      if (frame[0] !== 'OK') return
      if (frame[1] === event.id) {
        // Wait for the login and the resend; a relay that refuses again runs into the timeout.
        if (!frame[2] && signer && String(frame[3] || '').startsWith('auth-required')) return
        finish(Boolean(frame[2]), String(frame[3] || ''), true)
      } else if (authed && frame[2]) send()
    })
    ws.on('error', error => finish(false, error.message))
    ws.on('close', () => finish(false, 'connection closed'))
  })
}
