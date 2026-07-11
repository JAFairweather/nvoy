// wsrelay.mjs — the in-memory relay behind a real websocket, speaking just
// enough NIP-01 (EVENT/REQ/CLOSE → OK/EVENT/EOSE/CLOSED) for nostr-tools'
// SimplePool. Lets the MCP conformance test exercise the ACTUAL server
// binary — LiveRelay transport and all — fully offline and deterministic.

import { WebSocketServer } from 'ws'
import { Relay } from '../lib/relay.mjs'

export function startWsRelay(port = 0) {
  const store = new Relay()
  const wss = new WebSocketServer({ host: '127.0.0.1', port })

  wss.on('connection', (ws) => {
    ws.on('message', (raw) => {
      let msg
      try { msg = JSON.parse(raw) } catch { return }
      const [type, ...rest] = msg
      if (type === 'EVENT') {
        const event = rest[0]
        try {
          store.publish(event)
          ws.send(JSON.stringify(['OK', event.id, true, '']))
        } catch (e) {
          ws.send(JSON.stringify(['OK', event.id, false, `invalid: ${e.message}`]))
        }
      } else if (type === 'REQ') {
        const [subId, ...filters] = rest
        const seen = new Set()
        for (const filter of filters)
          for (const event of store.query(filter))
            if (!seen.has(event.id) && seen.add(event.id))
              ws.send(JSON.stringify(['EVENT', subId, event]))
        ws.send(JSON.stringify(['EOSE', subId]))
      } else if (type === 'CLOSE') {
        ws.send(JSON.stringify(['CLOSED', rest[0], '']))
      }
    })
  })

  return new Promise((resolve) => {
    wss.on('listening', () => resolve({
      store, // direct handle: seed events + observerView() without a socket
      url: `ws://127.0.0.1:${wss.address().port}`,
      close: () => new Promise((r) => {
        for (const c of wss.clients) c.terminate()
        wss.close(r)
      }),
    }))
  })
}

// Standalone mode for browser E2E: `node test/wsrelay.mjs 4460` keeps a
// relay up on that port so the console (Settings → ws://127.0.0.1:4460) and
// the MCP server share one offline, deterministic relay.
import { pathToFileURL } from 'node:url'
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href && process.argv[2]) {
  const { url } = await startWsRelay(Number(process.argv[2]))
  console.log(`wsrelay listening on ${url} (ctrl-c to stop)`)
}
