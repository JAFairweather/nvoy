// serve.mjs — minimal static server for the Nvoy console. Serves the repo
// root so /console/*.mjs can import ../lib/nipxx.mjs — the same protocol lib
// Node and the MCP server run.
//
//   node console/serve.mjs   →   http://localhost:4443/

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, join, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = normalize(join(fileURLToPath(import.meta.url), '..', '..'))
const types = {
  '.html': 'text/html', '.mjs': 'text/javascript', '.js': 'text/javascript',
  '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml',
}

createServer(async (req, res) => {
  let path = decodeURIComponent(new URL(req.url, 'http://x').pathname)
  if (path === '/') { res.writeHead(302, { location: '/console/' }); return res.end() }
  if (path === '/console/') path = '/console/index.html'
  const file = normalize(join(root, path))
  try {
    if (!file.startsWith(root)) throw new Error('outside root')
    const body = await readFile(file)
    res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' })
    res.end(body)
  } catch {
    res.writeHead(404)
    res.end('not found')
  }
}).listen(4443, () => console.log('Nvoy console → http://localhost:4443/'))
