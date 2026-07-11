// nvoy-local TypeScript declarations for the vendored liverelay.mjs.
// NOT vendored — npm run sync-lib overwrites only the .mjs files.

import type { RelayLike } from './nipxx.mjs'

export class LiveRelay implements RelayLike {
  constructor(urls: string[])
  urls: string[]
  publish(event: object): Promise<{ acks: number; of: number; rejections: string[] }>
  query(filter: object): Promise<any[]>
  close(): void
}

export class LocalRelay implements RelayLike {
  constructor(inner: { publish(event: object): unknown; query(filter: object): any[] })
  publish(event: object): Promise<{ acks: number; of: number; rejections: string[] }>
  query(filter: object): Promise<any[]>
  close(): void
}
