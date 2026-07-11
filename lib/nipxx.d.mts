// nvoy-local TypeScript declarations for the vendored nipxx.mjs.
// NOT vendored — npm run sync-lib overwrites only the .mjs files. If the
// upstream lib's exports change, update this by hand.

export const KIND_DATA_SET: number
export const KIND_GRANT: number
export const KIND_GRANT_INDEX: number

/** Anything with publish/query — sync (in-memory) or async (SimplePool). */
export interface RelayLike {
  publish(event: object): Promise<unknown> | unknown
  query(filter: object): Promise<any[]> | any[]
}

export interface Signer {
  getPublicKey(): Promise<string>
  signEvent(event: object): Promise<any>
  nip44Encrypt(pub: string, plaintext: string): Promise<string>
  nip44Decrypt(pub: string, ciphertext: string): Promise<string>
}

/** Grant record as the lib speaks it (no nvoy terms — the lib predates them). */
export interface LibGrantRecord {
  publisher: string
  scopeId: string
  scopeName?: string
  relayHint?: string
  generation: number
  scopeKey: Uint8Array
  issuedAt: number
}

export interface ScopeFetchResult {
  status: 'ok' | 'stale' | 'missing'
  generation?: number
  data?: any
}

export function localSigner(sk: Uint8Array): Signer
export function newScopeKey(): Uint8Array

export function publishScope(
  relay: RelayLike,
  publisherSecret: Uint8Array | Signer,
  args: { scopeId: string; generation: number; scopeKey: Uint8Array; payload: object },
): Promise<any>

export function grant(
  relay: RelayLike,
  publisherSecret: Uint8Array | Signer,
  granteePubkey: string,
  args: { scopeId: string; generation: number; scopeKey: Uint8Array; scopeName?: string; relayHint?: string },
): Promise<any>

export function rotateScope(
  relay: RelayLike,
  publisherSecret: Uint8Array | Signer,
  args: { scopeId: string; generation: number; payload: object; scopeName?: string; survivors: string[] },
): Promise<{ scopeKey: Uint8Array; generation: number }>

export function deleteScope(
  relay: RelayLike,
  publisherSecret: Uint8Array | Signer,
  args: { scopeId: string; generation: number },
): Promise<any>

export function receiveGrants(relay: RelayLike, granteeSecret: Uint8Array | Signer): Promise<LibGrantRecord[]>

export function latestGrants<T extends { publisher: string; scopeId: string; generation: number }>(grants: T[]): T[]

export function fetchScope(
  relay: RelayLike,
  grantRecord: { publisher: string; scopeId: string; generation: number; scopeKey: Uint8Array },
): Promise<ScopeFetchResult>

export function addressBook(relay: RelayLike, granteeSecret: Uint8Array | Signer): Promise<any[]>

export function loadGrantIndex(
  relay: RelayLike,
  secret: Uint8Array | Signer,
): Promise<{ issued: any[]; received: any[] }>

export function saveGrantIndex(
  relay: RelayLike,
  secret: Uint8Array | Signer,
  index: { issued: any[]; received: any[] },
): Promise<any>

export function toReceivedEntry(g: LibGrantRecord, petname?: string, relays?: string[]): any
export function fromReceivedEntry(e: any): any
export function toIssuedEntry(
  s: { scopeId: string; scopeName?: string; generation: number; scopeKey: Uint8Array },
  grantees: string[],
): any
export function fromIssuedEntry(e: any): any
