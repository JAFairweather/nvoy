import { Relay, nip19, verifyEvent, type Event, type Filter } from 'nostr-tools'

const KIND_GRANT = 440
const KIND_REVOCATION = 441
const MAX_EVENTS = 1000
const QUERY_TIMEOUT_MS = 4000

export type RelayQuery = (url: string, filter: Filter) => Promise<Event[]>

export type CapabilityRow = {
  grant_id: string
  grantor_npub: string
  cap: string
  label: string
  scope_hash: string | null
  granted_at: number
  expires_at: number | null
  status: 'active' | 'expired' | 'revoked' | 'unverifiable'
  revocation_id: string | null
}

const labels: Record<string, string> = {
  admit: 'Channel admission',
  'admit+read': 'Channel admission + read',
  task: 'Tasking authority',
  'task+act': 'Tasking + act',
  'task-relay': 'Task relay carrier',
  mirror: 'Mirror consent',
}

const tagValues = (event: Event, name: string) => event.tags
  .filter(tag => tag[0] === name && typeof tag[1] === 'string')
  .map(tag => tag[1])

/** One relay counts as answered only after its EOSE. A TCP connection or one event is not a
 * complete read: treating either as success would turn a truncated response into false absence. */
export async function queryRelay(url: string, filter: Filter): Promise<Event[]> {
  const relay = new Relay(url, { enableReconnect: false })
  const abort = new AbortController()
  const timer = setTimeout(() => abort.abort(), QUERY_TIMEOUT_MS)
  try {
    await relay.connect({ timeout: QUERY_TIMEOUT_MS, abort: abort.signal })
    return await new Promise<Event[]>((resolve, reject) => {
      const events: Event[] = []
      let settled = false
      const finish = (fn: () => void) => { if (!settled) { settled = true; fn() } }
      relay.subscribe([filter], {
        abort: abort.signal,
        eoseTimeout: QUERY_TIMEOUT_MS,
        onevent: event => { if (events.length < MAX_EVENTS) events.push(event) },
        oneose: () => finish(() => resolve(events)),
        onclose: reason => finish(() => reject(new Error(reason || 'relay closed before EOSE'))),
      })
    })
  } finally {
    clearTimeout(timer)
    relay.close()
  }
}

const readSet = async (relays: string[], filter: Filter, query: RelayQuery) => {
  const results = await Promise.allSettled(relays.map(url => query(url, filter)))
  const events = new Map<string, Event>()
  let answered = 0
  for (const result of results) {
    if (result.status !== 'fulfilled') continue
    answered++
    for (const event of result.value) events.set(event.id, event)
  }
  return { answered, events: [...events.values()] }
}

export async function readHeldCapabilities(
  relays: string[],
  subject: string,
  query: RelayQuery = queryRelay,
  now = Math.floor(Date.now() / 1000),
) {
  const configured = [...new Set(relays.map(String).map(value => value.trim()).filter(Boolean))]
  const grantsRead = await readSet(configured, {
    kinds: [KIND_GRANT], '#p': [subject], limit: MAX_EVENTS,
  }, query)
  const grantCoverageComplete = configured.length > 0 && grantsRead.answered === configured.length

  const grants = grantsRead.events.filter(event => {
    if (event.kind !== KIND_GRANT || !verifyEvent(event)) return false
    if (!tagValues(event, 'p').includes(subject)) return false
    return tagValues(event, 'da-cap').length === 1
  })

  if (!grantCoverageComplete && grants.length === 0) {
    return {
      capabilities: null,
      verification: {
        status: 'unverifiable' as const,
        configured_relays: configured.length,
        grant_query_answered: grantsRead.answered,
        revocation_query_answered: null,
        statement: `${grantsRead.answered}/${configured.length} configured relays completed the grant query. Nothing could be verified absent until every configured relay answers.`,
      },
    }
  }

  if (!grants.length && grantCoverageComplete) {
    return {
      capabilities: [] as CapabilityRow[],
      verification: {
        status: 'verified' as const,
        configured_relays: configured.length,
        grant_query_answered: grantsRead.answered,
        revocation_query_answered: null,
        statement: 'Every configured relay completed the grant query and returned no verified capability grant naming this identity.',
      },
    }
  }

  const grantIds = grants.map(event => event.id)
  const grantAuthors = [...new Set(grants.map(event => event.pubkey))]
  const revocationsRead = await readSet(configured, {
    kinds: [KIND_REVOCATION], authors: grantAuthors, '#e': grantIds, limit: MAX_EVENTS,
  }, query)
  const revocationCoverageComplete = configured.length > 0 && revocationsRead.answered === configured.length
  const revocations = new Map<string, Event>()
  if (revocationsRead.answered > 0) {
    const grantsById = new Map(grants.map(event => [event.id, event]))
    for (const event of revocationsRead.events) {
      if (event.kind !== KIND_REVOCATION || !verifyEvent(event)) continue
      for (const id of tagValues(event, 'e')) {
        const grant = grantsById.get(id)
        if (grant && event.pubkey === grant.pubkey) revocations.set(id, event)
      }
    }
  }

  const capabilities: CapabilityRow[] = grants.map(event => {
    const cap = tagValues(event, 'da-cap')[0]
    const expirationRaw = tagValues(event, 'expiration')[0]
    const expiresAt = /^\d+$/.test(expirationRaw || '') ? Number(expirationRaw) : null
    const revocation = revocations.get(event.id)
    const status: CapabilityRow['status'] = revocation ? 'revoked'
      : !grantCoverageComplete || !revocationCoverageComplete ? 'unverifiable'
        : expiresAt !== null && expiresAt <= now ? 'expired' : 'active'
    return {
      grant_id: event.id,
      grantor_npub: nip19.npubEncode(event.pubkey),
      cap,
      label: labels[cap] || `Capability: ${cap}`,
      scope_hash: tagValues(event, 'da-scope')[0] || null,
      granted_at: event.created_at,
      expires_at: expiresAt,
      status,
      revocation_id: revocation?.id || null,
    }
  }).sort((a, b) => b.granted_at - a.granted_at || b.grant_id.localeCompare(a.grant_id))

  const verifiable = grantCoverageComplete && revocationCoverageComplete
  return {
    capabilities,
    verification: {
      status: verifiable ? 'verified' as const : 'unverifiable' as const,
      configured_relays: configured.length,
      grant_query_answered: grantsRead.answered,
      revocation_query_answered: revocationsRead.answered,
      statement: verifiable
        ? 'Every configured relay completed both the grant and revocation queries.'
        : `Relay coverage is incomplete (grants ${grantsRead.answered}/${configured.length}; revocations ${revocationsRead.answered}/${configured.length}). Positive signed evidence is shown, but absence and current active status are unverifiable.`,
    },
  }
}
