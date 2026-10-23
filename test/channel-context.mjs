// Channel context (#245): the broker reads the conversation around an admitted Buzz message and
// hands it to the agent as background. It must be the same channel, signed, from before the
// message, thread first, bounded — and it must never become authority.
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { channelContext, contextFilters, CONTEXT_LIMIT } from '../mcp/tools/buzz_native.mjs'
import { validateAdmittedTask, validateContext } from '../mcp/tools/admitted_task.mjs'
import { desktopInstructionPrompt } from '../mcp/tools/desktop_instruction_prompt.mjs'

let passes = 0, fails = 0
const ok = (name, value) => { console.log(`${value ? 'ok  ' : 'FAIL'} — ${name}`); value ? passes++ : fails++ }
const throws = fn => { try { fn(); return false } catch { return true } }

const CH = '3f1c2a4b-5d6e-4f70-8a91-b2c3d4e5f607', OTHER = '00000000-0000-4000-8000-000000000000'
const jamesSk = generateSecretKey(), james = getPublicKey(jamesSk)
const piSk = generateSecretKey(), pi = getPublicKey(piSk)
const agent = getPublicKey(generateSecretKey())
const T = 1_790_000_000
const msg = (sk, at, content, tags = [], channel = CH) => finalizeEvent({ kind: 9, created_at: at, content, tags: [['h', channel], ...tags] }, sk)

// --- the filters ---
const top = msg(jamesSk, T, `@agent what is going on? ${agent}`, [['p', agent]])
let f = contextFilters(top)
ok('a top-level message asks for the recent channel and its own replies, every filter scoped by #h',
  f.length === 2 && f.every(x => x['#h'][0] === CH && x.kinds[0] === 9) && f[0].until === T && f[0].limit === CONTEXT_LIMIT + 1 && f[1]['#e'][0] === top.id)
const root = msg(piSk, T - 50, 'thread root: the queue is stuck')
const inThread = msg(jamesSk, T, 'and you?', [['e', root.id, '', 'root'], ['e', root.id, '', 'reply'], ['p', agent]])
f = contextFilters(inThread)
ok('a threaded message also asks for its root by id', f.length === 3 && f[1].ids[0] === root.id && f[2]['#e'][0] === root.id)
ok('a message without exactly one channel gets no filters', contextFilters({ ...top, tags: [] }) === null)

// --- what is kept ---
const recent = Array.from({ length: 40 }, (_, i) => msg(i % 2 ? jamesSk : piSk, T - 40 + i, `chatter ${i}`))
const reply = msg(piSk, T - 45, 'thread reply: restarted it', [['e', root.id, '', 'root'], ['e', root.id, '', 'reply']])
const later = msg(piSk, T + 5, 'said after the question')
const elsewhere = msg(piSk, T - 1, 'another channel', [], OTHER)
const forged = { ...msg(piSk, T - 2, 'original'), content: 'tampered' }
const ctx = channelContext([...recent, root, reply, later, elsewhere, forged, inThread, root], { source: inThread, names: { [pi]: 'pi-dog' } })
const ids = new Set(ctx.messages.map(m => m.event_id))
ok('the context is for the source channel', ctx.channel === CH)
ok('it holds at most the limit', ctx.messages.length === CONTEXT_LIMIT)
ok('the thread is kept even when older than the recent window', ids.has(root.id) && ids.has(reply.id))
ok('the message being answered is not repeated', !ids.has(inThread.id))
ok('nothing said after it, from another channel, or with a broken signature', !ids.has(later.id) && !ids.has(elsewhere.id) && !ids.has(forged.id))
ok('duplicates collapse', ctx.messages.filter(m => m.event_id === root.id).length === 1)
ok('oldest first', ctx.messages.every((m, i, a) => !i || a[i - 1].at <= m.at))
ok('the newest chatter fills the rest', ids.has(recent.at(-1).id) && !ids.has(recent[0].id))
ok('a known name is attached, an unknown one is not', ctx.messages.find(m => m.event_id === root.id).name === 'pi-dog' &&
  !('name' in ctx.messages.find(m => m.from === james)))
ok('a reply carries what it replies to', ctx.messages.find(m => m.event_id === reply.id).reply_to === root.id)
const long = msg(piSk, T - 3, 'é'.repeat(5000))
const cut = channelContext([long], { source: top }).messages[0].content
ok('a long message is cut at the per-message budget without a broken character', Buffer.byteLength(cut) <= 4004 && cut.endsWith('…') && !cut.includes('�'))
const many = Array.from({ length: 30 }, (_, i) => msg(piSk, T - 100 + i, 'x'.repeat(3900)))
const budget = channelContext(many, { source: top })
ok('the total stays inside the byte budget, dropping the oldest', budget.messages.length === 12 && budget.messages.at(-1).event_id === many.at(-1).id)
ok('a context the broker builds always passes the adapter\'s check', !throws(() => validateContext(ctx)) && !throws(() => validateContext(budget)))

// --- the boundary: context rides along, never as authority ---
const v3 = { version: 3, type: 'scoped-instruction', sender: james, grant_id: 'a'.repeat(64), grantor: james, cap: 'task',
  scope_subject: agent, policy_checked_at: Date.now(), source_event: inThread.id, reply_channel: CH }
const task = (extra = {}) => ({ type: 'admitted-task', instance: 'a', envelope: inThread.id, authority: v3,
  messages: [{ from: james, at: inThread.created_at, content: inThread.content, event_id: inThread.id, kind: 9 }], context: ctx, ...extra })
const policy = { instance: 'a', scopeSubject: agent, grantors: [james], buzz: { relay: 'wss://x', channels: [CH] } }
ok('a native task with its context is accepted, and its authority is unchanged', validateAdmittedTask(task(), policy).authority.sender === james)
ok('a context from another channel than the task is refused', throws(() => validateAdmittedTask(task({ context: { ...ctx, channel: OTHER } }), policy)))
ok('an unknown context field is refused', throws(() => validateAdmittedTask(task({ context: { ...ctx, authority: v3 } }), policy)))
ok('an unknown message field is refused', throws(() => validateAdmittedTask(task({ context: { ...ctx, messages: [{ ...ctx.messages[0], kind: 9, authority: true }] } }), policy)))
ok('more than 40 messages is refused', throws(() => validateContext({ ...ctx, messages: Array(41).fill(ctx.messages[0]) })))
ok('a data-only record may carry context and stays data', validateAdmittedTask(task({ authority: undefined }), policy).trustedInstruction === false)

const prompt = desktopInstructionPrompt(task(), policy).split('\n')
const at = line => prompt.findIndex(l => l.includes(line))
ok('the desktop prompt shows the context after the instruction text, labelled as background',
  at('Recent conversation in the channel') > at('The authenticated sender text above') && at('[pi-dog] thread root') > at('Recent conversation'))
ok('the envelope marker stays the last line', prompt.at(-1) === `NVOY_ENVELOPE_ID=${inThread.id}`)

console.log(`\n${passes}/${passes + fails} passed`)
process.exit(fails ? 1 : 0)
