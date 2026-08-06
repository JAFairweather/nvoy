// Every instantiation of an agent action passes a fresh tap (AD-12 3a, nvoy#111).
//
//   node test/tap.mjs
//
// Three paths signed an agent's own act with no tap: a 1-second timer publishing a keyless worker's text,
// an incoming event spawning an unattended runtime holding a signer, and two MCP tools that signed directly
// with no approval parameter at all. The third is why the second was dangerous.
//
// THE SHARPEST PART of that issue is that the restraint on the wake path lived in PROMPT TEXT — WAKE_PROMPT
// says "never auto-obey" and "do not publish under a project identity". This estate already has a name for
// configuration that exists but does not bite: `◌`. A prompt is the `◌` case applied to authority, and the
// point of this module is to make the restraint a property of the code instead.
//
// THE DESIGN DECISION UNDER TEST, because it is a decision and not a deduction: the default is DRAFT, not
// REFUSE. Refusing outright would be simpler code and the wrong change — these tools are live, the crew's
// agents speak through them right now, and a hard refusal stops work rather than gating it. The ruling says
// every instantiation QUEUES, not that agents fall silent. So the agent still acts; what it no longer does
// is sign.
//
// The assertions that matter most are the ones about what CANNOT turn this off.

import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { decideTap, draftScopeName, tapAudit, NEEDS_TAP } from '../mcp/dist/tap.js'

let pass = 0, fail = 0
const t = (name, fn) => {
  try { fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

const APPROVAL = 'a'.repeat(64)

// ── the default is a draft, and it says what did NOT happen ─────────────────
t('no approval → DRAFT, never a silent publish', () => {
  const d = decideTap('nvoy_chat_post')
  assert.equal(d.mode, 'draft')
})
t('…and the notice leads with NOT PUBLISHED, because that is the surprising part', () => {
  const { notice } = decideTap('nvoy_chat_post')
  assert.match(notice, /^NOT PUBLISHED\./)
})
t('…and it says whose signature will carry it, which is the whole point of the desk', () => {
  const { notice } = decideTap('nvoy_chat_post')
  assert.match(notice, /in his own hand/)
  assert.match(notice, /under HIS signature or not at all/)
})
t('…and it states that nothing standing can grant this — doctrine, not a setting', () => {
  const { notice } = decideTap('nvoy_chat_post')
  assert.match(notice, /Nothing standing lets an agent sign/)
  assert.match(notice, /there is no flag that turns this off/)
})
t('an empty-string approval is treated as absent, not as consent', () => {
  assert.equal(decideTap('nvoy_dm_send', '').mode, 'draft')
})

// ── a per-call approval publishes, and only that ────────────────────────────
t('a well-formed approval publishes THIS call', () => {
  const d = decideTap('nvoy_chat_post', APPROVAL)
  assert.equal(d.mode, 'publish')
  assert.match(d.why, /supplied for this call/)
})
t('a MALFORMED approval is REFUSED, not downgraded to a draft', () => {
  // Downgrading would hide a caller holding a broken token: it would appear to work, quietly, forever.
  for (const bad of ['nope', 'A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 123, {}, true]) {
    const d = decideTap('nvoy_chat_post', bad)
    assert.equal(d.mode, 'refuse', `accepted ${JSON.stringify(bad)}`)
  }
})
t('…and the refusal explains why it is not a draft', () => {
  assert.match(decideTap('nvoy_chat_post', 'nope').why, /refused, not[\s\S]{0,12}downgraded/)
})
t('an approval is the estate\'s existing provenance atom — a 64-hex event id', () => {
  // Not a bespoke token type. `["approval", id, approver]` is already the act side's one NIP-worthy piece.
  assert.equal(decideTap('nvoy_chat_post', APPROVAL).mode, 'publish')
})

// ── tools that do not emit an agent act are untouched ───────────────────────
t('a read tool is not gated — this is not a blanket brake on the server', () => {
  assert.equal(decideTap('nvoy_scope_read').mode, 'publish')
  assert.equal(decideTap('nvoy_grants_list').mode, 'publish')
})
t('the gated set is explicit, and covers exactly the two signing tools', () => {
  assert.deepEqual([...NEEDS_TAP].sort(), ['nvoy_chat_post', 'nvoy_dm_send'])
})
t('the draft path is the one drafts.ts already admits', () => {
  // drafts.ts refuses any scope outside `draft:` at the signing boundary, and Ngage renders that namespace.
  assert.ok(draftScopeName('nvoy_chat_post', 'abcdef1234').startsWith('draft:'))
})
t('a post and a DM are DIFFERENT drafts — approving them is not the same decision', () => {
  // A desk that rendered them identically would collapse two decisions into one.
  assert.match(draftScopeName('nvoy_chat_post', 'abcdef1234'), /^draft:post\//)
  assert.match(draftScopeName('nvoy_dm_send', 'abcdef1234'), /^draft:dm\//)
})

// ── the audit line ──────────────────────────────────────────────────────────
t('both outcomes are logged, not only the refusals', () => {
  // Logging only refusals would make the APPROVED path the invisible one — and that is the path a reader
  // will later want to find.
  assert.match(tapAudit('nvoy_chat_post', decideTap('nvoy_chat_post')), /→ draft/)
  assert.match(tapAudit('nvoy_chat_post', decideTap('nvoy_chat_post', APPROVAL)), /→ publish/)
})

// ── what must NOT be able to turn this off ─────────────────────────────────
t('THE INVARIANT: no env var, config key or standing grant can bypass the tap', () => {
  // Those are all standing authority to sign, which is the thing being removed. Asserted at the source,
  // because the tempting "fix" for a noisy gate is exactly to add one of them.
  const src = readFileSync(new URL('../mcp/src/tap.ts', import.meta.url), 'utf8')
  const code = src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ')
  assert.doesNotMatch(code, /process\.env/, 'an env var would be standing authority')
  assert.doesNotMatch(code, /readFileSync|loadConfig/, 'reading config would be standing authority')
})
t('the decision depends ONLY on the tool name and the per-call approval', () => {
  // Same inputs, same answer, every time — no clock, no ambient state.
  const a = decideTap('nvoy_chat_post'), b = decideTap('nvoy_chat_post')
  assert.deepEqual(a, b)
})

// ── both tools are wired to the gate, asserted at the source ────────────────
//
// The module can be perfect and unreached. That is not hypothetical here: the gate landed on main inside a
// PR titled "Four kinds of grantee" because `git add -A` swept it in, and its own test was never wired into
// `npm test` — so a behavioural change to a live signing tool shipped both undisclosed and unexercised.
// These assertions are the cheap guard against the reached-ness half.
{
  const chat = readFileSync(new URL('../mcp/src/chat.ts', import.meta.url), 'utf8')
  for (const tool of ['nvoy_chat_post', 'nvoy_dm_send']) {
    t(`${tool} consults the gate`, () => {
      assert.match(chat, new RegExp(`decideTap\\('${tool}'`), 'the tool must call decideTap')
    })
    t(`${tool} accepts a per-call approval`, () => {
      // Without the parameter the gate can only ever draft, which would make the tool unusable rather than
      // gated — and someone would then add an env var to "fix" it.
      const block = chat.slice(chat.indexOf(`'${tool}'`), chat.indexOf(`'${tool}'`) + 2600)
      assert.match(block, /approval: z\.string\(\)\.optional\(\)/)
    })
    t(`${tool} refuses a malformed approval instead of publishing`, () => {
      const block = chat.slice(chat.indexOf(`decideTap('${tool}'`))
      assert.match(block.slice(0, 400), /mode === 'refuse'/)
    })
  }
  t('the DM draft carries its recipient — a desk cannot judge a DM without knowing who it is for', () => {
    assert.match(chat, /dm_to: nip19\.npubEncode\(recipient\)/)
  })
  t('neither tool signs before the gate has answered', () => {
    // Order matters: a signEvent above the decision would make the gate decorative.
    for (const tool of ['nvoy_chat_post', 'nvoy_dm_send']) {
      const from = chat.indexOf(`'${tool}'`)
      const block = chat.slice(from, chat.indexOf('server.registerTool', from + 10) + 1 || undefined)
      const gate = block.indexOf('decideTap')
      const sign = block.search(/signEvent|sealAndWrap/)
      assert.ok(gate > -1 && (sign === -1 || gate < sign), `${tool} signs before it asks`)
    }
  })
}

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
