// vendored: components/nave-source-note.mjs @ sha256:984c1a0ac3530e44 — nave.pub@refs/heads/m
// DO NOT EDIT. Change it in nave.pub and re-run: npm run sync-vendor
// Source of truth: nave.pub/components/nave-source-note.mjs — copy in, do not edit.
//
// AD-11 says "disconnected means empty": a control plane never renders fabricated
// approvals as if real. As a doctrine that is easy to agree with and easy to forget.
// As a component it is enforced, because a section that assembles from a store has
// to pass through here to say where its rows came from.
//
// Three states, and the third is the point:
//
//   ANSWERED   'from your Grant Index · 4 rows'
//   EMPTY      'nothing here'                    ← affirmative; only when the store answered
//   SILENT     'Nact did not answer. Nothing is shown because nothing could be
//               verified — this is not the same as "nothing granted."'
//
// SILENT renders a skeleton with a reason, never a zero and never a blank. A zero is
// a lie (it claims the store said none); a blank is a shrug (it says nothing about
// why). The wording generalises waggle's relay line, which is the best instance of
// this in the estate:
//   "No relay answered. Nothing is shown because nothing could be verified — this is
//    not the same as 'nobody is admitted.'"
//
// Usage:
//   sourceNote({ store: 'your Grant Index', count: 4 })
//   sourceNote({ store: 'Nact', answered: false, notSameAs: 'nothing granted' })
//   sourceNote({ store: 'relays', answered: 2, of: 4, count: 6 })

/** The three states, exported so callers can branch without string-matching. */
export const SOURCE = { ANSWERED: 'answered', EMPTY: 'empty', SILENT: 'silent' }

/**
 * @param {object} o
 * @param {string} o.store       what answered, in the words a person would use
 * @param {boolean|number} [o.answered=true]  false → SILENT; a number → "N/M answered"
 * @param {number} [o.of]        total sources tried, when `answered` is a count
 * @param {number} [o.count]     rows obtained (0 with answered → EMPTY)
 * @param {string} [o.unit='row'] singular noun for the rows
 * @param {string} [o.notSameAs] the wrong conclusion this state must not imply
 * @returns {{state:string, stamp:string, body:string|null, ok:boolean}}
 *   `stamp` is the short line for a section header; `body` is the sentence to render
 *   in place of content when there is none to render, or null when there is.
 */
export function sourceNote(o = {}) {
  const store = o.store || 'that source'
  const partial = typeof o.answered === 'number'
  const answered = partial ? o.answered > 0 : o.answered !== false
  const reach = partial && o.of ? ` · ${o.answered}/${o.of} answered` : ''

  if (!answered) {
    const wrong = o.notSameAs || 'nothing existing'
    return {
      state: SOURCE.SILENT,
      stamp: `${store} did not answer`,
      body: `${cap(store)} did not answer. Nothing is shown because nothing could be ` +
            `verified — this is not the same as "${wrong}".`,
      ok: false,
    }
  }

  const n = Number.isFinite(o.count) ? o.count : null
  if (n === 0) {
    return { state: SOURCE.EMPTY, stamp: `from ${store}${reach}`, body: 'nothing here', ok: true }
  }

  const unit = o.unit || 'row'
  const rows = n === null ? '' : ` · ${n} ${unit}${n === 1 ? '' : 's'}`
  return { state: SOURCE.ANSWERED, stamp: `from ${store}${rows}${reach}`, body: null, ok: true }
}

const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1)

/**
 * Render the note into a container. DOM-optional: pass a document to use it in a
 * test, or call sourceNote() alone if you render your own markup.
 * Adds `data-source-state` so CSS (and a test) can key on the state rather than
 * on the copy.
 */
export function renderSourceNote(el, o = {}) {
  const root = typeof el === 'string' ? document.querySelector(el) : el
  if (!root) throw new Error('renderSourceNote: no such element')
  const note = sourceNote(o)
  root.setAttribute('data-source-state', note.state)
  root.textContent = note.body ?? ''
  root.hidden = note.body === null
  return note
}

/**
 * Guard for the case this module exists to prevent: a caller about to render a
 * count from a store that never answered. Returns the count when it is real, and
 * null when a number would be a claim rather than a fact.
 *
 *   honestCount({ answered: false, count: 0 })  → null   (never render "0")
 *   honestCount({ answered: true,  count: 0 })  → 0
 */
export function honestCount(o = {}) {
  const partial = typeof o.answered === 'number'
  const answered = partial ? o.answered > 0 : o.answered !== false
  if (!answered) return null
  return Number.isFinite(o.count) ? o.count : null
}
