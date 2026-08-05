// vendored: components/nave-tabs.mjs @ sha256:d949e9e403f09a30 — nave.pub@refs/heads/m
// DO NOT EDIT. Change it in nave.pub and re-run: npm run sync-vendor
// Source of truth: nave.pub/components/nave-tabs.mjs — copy in, do not edit.
//
// Three tab idioms exist across five surfaces and NONE of them is defined in
// components/ or design/:
//   .tab.active          nvoy console, ngage
//   .tab.on              nact app.html
//   .console-tabs a.active   waggle console
// So the estate has three visual languages for the same control, and one app
// (nact) has no hash routing at all — its tab state is discarded on click, which
// is why nothing there is deep-linkable and a cross-plane link cannot land.
//
// This module is the promotion (AD-11). It carries three things the idioms did not:
//
//   1. HASH ROUTING, so every tab is a URL. `#agent/<npub>` resolving on all four
//      surfaces is the whole point of having one join key (AD-12).
//   2. THE BADGE LAW. A count badge means A HUMAN DECISION IS WAITING — nothing
//      else may carry one. Passing `badge` for anything else is the bug this
//      signature is shaped to discourage; there is no `count` option.
//   3. THE DIVIDER, so a surface can say "the screens after this one are about a
//      machine, not about your agents" — Nact's whole tab order problem in one
//      declaration.
//
// Styling is token-driven with dark-canonical fallbacks baked in, same as the
// titlebar. `.active` is the class, because two of the three idioms already use it.

const STYLE_ID = 'nave-tabs-style'
const CSS = `
.nave-tabs{display:flex;gap:3px;border-bottom:1px solid var(--line,#2a2317);flex-wrap:wrap}
.nave-tabs .nt-tab{background:none;border:0;border-bottom:2px solid transparent;
  color:var(--dim,#9c927f);font:650 13px var(--sans,system-ui);padding:9px 11px 8px;
  cursor:pointer;display:flex;align-items:center;gap:6px;white-space:nowrap}
.nave-tabs .nt-tab:hover{color:var(--text,#f4efe4)}
.nave-tabs .nt-tab:focus-visible{outline:2px solid var(--accent,#c39a56);outline-offset:-2px}
.nave-tabs .nt-tab[aria-selected="true"]{color:var(--accent-bright,#e2c079);
  border-bottom-color:var(--accent,#c39a56)}
.nave-tabs .nt-badge{background:var(--accent,#c39a56);color:var(--accent-ink,#0b0906);
  border-radius:var(--r-pill,999px);font:700 10px var(--mono,monospace);padding:1px 6px}
.nave-tabs .nt-div{border-left:1px solid var(--line,#2a2317);margin-left:7px;padding-left:14px}
.nave-tabs .nt-tab.nt-after-div{color:var(--faint,#6f6555)}
.nave-tabs .nt-tab.nt-after-div:hover{color:var(--dim,#9c927f)}
`

function ensureStyle(doc) {
  if (doc.getElementById(STYLE_ID)) return
  const s = doc.createElement('style')
  s.id = STYLE_ID
  s.textContent = CSS
  doc.head.append(s)
}

/**
 * @typedef {object} NaveTab
 * @property {string} id     the hash route, e.g. 'queue' → #queue
 * @property {string} label  what the person reads
 * @property {number} [badge] ONLY when a human decision is waiting (the badge law)
 * @property {boolean} [afterDivider] first tab of the plumbing group
 */

/**
 * @param {Element|string} el
 * @param {object} o
 * @param {NaveTab[]} o.tabs
 * @param {string} [o.active]        defaults to the hash, else the first tab
 * @param {(id:string)=>void} [o.onChange]
 * @param {boolean} [o.hash=true]    own the URL hash (set false to drive it yourself)
 * @param {string} [o.label='Sections'] aria-label for the tablist
 */
export function renderTabs(el, o = {}) {
  const root = typeof el === 'string' ? document.querySelector(el) : el
  if (!root) throw new Error('renderTabs: no such element')
  const doc = root.ownerDocument
  ensureStyle(doc)

  const tabs = (o.tabs || []).filter(Boolean)
  if (!tabs.length) throw new Error('renderTabs: no tabs')
  const useHash = o.hash !== false
  root.__naveTabsOpts = o

  const ids = tabs.map(t => t.id)
  const fromHash = () => {
    // Only the FIRST hash segment selects a tab, so `#ledger/grant/<id>` selects
    // `ledger` and leaves the rest to the screen. Deep links keep working.
    const seg = (doc.defaultView?.location.hash || '').replace(/^#/, '').split('/')[0]
    return ids.includes(seg) ? seg : null
  }
  let active = o.active && ids.includes(o.active) ? o.active
    : (useHash && fromHash()) || tabs[0].id

  root.classList.add('nave-tabs')
  root.setAttribute('role', 'tablist')
  root.setAttribute('aria-label', o.label || 'Sections')

  const paint = () => {
    root.textContent = ''
    let seenDivider = false
    for (const t of tabs) {
      if (t.afterDivider) seenDivider = true
      const b = doc.createElement('button')
      b.type = 'button'
      b.className = 'nt-tab' + (t.afterDivider ? ' nt-div' : '') + (seenDivider ? ' nt-after-div' : '')
      b.setAttribute('role', 'tab')
      b.setAttribute('aria-selected', String(t.id === active))
      b.dataset.tab = t.id
      b.append(doc.createTextNode(t.label))
      // The badge law, enforced by shape: a badge is a positive integer or absent.
      if (Number.isFinite(t.badge) && t.badge > 0) {
        const s = doc.createElement('span')
        s.className = 'nt-badge'
        s.title = 'waiting for you'
        s.textContent = String(t.badge)
        b.append(s)
      }
      b.addEventListener('click', () => select(t.id))
      b.addEventListener('keydown', (e) => {
        const i = ids.indexOf(t.id)
        if (e.key === 'ArrowRight') { e.preventDefault(); select(ids[(i + 1) % ids.length]) }
        if (e.key === 'ArrowLeft')  { e.preventDefault(); select(ids[(i - 1 + ids.length) % ids.length]) }
      })
      root.append(b)
    }
  }

  function select(id, fromRoute = false) {
    if (!ids.includes(id)) return
    active = id
    paint()
    if (useHash && !fromRoute && doc.defaultView) {
      const cur = (doc.defaultView.location.hash || '').replace(/^#/, '')
      if (cur.split('/')[0] !== id) doc.defaultView.location.hash = id
    }
    root.querySelector(`[data-tab="${id}"]`)?.focus?.({ preventScroll: true })
    o.onChange?.(id)
  }

  if (useHash && doc.defaultView) {
    doc.defaultView.addEventListener('hashchange', () => {
      const id = fromHash()
      if (id && id !== active) select(id, true)
    })
  }

  paint()
  o.onChange?.(active)
  return { select: (id) => select(id), get active() { return active } }
}

/** Shallow-merge and re-render — e.g. to update a badge count after a poll. */
export function updateTabs(el, patch = {}) {
  const root = typeof el === 'string' ? document.querySelector(el) : el
  if (!root) throw new Error('updateTabs: no such element')
  return renderTabs(root, { ...(root.__naveTabsOpts || {}), ...patch })
}
