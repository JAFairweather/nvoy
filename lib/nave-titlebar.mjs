// vendored from JAFairweather/nave.pub @ 6516d86 — do not edit; npm run sync-titlebar
// Source of truth: nave.pub/components/nave-titlebar.mjs — copy in, do not edit.
// The unified Nave title bar (the second half of the common sign-in work —
// nave-connect, nact#16), as a renderer. No imports, no build step: apps
// vendor this file next to their vendored nave-connect and call
//
//   renderTitlebar(el, { appName, npub, kind, onRefresh, onLogout, onSignIn })
//   updateTitlebar(el, patch)   // shallow-merge into the last opts, re-render
//
// with `kind` straight off nave-connect's signer (`signer.kind`):
//   nip07 → "extension"   nip46 → "bunker"   local → "local key"
// (a display label may also be passed through verbatim). `npub` set → the
// signed-in cluster (kind badge, click-to-copy npub pill truncated in the
// middle, Refresh, Log out); `npub` null → the signed-out cluster (a Sign in
// button, rendered only when onSignIn is given). Buttons render only when
// their callback is given. Copy uses the async clipboard API, falls back to
// execCommand, and — if both are unavailable — expands the pill to the full
// npub and selects it so a manual copy still works.
//
// Options: appName (text), tagline (text, optional), sealSvg (an inline-SVG
// string — a TRUSTED app-authored literal, never user input), npub, kind,
// onRefresh, onLogout, onSignIn, signInLabel. The markup and CSS here are the
// same as components/nave-titlebar.html — keep the two in lock-step. Styling
// is token-driven (design/tokens.css) with dark-canonical fallbacks baked in.

const STYLE_ID = 'nave-titlebar-style'

const CSS = `
  .nave-titlebar { position: sticky; top: 0; z-index: 20;
    border-bottom: 1px solid var(--line, #2a2317);
    background: var(--bg, #0b0906);
    background: color-mix(in srgb, var(--bg, #0b0906) 86%, transparent);
    backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
    color: var(--text, #f4efe4);
    font-family: var(--sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif); }
  .nave-titlebar .ntb-bar { display: flex; align-items: center; gap: 13px;
    max-width: 1080px; margin: 0 auto; padding: 13px 28px; }
  .nave-titlebar .ntb-seal { width: 40px; height: 40px; flex: none; }
  .nave-titlebar .ntb-seal:empty { display: none; }
  .nave-titlebar .ntb-seal svg { width: 100%; height: 100%; display: block; }
  .nave-titlebar .ntb-name { margin: 0; font-weight: 800; font-size: 21px;
    letter-spacing: 0.13em; text-transform: uppercase; color: var(--accent, #c39a56); }
  .nave-titlebar .ntb-name::first-letter { color: var(--text, #f4efe4); }
  .nave-titlebar .ntb-tag { color: var(--dim, #9c927f); font-size: 11.5px; font-weight: 500;
    letter-spacing: 0.06em; text-transform: uppercase;
    padding-left: 13px; border-left: 1px solid var(--line, #2a2317); }
  .nave-titlebar .ntb-tag:empty { display: none; }
  .nave-titlebar .ntb-spacer { flex: 1; }
  .nave-titlebar .ntb-me, .nave-titlebar .ntb-signin { display: flex; align-items: center; gap: 10px; }
  .nave-titlebar:not([data-signed-in]) .ntb-me { display: none; }
  .nave-titlebar[data-signed-in] .ntb-signin { display: none; }
  .nave-titlebar .ntb-badge { font-size: 10.5px; padding: 3px 9px; border-radius: 999px;
    font-family: var(--mono, ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace);
    letter-spacing: 0.06em; border: 1px solid var(--line, #2a2317);
    color: var(--dim, #9c927f); white-space: nowrap; }
  .nave-titlebar .ntb-badge.ntb-kind-extension { border-color: var(--good, #8fae6a); color: var(--good, #8fae6a); }
  .nave-titlebar .ntb-badge.ntb-kind-bunker { border-color: var(--accent, #c39a56); color: var(--accent, #c39a56); }
  .nave-titlebar .ntb-badge.ntb-kind-local { border-color: var(--warn, #d9a648); color: var(--warn, #d9a648); }
  .nave-titlebar .ntb-npub { font-size: 11px; letter-spacing: 0.05em;
    font-family: var(--mono, ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace);
    border: 1px solid var(--line, #2a2317); color: var(--dim, #9c927f); border-radius: 999px;
    padding: 5px 12px; cursor: pointer; transition: border-color .14s, color .14s; }
  .nave-titlebar .ntb-npub:hover { border-color: var(--accent, #c39a56); color: var(--accent-bright, #e2c079); }
  .nave-titlebar .ntb-npub.ntb-copied { border-color: var(--good, #8fae6a); color: var(--good, #8fae6a); }
  .nave-titlebar .ntb-npub.ntb-expanded { word-break: break-all; user-select: all; }
  .nave-titlebar .ntb-btn { background: transparent; color: var(--text, #f4efe4);
    border: 1px solid var(--line, #2a2317); border-radius: var(--r-sm, 6px); padding: 8px 15px;
    font-family: inherit; font-size: 12.5px; font-weight: 600; letter-spacing: 0.02em; cursor: pointer;
    transition: border-color .14s, color .14s, background .14s; }
  .nave-titlebar .ntb-btn:hover { border-color: var(--accent, #c39a56); color: var(--accent-bright, #e2c079); }
  .nave-titlebar .ntb-btn.ntb-primary { background: var(--accent, #c39a56); border-color: var(--accent, #c39a56);
    color: var(--accent-ink, #0b0906); font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; }
  .nave-titlebar .ntb-btn.ntb-primary:hover { background: var(--accent-bright, #e2c079);
    border-color: var(--accent-bright, #e2c079); color: var(--accent-ink, #0b0906); }
  @media (max-width: 640px) {
    .nave-titlebar .ntb-tag { display: none; }
    .nave-titlebar .ntb-bar { flex-wrap: wrap; row-gap: 10px; padding: 11px 16px; }
    .nave-titlebar .ntb-me, .nave-titlebar .ntb-signin { flex-wrap: wrap; }
  }
`

// signer.kind → display label (the mapping Nvoy's console set), and
// display label → badge colour class. Unknown labels pass through undecorated.
const KIND_LABEL = { nip07: 'extension', nip46: 'bunker', local: 'local key' }
const KIND_CLASS = { extension: 'ntb-kind-extension', bunker: 'ntb-kind-bunker', 'local key': 'ntb-kind-local' }

const truncNpub = (npub) => (npub.length > 21 ? npub.slice(0, 12) + '…' + npub.slice(-4) : npub)

function ensureStyle(doc) {
  if (doc.getElementById(STYLE_ID)) return    // the static block (or a prior render) already carries it
  const style = doc.createElement('style')
  style.id = STYLE_ID
  style.textContent = CSS
  doc.head.appendChild(style)
}

function h(doc, tag, attrs = {}, ...children) {
  const el = doc.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) if (v != null) el.setAttribute(k, v)
  for (const c of children) if (c != null) el.append(c)   // strings become text nodes: data stays escaped
  return el
}

function legacyCopy(doc, text) {
  try {
    const ta = doc.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.top = '-1000px'
    doc.body.appendChild(ta)
    ta.select()
    const ok = doc.execCommand('copy')
    ta.remove()
    return ok
  } catch { return false }
}

function selectContents(node) {
  try {
    const range = node.ownerDocument.createRange()
    range.selectNodeContents(node)
    const sel = node.ownerDocument.defaultView.getSelection()
    sel.removeAllRanges()
    sel.addRange(range)
  } catch { /* selection is a nicety */ }
}

async function copyNpub(pill, npub) {
  const doc = pill.ownerDocument
  let ok = false
  try { await navigator.clipboard.writeText(npub); ok = true } catch { /* fall through */ }
  if (!ok) ok = legacyCopy(doc, npub)
  if (ok) {
    pill.classList.add('ntb-copied')
    pill.textContent = 'copied'
    setTimeout(() => { pill.classList.remove('ntb-copied'); pill.textContent = truncNpub(npub) }, 1300)
  } else {
    // No clipboard at all: expand to the full npub, selected, for a manual copy.
    const expand = !pill.classList.contains('ntb-expanded')
    pill.classList.toggle('ntb-expanded', expand)
    pill.textContent = expand ? npub : truncNpub(npub)
    if (expand) selectContents(pill)
  }
}

export function renderTitlebar(el, opts = {}) {
  const root = typeof el === 'string' ? document.querySelector(el) : el
  if (!root) throw new Error('renderTitlebar: no such element')
  const doc = root.ownerDocument
  root.__naveTitlebarOpts = opts
  ensureStyle(doc)

  const { appName = '', tagline = '', sealSvg = '', npub = null, kind = null,
          onRefresh = null, onLogout = null, onSignIn = null, signInLabel = 'Sign in' } = opts

  root.classList.add('nave-titlebar')
  if (npub) root.setAttribute('data-signed-in', '')
  else root.removeAttribute('data-signed-in')
  root.textContent = ''

  const btn = (label, onClick, extra = '') => {
    const b = h(doc, 'button', { class: ('ntb-btn ' + extra).trim(), type: 'button' }, label)
    b.addEventListener('click', onClick)
    return b
  }

  const seal = h(doc, 'span', { class: 'ntb-seal', 'aria-hidden': 'true' })
  if (sealSvg) seal.innerHTML = sealSvg   // trusted app-authored literal (see header)

  // Note: no ids here — the static block (nave-titlebar.html) carries the
  // fleet ids (#me, #me-kind, #my-npub…) for by-id wiring; this renderer may
  // be instantiated more than once per page and wires by callback instead.
  const me = h(doc, 'div', { class: 'ntb-me' })
  if (npub) {
    const label = KIND_LABEL[kind] ?? (kind || 'local key')
    const badge = h(doc, 'span', {
      class: 'ntb-badge' + (KIND_CLASS[label] ? ' ' + KIND_CLASS[label] : ''),
      title: 'how this session signs',
    }, label)
    const pill = h(doc, 'code', {
      class: 'ntb-npub', title: 'click to copy',
      role: 'button', tabindex: '0', 'aria-label': 'copy your npub',
    }, truncNpub(npub))
    pill.addEventListener('click', () => copyNpub(pill, npub))
    pill.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copyNpub(pill, npub) }
    })
    me.append(badge, pill)
    if (onRefresh) me.append(btn('Refresh', onRefresh))
    if (onLogout) me.append(btn('Log out', onLogout))
  }

  const signin = h(doc, 'div', { class: 'ntb-signin' })
  if (!npub && onSignIn) signin.append(btn(signInLabel, onSignIn, 'ntb-primary'))

  root.append(h(doc, 'div', { class: 'ntb-bar' },
    seal,
    h(doc, 'h1', { class: 'ntb-name' }, appName),
    h(doc, 'div', { class: 'ntb-tag' }, tagline),
    h(doc, 'div', { class: 'ntb-spacer' }),
    me,
    signin,
  ))
  return root
}

// Shallow-merge `patch` into the opts of the last render and re-render.
// Pass `npub: null` to flip to the signed-out state.
export function updateTitlebar(el, patch = {}) {
  const root = typeof el === 'string' ? document.querySelector(el) : el
  if (!root) throw new Error('updateTitlebar: no such element')
  return renderTitlebar(root, { ...(root.__naveTitlebarOpts || {}), ...patch })
}
