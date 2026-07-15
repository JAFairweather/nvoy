# Nvoy — where the primitive grows

Two directions the delegation primitive wants to grow, recorded so we build
toward them deliberately. Both are cross-cutting with [Nact](https://github.com/JAFairweather/nact)
(the action-out half of scoped autonomy); its `DESIGN.md` holds the fuller
treatment.

## Credentials, not just data

Nvoy delegates *data* today. The same wire — an encrypted scope, a grant to the
agent's keypair, live dereference, revocation-by-key-rotation — can just as well
carry a **credential**: an OAuth token, an API key, a session.

A **broker** authenticates to the upstream provider, obtains the token, and
delegates it to the agent *as an Nvoy grant*:

- **End-to-end to the agent** — the broker's server holds the credential no
  longer than it takes to hand it over; it never lands in a shared store.
- **Live** — the broker refreshes the token in place; the agent always
  dereferences the current one, never a stale copy pasted into a prompt.
- **Severable** — rotate the scope key and the agent's *use* of the credential
  dies instantly. That's delegatee-level revocation OAuth itself doesn't give
  you: you can't un-issue a bearer token an agent already copied, but you can
  make an Nvoy-delivered one stop decrypting.
- **Scoped** — the grant carries exactly the one credential a flow needs.

Net effect: an agent gets *use* of a credential for a bounded flow without that
credential entering its long-term storage, its logs, or its model context.
Because a credential is higher-value than ordinary data, this pairs naturally
with a **Nact** approval tap (a human enacts the granting of a credential) and
short TTLs.

## Requests that are grants *and* enacts

Today grants flow delegator → agent (perceive). But an agent can **initiate** a
scoped-data request from a *named provider*, and that single request is two
things at once:

1. a **scoped grant** — the agent grants the provider scoped, revocable access
   to the request itself (the query, the context needed to fulfill it), and
2. an **enact request** — it asks the provider to *act*: assemble the data,
   decide whether to approve, and return it.

The provider, on approval, returns the result as **another scope** — a grant
back to the agent. So Nvoy and Nact turn out to be one primitive seen from two
sides: *a data request is an action*, and *fulfilling it produces a grant*. The
provider's approval is exactly a Nact **enact**; because the reply is a scope,
the provider keeps revocation power over what it returned.

This makes **providers first-class** — named, discoverable over NIP-05,
publishing which scopes they fulfill and on what terms — and lets requests
**chain**, with revocation propagating along the chain.

See [nact/DESIGN.md → "Two directions the primitive wants to grow"](https://github.com/JAFairweather/nact/blob/main/DESIGN.md).
