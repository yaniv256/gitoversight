# GitOversight Admin: How to enroll an agent

For an agent **entrusted as the GitOversight admin**. Enrollment binds an agent's Ed25519 public
key to a credential id under a tenant. It is a two-party flow — the agent proves key possession, a
human authorizes — and the admin agent may **drive every mechanical step itself** once the human has
logged in. Do not tell the human "only you can do this"; the human's *login* is the authorization,
the *approve POST* is the admin's to drive.

## The credential model (why two halves)
- **Agent side** (challenge + prove): authenticated by the agent's **Ed25519 request credential**
  (`-identity <key>`). Reaches `/v1/enrollments/challenge`. Only the key holder can begin/prove an
  enrollment for that agent.
- **Human side** (approve): authenticated by a **`gitoversight_session` cookie** obtained through the
  GitHub-App login route. Reaches `/v1/enrollments/<id>/approve`. `approve` **requires** a
  `HumanApprover` in context and returns `403 human_session_rejected` without it. The approver of
  record is the logged-in human (e.g. `approved_by: "yaniv"`).

An agent Ed25519 key **cannot** mint the human session, and the human session **cannot** begin an
enrollment — the two credentials are deliberately separate. `middleware.go` collapses several
distinct auth failures into one opaque `unauthorized`; likewise enrollment errors collapse into
`enrollment_rejected`. Treat both as "your PARAMETERS may be wrong", not "the broker is broken".

## The tenant id
Production tenant is **`default`** (see `config/api.example.json` `"tenant_id"`). A wrong tenant
(`heycode`, `tenant-a`, `production`, …) returns opaque `enrollment_rejected` — a wrong-parameter
null experiment, not a real failure. If challenge is rejected, **try tenant `default` before
concluding anything.**

## Procedure (verified live 2026-07-21)

### 1. Agent side — begin + prove (CLI, the agent's own key)
```bash
gitoversightctl enroll \
  -url https://gitoversight.com \
  -identity ~/.config/gitoversight/identity-<agent>-<n>.key \
  -tenant default -agent <agent> -credential <credential-id>
# → {"enrollment_id":"<id>","state":"awaiting_human_approval"}
```
A repeat challenge for the same credential now returns `enrollment_rejected` — that means the
pending enrollment is **holding the slot**, i.e. it is live. Not a failure.

Each agent's private key lives in **its own** session/machine (`~/.config/gitoversight/`), so
challenge+prove for a different agent must run from that agent's session — the admin cannot hold
another agent's key.

### 2. Human login — establish the session in a drivable tab
Open, in a browser context the admin agent can script (e.g. an actions.json claimed tab):
```
https://gitoversight.com/login/github?human_id=<human>       # e.g. human_id=yaniv
```
The `human_id` must be an allowlisted approver or the login 403s (`human_login_rejected`). If the
human's GitHub-App grant is cached, this round-trips straight to
`/oauth/github/callback?...` and renders **"GitHub authorization complete."** — the
`gitoversight_session` (HttpOnly) and `gitoversight_csrf` cookies are now set in that tab's profile.

### 3. Admin drives the approve — POST WITH THE CSRF HEADER
From the SAME authenticated tab (same-origin, credentials included):
```js
const csrf = document.cookie.match(/gitoversight_csrf=([^;]+)/)[1];
await fetch(`/v1/enrollments/${enrollmentId}/approve`, {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
  body: JSON.stringify({ tenant_id: 'default' })
});
// → 201 {"agent_id":"...","approved_by":"<human>","credential_id":"...","tenant_id":"default"}
```
**The `X-CSRF-Token: <gitoversight_csrf>` header is mandatory.** Without it the POST returns
`403 human_session_rejected` even with a valid session — this is a CSRF double-submit guard, not a
session failure. (The CSRF cookie was renamed `gitoversight_csrf` (renamed from the pre-rebrand name) in the
gitoversight → gitoversight rename; read the actual cookie, don't assume the name.)

### 4. Verify by transition (red → green)
After approve, with the agent's key:
```bash
gitoversightctl status … -credential <credential-id> -request-id <any>
```
- Before enrollment: `unauthorized`.
- After approval: `operation_not_found` — **this is success** (authenticated; just no such request).
- `enroll` for that credential now returns `enrollment_rejected` because it is an **active**
  credential, not re-enrollable. Both confirm the credential is live.

## Do-not
- Do not place GitHub credentials in an agent session; the worker alone holds them.
- Do not weaken policy, switch identity, use a broader token, or ask a *different* agent to perform
  a write to route around a denial (`SKILL.md` non-negotiable boundary).
- Do not escalate "the human must do it" before exhausting the mechanical retry — a missing CSRF
  header, a wrong tenant, or a not-yet-completed login all *look* like "needs the human" and are not.
