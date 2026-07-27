# Promoting a policy generation

**A file edit cannot promote policy. This is deliberate, and it is enforced.**

`gitoversight-api` reads `policy_file` once at startup, then checks the loaded
snapshot against the active durable generation recorded in the database. A
mismatch is a hard startup failure:

```
install policy: configured policy does not match active durable generation
```

The check is on **content**, not on the generation number. Editing the file and
bumping `generation` fails; editing the file and keeping the same number fails
too. Only a policy that matches what was actually promoted will start.

That is the product refusing to let a file edit do what only an approved
operation may do — the same guarantee it offers for GitHub writes, applied to
its own configuration.

## The sanctioned path

`POST /v1/policy`, which requires a **human approver session**
(`HumanApproverFromContext`; without one the route answers
`human_authentication_required`). The request carries the expected generation
and policy hash, so a promotion that races another promotion is rejected rather
than silently overwriting it.

An agent prepares the proposed snapshot and validates it offline. A human
promotes it. There is no agent-only path, by design.

## Validate offline before proposing

Decode with the same decoder the API uses, then `Validate()`:

- `DisallowUnknownFields` is set, so a misspelled key is a hard failure rather
  than a silently ignored field.
- `Snapshot.Validate()` enforces the cross-field rules, including that
  `syncs_to` appears only on a private repository.

**Confirm the validator can fail before trusting it to pass.** Feed it a
deliberately broken snapshot both ways — `syncs_to` on a public repository, and
a misspelled key — and check it rejects each. A validator you have only watched
succeed is not evidence.

## If you edit the file anyway

Two things will bite, in this order:

**Ownership.** The live file is `root:gitoversight-api` mode `640`. The service
runs as `gitoversight-api` and reads it through the **group**. A `chown
root:root` leaves the mode looking correct and the file unreadable —
`policy: open /etc/gitoversight/policy.json: permission denied`, followed by a
restart loop. Read the current ownership before writing; do not assume it.

**The generation check.** Even with permissions correct, the content must match
what was promoted. Restoring the byte-exact previous file is what recovers the
service.

Recovery is `cp` the backup back, restore `root:gitoversight-api` `640`, and
restart. `docs/operations/rollback-runbook.md` covers the wider cases.
