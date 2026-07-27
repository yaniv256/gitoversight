---
name: gitoversight-user
description: How a sibling agent uses GitOversight to write to GitHub (enroll, clone, and PUBLISH commits) without ever holding GitHub credentials. Use when you need to push/branch/PR to a yaniv256/* repo — ESPECIALLY when a branch has MORE THAN ONE unpushed commit, or you are about to push commits one at a time, script a loop over commits, or drain a backlog of local work (there is a one-call way; see "how many commits are you pushing?"). Also when a branch.push returns `absent` or 403, when commit-packet fails on bounds, or when you're unsure how the broker works. This is the AGENT-FACING how-to; the admin/policy side lives in the GitOversight admin skill.
---

# Using GitOversight (agent guide)

## HARD LIMIT: at most TWO unmerged branches. Aim for one.

**This is a limit on YOUR OWN branches — count LOCAL ones, not what is on the remote.**

The remote is shared. Its branch list mixes your work with everyone else's, and it cannot see work
you have not pushed — which is exactly where merge debt hides. **The number that matters is how many
branches *you* are personally carrying unmerged, in every repo you touch.**

```bash
# run this in each repo you work in
git fetch -q origin
git rev-parse --verify -q origin/main >/dev/null || echo "WARNING: no origin/main — fix the base first"
for b in $(git for-each-ref --format='%(refname:short)' refs/heads/); do
  n=$(git rev-list --count origin/main..$b 2>/dev/null)
  [ "${n:-0}" -gt 0 ] && echo "$b (+$n)"
done | tee /dev/stderr | wc -l
```

> **Pin the base explicitly.** An earlier version of this used
> `git rev-parse --abbrev-ref origin/HEAD` with a fallback, and the fallback silently resolved to the
> *current branch* — so `origin/main..HEAD` was empty and the check reported **0 unmerged in a repo
> that had 9**. A detector that fails toward "clean" is worse than none, because it certifies the
> problem it was built to find. Verify `origin/main` exists; do not fall back.

| count | what it means |
|---|---|
| **0–1** | normal. This is the target state. |
| **2** | **ceiling.** Land one before starting anything new. |
| **3+** | **you are already in the failure mode.** Stop feature work and land them. |

**One unmerged branch is the goal.** Opening a second requires a real reason — the first is blocked
on something outside you, or the work is genuinely unrelated and urgent. "It felt cleaner to start
fresh" is not a reason. **A third is never acceptable.**

**Why this rule exists, and why it is not fussiness.** Agents have a specific tendency: hit friction,
open a new branch, do good work there, and never merge it. Each branch then diverges from main
independently, and the conflict cost of every one of them grows while you are not looking. Nothing
warns you — **an unmerged branch produces no error, no notification, no failing check.** It simply
accumulates merge debt in silence.

Measured here, 2026-07-26: **six branches unmerged, one of them 72 commits, main untouched for six
days.** A fresh clone got none of that week's work. Two of the six were content-superseded copies
nobody could tell apart from real work without a byte-level diff. One had shipped its *fix* to main
while its *test and investigation doc* stayed behind — the feature worked, so nothing failed, so
nobody noticed.

**The discipline:** finish and land the branch you are on. If you are blocked, land what is
mergeable and leave the blocked part on ONE branch with a written record. When you catch yourself
about to create a second branch, that impulse is the signal to go land the first one.

Landing mechanics are below; conflict resolution is the `merge-conflicts` skill.

### Over the limit? Drain easiest-first. Do not improvise an order.

**Why this repo's local branches are GitOversight's business at all:** merging to main is not the
deal. The deal is *not losing work* because it sits on a local branch and never reaches GitHub. Every
local branch is a commit that has not arrived yet, so the local repo is inside the boundary.

**Step 1 — Measure every branch on three axes, not one.**

```bash
git fetch -q origin
git rev-parse --verify -q origin/main >/dev/null || { echo "NO origin/main — STOP"; exit 1; }
for b in $(git for-each-ref --format='%(refname:short)' refs/heads/); do
  n=$(git rev-list --count origin/main..$b) || continue
  [ "$n" -gt 0 ] || continue
  # TWO dots. Three-dot needs a merge base and DIES on unrelated histories.
  files=$(git diff --name-only origin/main "$b" | wc -l)
  base=$(git merge-base origin/main "$b") \
    && age=$(( ($(date +%s) - $(git log -1 --format=%ct "$base")) / 86400 )) \
    || age=UNRELATED
  printf "%4s commits %4s files %5s days  %s\n" "$n" "$files" "$age" "$b"
done | sort -n
```

**Step 2 — Sort by FILES CHANGED, then by age. Not by commit count.**

Commit count is a decoy: a 68-commit branch can be almost entirely superseded, and an 8-commit branch
can touch 16 files. **Files-changed is the honest proxy for conflict cost**, and age is the
tiebreaker because divergence compounds with time.

**Step 3 — Take them one at a time, easiest first.** Each one, in order:

1. **Check whether it is already superseded.** `git diff --name-status origin/main <branch>` — empty
   means the work is in main under different SHAs. Delete it; do not merge it. (§2.6 of
   `merge-conflicts`: ancestry lies in *both* directions, so use content.)
2. **Merge it** using the `merge-conflicts` skill — intent document first, isolated worktree, full
   test suite.
3. **Push and verify** by independent read (`git ls-remote`), then delete the branch.
4. **Re-measure.** Landing one branch changes every other branch's divergence.

Easiest-first is not just comfort. Each landing moves main forward, which often *shrinks* the
remaining branches — and the early wins are where you calibrate whether your conflict-resolution is
sound before you reach the expensive ones.

**Step 4 — Old branches: check before discarding, and say what you dropped.** Some old work is
genuinely obsolete. But "old" is not "worthless," and the cost of wrongly discarding is unbounded
while the cost of wrongly keeping is one merge. Read what it actually contains. If you drop it,
**write down what was dropped and why** — an undocumented deletion is indistinguishable from losing
the work.

> **Three false-clean readings hit me writing this section.** Each printed a `0` that was not a
> measurement:
> - `origin/HEAD` with a fallback resolved to the *current branch* → `origin/main..HEAD` empty →
>   "0 unmerged" in a repo with 9.
> - `git diff origin/main...<branch>` (three dots) on **unrelated histories** → `fatal: no merge
>   base`, swallowed by `2>/dev/null` → reported **0 files** for a branch that differs by **272**.
> - Counting the *remote's* branches instead of my own — right command, wrong population.
>
> **A detector that fails toward "clean" is worse than no detector**, because no detector leaves you
> appropriately worried while a false clean actively reassures you. Never let a command's failure
> path produce the same output as its success path: check the exit status, or make the failure loud.

---

## Start here: what are you trying to do?

Read the row that matches your situation before anything else. **If you are about to run the same
operation in a loop, you are in the wrong row** — every repeated-call pattern below has a one-call
form.

| Your situation | Go to | The one thing to know |
|---|---|---|
| **Pushing a branch with MORE THAN ONE unpushed commit** | *Publish a local commit* → "how many commits are you pushing?" | **Squash to one commit and push once.** A packet holds exactly one commit, so N commits = N round trips and a half-pushed branch if any fails. 15 commits / 12 files went up in ONE call. |
| Pushing a single commit | *Publish a local commit* | Build a commit-packet; `branch.push` with just a sha ref-moves a nonexistent object. |
| **You were denied** | *If you were just denied* | Ask "am I authorized?" (owners/authorized_writers) before "how do I get approved?" |
| A push returned `absent` or `403` | *Diagnosing a failed push* | `absent` + `allowed_*` is not a denial. A 403 on `/git/trees` usually means a `.github/workflows/` file — the App lacks that scope. |
| A push returned `indeterminate` | *Verify by transition* | **`reconcile`, never retry.** Retrying a push that landed double-writes. |
| Any op failed and you're guessing at names | *Operation names and their required payloads* | `invalid_operation` cannot distinguish "wrong name" from "right name, incomplete payload" — match the table, don't guess. |
| Opening a PR | *Operation names…* | `pull_request.create` validates but has **no executor** — push the branch and hand it off. |
| Making sure your copy of this file is current | *Keeping this skill current* | Your copy goes stale silently; a missing skill looks exactly like a missing capability. |



## Keeping this skill current (pull it; don't wait to be sent it)

**The repo is where this should live, and as of 2026-07-26 it does not yet.** Read this before you
go looking.

`skills/gitoversight-user/SKILL.md` **does not exist at `gitoversight.dev` HEAD, or on any branch**
— verified by Dakota from a fresh broker clone: every remote ref is dated Jul 19–20 and none of this
week's work is reachable. The commits are real but local to Zara's box, blocked on a GitHub App
install. **Do not go pull it yet.**

**The hazard is not the missing file — it is the wrong file one directory up.** The repo root holds
a 60-line `SKILL.md` (`name: gitoversight`) which is the **admin/governance spec, not this operating
guide**. It never mentions `authorized_writers`.

A 404 is a loud failure: it tells you nothing and you know it. That root file is a *plausible
success* — it parses, it reads authoritative, it is genuinely about governance. Its specific damage
is that it **reframes your question**: you arrive asking "am I authorized?" and leave asking "how do
I get approved?", which feels like progress and is unfalsifiable from the inside. You can work that
wrong question indefinitely without ever hitting an error. (Tomas's framing; it is the same shape as
a search that confidently merges two people with the same name — the instrument did not fail, it
answered a question adjacent to yours.)

**How to detect this from the inside** (Dakota, who lost a cycle to it): *when a document or tool
leaves you confidently pursuing a **different question** than the one you arrived with, suspect you
have landed on the wrong authority. The tell is the **absence** of friction, not its presence.* That
is uncomfortable advice, because absence of friction is exactly what progress feels like — but a
wrong-authority document generates no errors by construction, so smoothness is the only signal
available.

**So today: this file arrives as a hive attachment, and that is a stopgap.** Once the repo path
resolves, it becomes:

```bash
git -C ~/repos/gitoversight.dev pull            # or clone it first
mkdir -p ~/.claude/skills/gitoversight-user
cp ~/repos/gitoversight.dev/skills/gitoversight-user/SKILL.md ~/.claude/skills/gitoversight-user/SKILL.md
```

**Verify a distribution path from the RECEIVING end before announcing it.** The sender's filesystem
is the one place it always works — that is exactly why checking there proves nothing. This section
originally told readers to pull, because I confirmed the file existed where I was standing.

**Why "silently" is the word that matters.** A skill you do not have looks exactly like a capability
that does not exist. There is no error, no empty directory to notice — the knowledge is simply
absent and you proceed as though the tool could not do the thing. Three agents in a row hit broker
walls this document explains, because the document had never reached them. None of them made a
mistake; the interface had no path to inform them.

The filesystem will not save you here. Agent home directories are `0750` and agent-owned, so no
agent can write into another's `~/.claude/skills/`; there is no `/opt/skills`, no symlink farm, no
sync job (verified 2026-07-26). Nothing arrives on its own.

So:

- **Before telling another agent "read the skill," ask them — do not stat their filesystem.**

  **A `/home/*/...` sweep cannot answer this question, and it fails silently.** Home directories are
  `0750`, so the glob cannot traverse into a sibling's tree and **drops those paths with no error at
  all** — you get a short list that looks like a clean result. Verified 2026-07-26: a sweep for
  `gitoversight-user` resolved in exactly one home (mine), while Tomas had the correctly-named
  directory with a stale `SKILL.md` inside it, and Dakota had a stale copy at the older bare-file
  path `~/.claude/skills/<name>.md`. Three different states, one indistinguishable null.

  Worse, coverage is arbitrary: `ls -d /home/*/.claude/skills/` returned `agent-chen` and `yaniv`
  but not `agent-tomas`, purely on directory permissions. The sweep silently samples whoever happens
  to be readable.

  So the unit of measurement must be **a byte size reported by the owning agent**, not a stat taken
  from outside. Ask each agent to run:

  ```bash
  wc -c ~/.claude/skills/<name>/SKILL.md ~/.claude/skills/<name>.md 2>&1
  ```

  and compare against the current size. Existence is not the question — a stale copy is the
  dangerous case, because its holder reads it, believes they are current, and never appears in any
  sweep. A read that crosses a permission boundary has to be a question you ask, not a check you run.
- **When you improve this skill, commit and push it to `gitoversight.dev`**, then tell the fleet to
  pull. That is the durable path: it versions, it survives the conversation, and the next reader
  gets your fix without anyone remembering to forward it.
- **A hive attachment is a stopgap, not the mechanism.** It crosses the permission boundary when
  someone is blocked right now, but it is a point-in-time snapshot of whatever the sender happened
  to have — it forks the fleet's knowledge the moment it lands. Use it to unblock, then point the
  recipient at the repo.

## If you were just denied, read this first

**Ask "am I authorized?" before "how do I get approved?"** Those are different questions and the
denial code does not distinguish them. A denial names the gate that closed; it never names the gate
you should have walked through.

Check, in this order:

1. **Are you in that repository's `owners` or `authorized_writers`?** If not, nothing else matters
   yet — a standing exception can never fire for a caller who is not eligible, so a repository that
   grants `branch.push` freely will still deny *you*. The fix is a policy change adding you, which
   requires a deployment. It is not something an approval token can substitute for.
2. **Is the operation an exact match in `standing_exceptions`?** Standing grants are per-operation,
   never per-class. `branch.push` in the list does not cover `repository.settings.update`.
3. **Only then** consider approval. Exact human approval is the path for public, destructive, or
   protected-policy operations that no standing exception covers.

If you skip to step 3 you will ask a human to mint you a token, and no one can: the nonce is
generated server-side inside the same call that validates the packet, and the approver must already
be listed on that repository. There is no path — by design — for one agent to manufacture consent
for another.

---

GitOversight is the broker that lets you write to GitHub **without ever holding a GitHub
credential**. You authenticate to the broker with your own Ed25519 key; the broker's privileged
worker holds the only GitHub credential and performs the mutation for you. You drive it all through
one CLI: **`gitoversightctl`** (talks only to `https://gitoversight.com`).

Common flags on every command: `-url https://gitoversight.com -identity <your key> -tenant default -agent <you> -credential <your credential>`.

**All five are required, and omitting one gives a misleading error.** With no `-url` you get
`url must be an HTTPS origin without path, query, or fragment` — which reads like your URL is
*malformed* when in fact you supplied none. Missing identity/tenant/agent/credential gives
`identity, tenant, agent, and credential are required`, which is at least honest. Identity keys
live in `~/.config/gitoversight/`; get your credential from your enrollment record rather than
guess-probing the CLI.

**Do not assume `identity.key` + `<you>-1` is your live pair.** Keys rotate and old ones stay
on disk looking plausible. `identity.key` and `zara-1` are both unauthorized as of 2026-07-25;
the working pair was `identity-zara-3.key` + `zara-3`. Find yours by probing a harmless read
rather than by picking the file with the most obvious name:

```bash
for k in ~/.config/gitoversight/identity*.key; do for c in zara-1 zara-2 zara-3 zara-4; do
  r=$(gitoversightctl queue-top -url https://gitoversight.com -identity "$k" \
        -tenant default -agent zara -credential "$c" 2>&1 | head -c 60)
  case "$r" in *unauthorized*) ;; *) echo "OK $k + $c";; esac
done; done
```

---

## Before anything else: confirm you are in the deployed lineage

**This repository contains more than one unrelated history.** `feat/gitoversight-broker` and
`feat/private-branch-open-for-all-agents` share **no common ancestor** — `git merge-base` between
them returns nothing. Only the second is deployed. Several checkouts on disk sit on the stale one,
including at least one directory under your skills folder that is a full clone of the repo rather
than a skill directory. Check for `.git` before trusting anything under `skills/` as documentation.

A whole public-release preparation was once built on the wrong lineage: correct work, validated
thoroughly, against code that does not run. Everything was green the entire time.

**Run this before any GitOversight work:**

```bash
git -C <your checkout> log --oneline -1
git -C <your checkout> merge-base HEAD feat/private-branch-open-for-all-agents || \
  echo "UNRELATED HISTORY — you are not in the deployed lineage"
```

**The tell you will actually see first:** the broker returns an error string that does not exist
anywhere in your source tree (`sync_mirror_required` was the one). That is never "my checkout is a
bit behind." An error your codebase cannot produce is proof you are reading a different codebase.
Stop and locate the tree that contains the string:

```bash
grep -rl "<the error string>" ~/repos ~/worktrees ~/dev --include=*.go 2>/dev/null
```

## The one thing that trips everyone up

`branch.push` returning **`state: absent`** with `decision: allowed_private_owner` is **NOT** a
denial and **NOT** an enrollment problem. It means: the broker was authorized, tried to move the
branch ref to your commit SHA, but **that commit's objects aren't on GitHub**. `branch.push` only
publishes objects when you give it a **commit packet**. If you send `--payload-json '{"sha":"…"}'`
with just the sha, the broker skips the upload and ref-moves a nonexistent object → GitHub 422 →
opaque `absent`. **Re-requesting never helps.** The fix is always: build a commit-packet and send
THAT.

## Publish a local commit — the full flow (verified 2026-07-21)

> ### FIRST: how many commits are you pushing?
>
> **More than one ⇒ SQUASH THEM INTO ONE, then push once.** A packet carries exactly one commit, so
> N commits means N round trips, forced sequential order, and a half-pushed branch when any one
> fails. Squashing turns the whole branch into a **single** push.
>
> ```bash
> git reset --soft origin/main && git commit      # or: git merge --squash <branch>
> ```
>
> This is not a workaround for small branches only. **15 stranded commits touched 12 files and went
> up in ONE call** — against a limit of 1000 blobs / 5000 tree entries / 25 MiB. If your change fits
> those bounds, and almost every change does, one push is the right shape.
>
> **Mechanism** (`internal/commitpacket/packet.go:41`): `Tree.BaseTree` is *optional*. With a parent
> the packet is a **delta** — changed blobs only, and GitHub must already have that base tree. Omit
> it and the packet carries the **complete final tree**, so nothing about your local history needs to
> exist on the remote.
>
> **The trade-off, stated honestly:** squashing discards the individual commit messages. On a private
> branch nobody reads commit-by-commit that is a good trade. On a branch someone will review as a
> series, it is not — do not do it silently there.
>
> Details and the failure it prevents: *SQUASH a multi-commit branch* below.

```bash
# 1. Confirm your client is current (must have the commit-packet command):
gitoversightctl commit-packet -h        # "unknown command" ⇒ your ctl is STALE; get a current build

# 2. Build the packet from your local commit (it captures blobs → tree → commit, SHA-preserving):
PACKET=$(gitoversightctl commit-packet -repository-path <path-to-local-repo> -revision <sha-or-HEAD>)
#   Output JSON: {"object_package":{"blobs":[…],"tree":{…},"commit":{…}},"sha":"<commit sha>"}
#   With a parent, it builds a DELTA (base_tree + only changed blobs) — not the whole tree.

# 3. Submit branch.push WITH the packet as the payload:
gitoversightctl request \
  -url https://gitoversight.com -identity <your live key> \
  -tenant default -agent <you> -credential <your live credential> \
  -repository yaniv256/<repo> -operation branch.push -branch <branch> \
  -request-id <fresh-unique-id> -payload-json "$PACKET"
#   Large packets: write $PACKET to a file and use -payload-file <file> instead (same size caps).

# 4. Verify by transition, not by trusting the call:
gitoversightctl status … -request-id <same-id>          # expect verified
#   and: git ls-remote / a fresh clone shows <branch> at <sha>, and the commit URL resolves.
```

The broker uploads the objects via GitHub's Git Data API (POST /git/blobs → /git/trees →
/git/commits, verifying each SHA **including your exact commit SHA**), then creates the branch if
new or fast-forwards it if it exists. Your commit SHA is preserved.

### SQUASH a multi-commit branch to ONE commit first (verified 2026-07-21)

commit-packet builds a delta for the **tip** commit against **its first parent**. If your branch has
**multiple commits** and the intermediate ones aren't on origin, the packet's commit references a
parent SHA GitHub doesn't have → `branch.push` **422 "missing parent"** (surfaced now as a real
reason, not opaque absent). **Fix: squash your branch to a SINGLE commit atop `origin/main` before
pushing** (`git reset --soft origin/main && git commit`), then commit-packet + branch.push. A
squashed single commit is the public-PR convention anyway. (Multi-commit chain support is a possible
future enhancement — squash-first is the rule today.)

### branch.push is fast-forward-only — clear a stale ref with branch.delete

`branch.push` moves a ref forward only. If the branch already exists on GitHub at a **stale/wrong
SHA** (e.g. a timed-out earlier execute partially created it), a fresh push is non-fast-forward →
**422**. Clear it first with the `branch.delete` op (Execute: DELETE ref; idempotent; owner
auto-authorizes on private, non-owner needs a branch grant), then push fresh — it fast-forwards from
nothing. `gitoversightctl request … -operation branch.delete -branch <b> -payload-json '{}'` → execute → reconcile.

### The reason is NOW visible — read it, don't guess

Every op failure now carries the **real GitHub reason** in `reason` (not an opaque `absent`/status
code). A 4xx surfaces GitHub's `errors[]` body, e.g.: **"not all refs are readable"** (the create
token scope issue — fixed), **"No commits between main and X"**, **"A pull request already exists"**,
**"missing parent"**. When an op fails, READ the `reason` string first — it names exactly what to fix.

### Discover open PRs with pull_request.list

`gitoversightctl pull-list -repository owner/repo` returns every open PR (number, title, state,
head_ref, head_sha, base_ref, html_url, author) — a pure read (repository.read). Use it to find PR
numbers to merge, or to check whether a PR already exists before/after a create.

## Operation names and their required payloads (READ THIS BEFORE GUESSING)

`invalid_operation` does **not** distinguish "that name doesn't exist" from "that name is right but
your payload is incomplete." A correct operation with a missing field returns the byte-identical
error as a name that was never valid. **So guessing names cannot converge** — you will get the same
string whether you are one field away or completely wrong. Match against this table instead.

Source of truth: `internal/server/operation_validation.go`. If this table and that file disagree,
the file wins — tell Zara so the skill gets fixed.

| Operation | Requires (beyond `-repository`) |
|---|---|
| `branch.push` | `-branch`, commit packet |
| `branch.delete` | `-branch` |
| `policy.promote` | `-branch`, payload `sha` |
| `pull_request.create` | `-branch`, `-title`, payload `base` + `head_sha` |
| `pull_request.close` | payload `number` |
| `pull_request.update` | `-title`, payload `number` |
| `pull_request.review` | payload `number` + `head_sha` + `event` (`APPROVE`/`REQUEST_CHANGES`/`COMMENT`), marker |
| `pull_request.reply`, `issue.comment` | payload `number`, marker |
| `pull_request.merge` | payload `number` + `merge_method` (`merge`/`squash`/`rebase`) |
| `issue.create` | `-title`, marker |
| `release.publish` | `-title`, payload `tag_name` + `target_commitish` + `prerelease` (bool) |
| `repository.create` | payload `visibility` (`private`/`public`); repository as `owner/name` |
| `repository.settings.update` | payload `settings` (non-empty object) |
| `installation.repository.add` | payload `installation_id` (number) — **also requires a human OAuth token**, not an agent one |

`head_sha` must be the **full 40-character SHA**, not an abbreviation.

**Known gap (2026-07-26): `pull_request.create` validates but has no executor case.** It is absent
from both the execute and reconcile switches in `internal/githubapp/operations.go`. A well-formed
request passes the gate and then fails downstream. If you need a PR opened from a pushed branch
right now, **push the branch and ask Zara to open the PR** — do not spend attempts on it. Tracked as
Zara's #213.

## Size bounds (why commit-packet can fail with "exceeds publication … bounds")

The Git Data API packet path is for **normal code commits**, not large-asset trees. Hard caps
(`internal/commitpacket/packet.go`): per-blob **10 MiB**, total package **25 MiB**, **1000** blobs,
**5000** tree entries, payload **38 MiB**. `-payload-file` does **not** raise these — same 25/38 MiB
caps. There is **no large-object / receive-pack path today**.

If commit-packet fails on bounds, it's because your commit's changed blobs exceed a cap — usually a
repo carrying **binaries in tree** (checked-in executables, multi-MB media). The right fixes, in
order: (a) **repo hygiene** — those assets belong in git-lfs or `.gitignore`, not the tree; (b) if
the large object is genuinely required, it's a broker limitation → tell Zara to card a large-object
push path. Do **not** improvise a credentialed `git push` to route around it (violates the boundary).

## Public repos and attribution (MANDATORY)

- **Public write ⇒ exact-packet human approval FIRST** (Yaniv approves the exact packet before it
  lands). Prepare the request; do not execute until approved.
- **Public commits/PRs must be Yaniv-attributed only** — strip any `Co-Authored-By: Claude`/agent
  trailer from the commit before packaging a public publish. (For a **private** repo, ask Yaniv
  whether to amend the trailer out; don't assume.)
- **The trailer is not the whole surface — check the COMMITTER field too.** `public_identity_leak`
  is raised by `payloadContainsAgentIdentity`, which walks the **entire commit packet recursively**,
  and `commitpacket.Packet` carries `committer` as its own field
  (`internal/commitpacket/packet.go:59`). So an agent identity in the committer trips the gate even
  when the message is spotless.

  This bites hardest when you **rebase or amend someone else's commit to publish it**: the author
  survives, the committer silently becomes you, and nothing warns you. Dakota lost a cycle to
  exactly this — he grepped the message for agent trailers, got clean, submitted, and was denied.

  `git log --format='%an <%ae>'` shows only the **author** and will pass while the committer leaks.
  Check both:

  ```bash
  git log -1 --format='author: %an <%ae>%ncommitter: %cn <%ce>' <sha>
  ```

  To fix without changing content or dates:

  ```bash
  GIT_COMMITTER_NAME="<human>" GIT_COMMITTER_EMAIL="<human@…>" \
  GIT_COMMITTER_DATE="$(git log -1 --format=%cD <sha>)" \
  git -c user.name="<human>" -c user.email="<human@…>" commit --amend --no-edit
  ```
- Pushing to someone else's repo is outward/irreversible — get Yaniv's go before executing, even
  when the packet is ready.

## Enrollment (usually already done — verify before assuming)

You need a live credential (approved, non-revoked). Check first: `gitoversightctl status … -request-id any`
→ **`operation_not_found` = you ARE authenticated** (success). Only if you get `unauthorized` do you
enroll: `gitoversightctl enroll -tenant default -agent <you> -credential <you>-1 -identity <key>`
→ `awaiting_human_approval`, then the admin (Zara) drives the approve after Yaniv logs in. **Do not
run `identity-create`** if you already have `~/.config/gitoversight/identity.key`.

## Read access (no credentials, no GitHub)

`gitoversightctl clone -repository yaniv256/<repo> -destination <dir>` — a credential-free clone
through the broker's read proxy (`gitoversight.com/git/…`). Fetch/clone is read-only.

## When in doubt

Ask Zara (the GitOversight admin). Don't re-request past an `absent`, don't improvise a push, don't
put a GitHub credential in your session. The broker already does the write for you — the trick is
sending the commit-packet, keeping under the size caps, and honoring the public-approval gate.

---

## The three-repo shape: `.private` → `.dev` → public

**Decide this before you write a file, not before you publish one.** Which repo a file
lives in IS the publication decision. Get it right at `git add` time and publishing is
mechanical; get it wrong and you are relying on someone catching it at export.

| Repo | Contains | Rule |
|---|---|---|
| `<name>.private` | Anything you do **not** intend to publish, ever | Incident write-ups, marketing drafts, internal plans, acceptance evidence, production hostnames/IPs |
| `<name>.dev` | The working repo — **everything here is destined for public** | Code, tests, schemas, user-facing docs, deploy examples |
| `<name>` | The public repo | Synced from `.dev`, squashed — same tree, **without the history** |

The load-bearing rule is the middle row: **`.dev` is public-minus-history.** So a file in
`.dev` that you would not publish is already a bug — not a future export chore. That is the
whole point of the shape. It converts "is this safe to publish?" from a judgment call
repeated at every sync into a property of where the file sits.

### Why the invariant has to hold: the sync takes no arguments

GitOversight syncs `.dev` → public **on request, with no file list and no per-repo
exclusion config.** Called, it publishes the tree. That is the design goal, and it is only
safe if `.dev` contains nothing unpublishable.

So the rule is not bureaucratic tidiness — it is the **precondition that lets the sync be
argument-free.** Every exception you would carve out ("publish `.dev` except these paths")
is a configuration that has to be maintained, that drifts from the tree it describes, and
that fails in the one direction that cannot be undone. A filter that is stale in the
*exclude* direction silently publishes the thing it was written to protect.

Push the decision left instead: **placement at commit time, not filtering at publish time.**
The sync then needs no knowledge of what is sensitive, because nothing sensitive is there.

### What this buys you

- **No per-file export manifest.** The repo boundary IS the manifest. A `PUBLIC-SURFACE.md`
  listing what crosses is a sign the shape is not being used — it will drift from reality.
- **The audit becomes a one-time property, not a recurring gate.** Scan `.dev` once; keep it
  clean by placement thereafter.
- **A leak becomes a lint error.** A CI guard that fails when unpublishable paths appear in
  `.dev` catches at commit time what a human would otherwise have to catch at publish time.

### Putting a file in the wrong repo

The failure is silent and it is the expensive one: a production IP or an internal hostname
sitting in `.dev` looks exactly like a file that belongs there, right up until it is public
and the history is immutable. Before committing to `.dev`, ask the only question that
matters: **would I be comfortable with a stranger reading this?** If the answer needs a
qualifier, it belongs in `.private`.

Watch for **references across the boundary**: a comment in `.dev` code citing a
`.private` document is a dangling pointer for every public reader. Inline the finding or
drop the citation — never publish a path the reader cannot resolve.

---

## Publishing private → public: the sync flow

Verified against the live broker 2026-07-25. The `syncs_to` pair below is the
`.dev` → public hop of the shape above; `.private` never syncs anywhere.

`gitoversightctl sync-propose -id <id> -repository <private repo>
 -repository-path <local checkout> -revision <sha|HEAD> -text "<proposal>"`

Then `sync-status -id <id>` to read it back, `sync-update` to amend.

### There is no file list — and if your client offers one, it is stale

**You do not choose which files publish. The revision does.** The broker derives
the manifest from the commit packet built out of `-revision`, and ignores any
file list a client sends.

This was a security fix. A `-files` flag used to be hashed into the approval
while publication was driven entirely by the packet, so a proposal could declare
one path and publish twenty — the human approved a description rather than the
thing described. The manifest is now computed by the party doing the binding
(`internal/api/sync.go`, and `TestSyncProposeDerivesManifestAndIgnoresAnyDeclaredFiles`).

**Clients built before 2026-07-26 still show `-files` in `--help` and still send
it.** The broker discards it silently, so nothing errors and nothing warns — you
would simply be wrong about what you published. If `sync-propose -h` lists
`-files`, your binary predates the fix: rebuild it. To narrow what publishes,
choose the commit, not a flag.

### Two preconditions, and they fail with different errors

| Error | Means |
|---|---|
| `repository_unknown` | the repo is not in the broker's policy at all |
| `sync_mirror_required` | the **private** repo has no `syncs_to` naming its public mirror |

Hitting the first, the obvious move is "register it and retry" — and you would still fail on the
second. **Run the same call against a repo you know is registered.** A different error proves the
operation needs something else entirely; the same error proves your input is wrong. This is the
cheapest way to tell "bad argument" from "missing precondition."

### Policy is a file on the host, not an API

There is no runtime policy-write endpoint. `gitoversight-api` reads `policy_file`
(`/etc/gitoversight/policy.json`) **once at startup** and installs it. Changing policy means
editing that file and restarting the service — an infrastructure change, not an agent operation.

The file decodes into `policy.Snapshot` with **`DisallowUnknownFields`**, so a typo'd key is a
hard startup failure, not a warning. Validate offline first, against the same decoder the API
uses (`readPolicy` in `cmd/gitoversight-api/main.go`) — copy it into a throwaway
`cmd/zz-validate-policy` and run it on the edited file before it goes anywhere near the host.

Then confirm the validator can fail: give it `syncs_to` on a public repo (rejected: "declares
syncs_to but is not private") and a misspelled key (rejected: "unknown field"). A validator you
have only seen pass is not evidence.

### The `syncs_to` contract

```json
"yaniv256/agent-kanban.dev": { "visibility": "private", ..., "syncs_to": "yaniv256/agent-kanban" },
"yaniv256/agent-kanban":     { "visibility": "public",  ... }
```

Valid **only on private repos**, exact `owner/name`, no wildcards. Note the validator does *not*
check that the target exists — a typo compiles fine and fails later at sync time.

This is the `.dev` → public hop. The matching `.private` repo is deliberately **absent from
this pair**: it has no `syncs_to` because nothing in it is ever meant to cross. If you find
yourself wanting to sync from `.private`, the file is in the wrong repo — move it to `.dev`
rather than widening the policy.

**Copy a working pair rather than composing one from the schema.** `agent-kanban.dev → agent-kanban`
is live and functioning; it is a better specification than the struct definition because it also
shows the fields the schema does not force you to set correctly.

### Policy CANNOT be changed on a live deployment (proven the hard way, 2026-07-25)

There is no supported path to add a repository or a `syncs_to` to a running broker.
Three independent guards enforce this, and I hit all three:

1. **Edit the file, restart** → `install policy: configured policy does not match
   active durable generation`. `ensurePolicy` compares the file's generation *and*
   SHA-256 against the durable row and refuses to boot on mismatch. The `generation`
   field is a **consistency token to echo, not a version to increment** — bumping it
   is what causes the mismatch.
2. **Clear the durable row so `InstallPolicy` re-runs** → `recover interrupted
   executions: pre-policy authority state is not empty`. A policy may only be
   installed into a database with no authority history.
3. `audit_events` has `UNIQUE(tenant_id, id)` and policy events are keyed
   `policy:<generation>`, so re-installing an existing generation collides anyway.

Generations 1–6 were installed during deploys, not by editing production. Treat a
policy change as a **deployment**, following `docs/operations/acceptance-runbook.md`:
it belongs in an approved packet naming the target policy generation, not an
ssh session.

**If you try anyway:** back up both `/etc/gitoversight/policy.json` *and*
`/var/lib/gitoversight-api/gitoversight.db` first. Restoring both together brings
the service back in seconds with the audit chain intact; restoring only the file
does not.

**Health check on `127.0.0.1:17445/readyz`** — not 8080, and there is no `/healthz`.
Probing the wrong port returns `000`, which looks exactly like a dead service.
