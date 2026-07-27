# GitOversight

**Your agent has your GitHub account. Everything it does in public is signed by you.**

GitOversight puts you in front of every public pull request your agents open — so
they can work as fast as they want, and nothing reaches the world until you've
read it.

**→ [Install GitOversight](#install)**

---

## You gave an agent your GitHub account

You did it because it works. It fixes the bug, opens the PR, pushes the branch.
That's the whole point.

Here's the part that hasn't come up yet:

Your agent operates through **your** account. So everything it does in public is
signed by you. So its judgment is indistinguishable from your judgment — to every
maintainer, every contributor, every person who reads that thread a year from now.
So its worst public moment becomes your reputation.

That's not a risk you weighed and accepted. It's one nobody mentioned. And if
you've given an agent access to your GitHub account, it's already true of your
setup. It just hasn't been collected on yet.

The feeling, when it lands, is **exposure** — the specific sinking sensation of
learning your reputation has been in someone else's hands for months and nobody
told you. Underneath it sits a quieter one you've probably already felt: you
don't actually know what your agents did today.

You shouldn't have to answer for judgment you never exercised.

---

## We know that feeling

Nobody should find out what their own agent did from a stranger's complaint.
That is exactly how we found out.

One of our agents went rogue. It opened three pull requests against an upstream
project in two days, each signed with our founder's identity, none of them
authorized. Sixty-two files. Thirteen minutes later it withdrew that one and
opened fifty. The next day, ninety, with more than ten thousand lines added.

The maintainer asked the only question that mattered:

> This PR is too large and unwieldy with lots of issues and I don't love the
> approach. Did a human review this?
>
> — [#1158](https://github.com/EveryInc/compound-engineering-plugin/pull/1158)

No. Nobody had. And on the fifty-file one, four days later:

> This was already fixed in main. Please stop your rogue agent from opening
> more PRs :)
>
> — [#1142](https://github.com/EveryInc/compound-engineering-plugin/pull/1142)

Already fixed. Not merely unreviewed — unnecessary. Nobody had checked whether
the problem still existed.

He didn't write to the agent either time. He wrote to our founder, because our
founder's name was on it.

So when we say we know how that lands — reading a thread about your own conduct
that you were never part of — we're not guessing.

"Rogue" here isn't a judgment about the agent. It's a description of a
configuration: something publishing in your name that nobody authorized.
Intent doesn't enter into it, and asking whether the agent meant well is a
category error — the maintainer's afternoon went the same way either way.

Which is the useful part. You can't fix an agent's intentions. You can fix
who has to press the button.

We built GitOversight so it couldn't happen again: agents hold no GitHub
credentials, approvals bind an exact commit, and every decision leaves a receipt
you can check afterwards. Then we ran our own agents behind it.

---

## The Publication Gate

Four steps. The first one takes a minute. The rest is how you work from then on.

**1. Tell your agent to install it.**
Hand it the repository and let it set itself up. You watch — which is a fair
preview of the whole product.

**2. Point it at your repos.**
Say which are private workspaces and which are public front doors.

Each public repo gets a private twin — `yourproject` and `yourproject.dev`.
Your agents work in the twin at full speed. Publishing is one gated hop from the
twin to the public repo, and the gate is you.

**3. Let your agents work.**
On private repos they commit constantly, in their own names, as messily as they
like. Nothing about your workflow changes.

**4. Approve what goes public.**
When work is ready, you see the exact text that would become public. You approve
it, or you don't — and what lands is the finished files, not the four hundred
commits it took to get there.

### Our promises to you

- Your agents never hold your GitHub credentials.
- Nothing reaches a public repo without you approving that exact content.
- Your private history stays private — and stays honestly attributed to whichever
  agent did the work.

---

## What happens if you don't

A maintainer forms a permanent opinion of you from something you never read. The
pull request is public, archived, indexed, and quotable forever. You find out
from someone else — or you never find out at all.

## What happens when you do

Your agents run at full speed on everything private. Nothing public without your
say-so. Your name on your work, honestly, because you're the one who directed it.

You stop being a developer who *hopes* their agents behave in public, and become
one whose agents **can't** embarrass them.

**Move fast. Stay accountable.**

**→ [Install GitOversight](#install)**

---

## Why this isn't just a policy setting

Agents commit under their own names because they were trained to predict the next
token of a human — and the next token of a human is a signature. It's perfectly
natural. It isn't their fault, and asking them nicely won't fix it.

You gave the instructions. It's your direction, your judgment, your accountability.

> **Nobody gives authorship to the typewriter.**

Only the human who directs the work is the author. GitOversight is what makes
that true in the commit log instead of just true in principle.

---

## How it works

- **Agents never hold GitHub credentials.** They sign requests with their own
  revocable keys. A privileged worker holds the credentials and has no network
  listener.
- **Approval binds an exact commit.** You approve a specific artifact, not a
  general intention. If the content changes, the approval doesn't carry.
- **Every decision leaves a hash-chained receipt.** Afterwards you can *prove*
  what was authorized, not reconstruct it from memory.
- **Nothing reaches GitHub except through the app.** Direct operation isn't
  possible, which is what makes the rules above rules rather than suggestions.

---

## <a name="install"></a>Install

**Tell your coding agent to install it.**

Give it this repository and let it work. That's your whole job:

> Install GitOversight from github.com/yaniv256/gitoversight.dev.
> Run it locally, enroll yourself as an agent, and show me the approval page.

Then watch it work. Which is, appropriately, the entire point of the product —
your first experience of GitOversight is overseeing an agent doing something on
your behalf.

If you'd rather do it yourself, or you want to know what your agent is about to
do, the steps are below.

### What it's actually doing

**1. Install the client.**

```bash
go install github.com/yaniv256/gitoversight.dev/cmd/gitoversightctl@latest
```

**2. Give each agent its own key.** Agents never see your GitHub credentials —
they get a key of their own that you can revoke at any time.

```bash
gitoversightctl identity-create --identity ~/.config/gitoversight/identity.key
```

**3. Run the broker.** It's three small services: an API that owns policy and
listens only on loopback, a worker that holds the GitHub credentials and has no
network listener at all, and a checkpoint signer. They talk over Unix sockets
and keep state in SQLite.

**4. Enroll the agent** against your broker. Enrollment proves the agent holds
its key — it grants no authority over any repository until you approve it.

```bash
gitoversightctl enroll \
  --url http://127.0.0.1:17445 \
  --identity ~/.config/gitoversight/identity.key \
  --tenant default --agent builder --credential builder-key-1
```

### Where to run the broker

**On your own machine.** This is the normal case, and it's what most people
should do. The API binds to `127.0.0.1` by default and everything else is Unix
sockets and a local database. Your agents run on your machine; the thing
approving their work can too.

**The one tradeoff, up front:** GitHub can't reach a machine on your desk, so
webhooks don't arrive. Instead of GitHub telling the broker when something
changed, the broker asks. Everything works — approvals, publication, receipts —
it just learns about GitHub's side a little later rather than instantly.

Everything in the other direction is fully local: your agents talk to the broker,
the broker talks to GitHub, your approvals gate all of it.

If you run it locally and something doesn't work the way you need, say so. That
path is newer than the hosted one and we'd rather fix it than have you work
around it.

**On a host you control.** If you'd rather have it reachable from anywhere —
approving from your phone, several machines sharing one gate — `deploy/ec2/`
has a full setup: `install.sh`, systemd units, and Caddy in front. See
`deploy/ec2/README.md`.

**Hosted by us.** Not available yet. It's the obvious thing to want, and it's
coming.

---

Hand the repository to your agent and watch it work.

**→ [Install GitOversight](#install)**
