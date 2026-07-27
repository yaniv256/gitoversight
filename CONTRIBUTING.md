# Contributing

Thanks for looking. A few things worth knowing before you open a pull request —
some of them are unusual, and all of them are here because of something that
actually happened.

## Yes, your agent can write the code

That's the entire premise of this project. We are not going to ask you to
hand-write patches to a tool built for people who don't.

Use your agent freely. Let it iterate as much as it wants.

## But a human reads it before it becomes a pull request

This is the one rule we'd ask you to hold to, and it's the rule GitOversight
exists to enforce:

**Do not let an agent open a pull request here without a human reading it
first.**

Not because agents write bad code. Because an unread pull request is a request
for *someone else's* attention, and the person on the other end can't tell
whether you looked. A maintainer who receives fifty files nobody reviewed has to
review fifty files nobody reviewed.

We know how that lands. It's why this project exists.

## What a good pull request looks like

- **Small enough to review.** If it's large, say why in the description.
- **You can explain every change.** If your agent did something you can't
  account for, that's a signal to look again, not a reason to ship it.
- **Tests for behaviour you changed.** For a bug fix, a test that fails before
  and passes after.
- **A description written for the reader** — what changes, why, what you're
  unsure about.

"I'm not sure about this part" is welcome. Pretending to be sure is not.

## Attribution

Commits should carry the name of the **human who directed the work**, not the
agent that typed it. You gave the instructions; it's your direction and your
accountability.

Nobody gives authorship to the typewriter.

If you want to note that an agent did the drafting, mention it in the pull
request description. That's genuinely interesting. It just isn't authorship.

## Before you push

```bash
go build ./...
go test -count=1 ./...
go vet ./...
```

Use `-count=1`. Go caches test results, and a cached pass looks exactly like a
real one — you can "run" a test that never executed.

**These checks are not yet automated, so running them locally is the only run
they get.** The workflow that would run them lives at
`ci/workflow-ci.yml.pending` rather than `.github/workflows/ci.yml`: the
GitOversight App that publishes this repository does not hold GitHub's
`workflows` permission, so it cannot write that path. See `ci/README.md` for how
to install it if you have a credential that can.

## Reporting bugs

Open an issue with what you did, what you expected, and what happened. Version
and platform help.

**Security problems go through the private path instead** — see
[SECURITY.md](SECURITY.md). Please don't put a vulnerability in a public issue.

## Questions and design discussion

Open an issue before writing code if you're planning something substantial. A
short conversation up front beats a large pull request that goes in a direction
we can't merge — that's a bad outcome for you more than for us.
