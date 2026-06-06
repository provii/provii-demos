# Git Hooks

Tracked pre-commit (and later pre-push) hooks. Wired via `core.hooksPath`
so they travel with the branch and are auditable in the repo tree.

## Install

Run once per clone or worktree, from the worktree root:

```sh
git config core.hooksPath .githooks
```

The `scripts/bootstrap-hooks.sh` helper does the same thing and is safe
to re-run. The `hooks-enforcement` job in `.github/workflows/ci.yml`
asserts the tracked hook machinery is present and that
`bootstrap-hooks.sh` sets `core.hooksPath=.githooks` when run, so a
broken or missing hook setup fails PR CI.

## What runs

| Hook | Purpose | Source |
|---|---|---|
| `pre-commit` | Invoke `scripts/check-worktree-isolation.sh self`. Blocks the commit on collision. | This dir. |

## Why not `.git/hooks/`

Hooks in `.git/hooks/` are per-clone and invisible to reviewers. Tracked
hooks under `.githooks/` are a single source of truth across worktrees
and agents, with changes reviewed on the same PR as the code they cover.

## Bypass

`git commit --no-verify` exists. Use it when the hook is demonstrably
wrong, not as a workaround for a real collision.
