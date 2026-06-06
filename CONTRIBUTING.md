# Contributing to provii-demos

This repository contains reference implementations and demo applications for
Provii age verification, maintained by Maelstrom AI Pty Ltd. Contributions are
welcome. This guide covers setup, testing, conventions, and the pull request
workflow.

## Development Setup

### Prerequisites

The repo spans multiple languages and platforms. You only need the toolchain for
the component you plan to work on.

| Component | Toolchain |
|---|---|
| `demo-web-provii-agegate` | Node.js >= 18, npm |
| `demo-cloudflare-worker` | Node.js >= 18, npm, Wrangler CLI |
| `provii-provenance` | Node.js >= 18, npm, Wrangler CLI |
| `backends/*/nodejs` | Node.js >= 18, npm |
| `backends/*/go` | Go 1.21+ |
| `backends/*/python` | Python 3.11+, pip |
| `backends/*/cloudflare-workers` | Node.js >= 18, npm, Wrangler CLI |
| `apps/android/*` | Android Studio, JDK 17 |
| `apps/ios/*` | Xcode 15+, macOS |
| `apps/flutter/*` | Flutter SDK |
| `apps/react-native/*` | Node.js >= 18, npm, React Native CLI |

### Clone and install

```bash
git clone https://github.com/provii-id/provii-demos.git
cd provii-demos
```

Each sub-project manages its own dependencies. Navigate to the directory you
need and install from there.

```bash
# TypeScript / Cloudflare Worker demos
cd demo-web-provii-agegate && npm install

# Go backend demos
cd backends/verifier/go && go mod download

# Python backend demos
cd backends/verifier/python && pip install -r requirements.txt
```

### Git hooks

The repository ships tracked hooks under `.githooks/`. After cloning (and after
creating any linked worktree), run:

```bash
./scripts/bootstrap-hooks.sh
```

This sets `core.hooksPath=.githooks` in your local git config. CI enforces that
the hook machinery is present, so PRs that break it will fail.

## Running Tests

The primary test suite lives in `demo-web-provii-agegate` and uses Vitest with
`@cloudflare/vitest-pool-workers` to run tests against a Miniflare-backed
isolate that mirrors the production runtime.

```bash
cd demo-web-provii-agegate

# Run the full suite once
npm test

# Run in watch mode during development
npm run test:watch
```

Other checks available in `demo-web-provii-agegate`:

```bash
npm run lint # ESLint
npm run typecheck # TypeScript strict mode, no emit
npm run verify:sdk-sri # SRI hash verification
```

The top-level Makefile provides a cross-cutting fixture check:

```bash
make check-canonical-fixtures
```

This verifies that canonical HMAC message fixture JSON files stay byte-identical
across provii-verifier, provii-issuer, and this repo.

## Commit Conventions

All commits must follow the [Conventional Commits](https://www.conventionalcommits.org/)
format:

```
<type>(<scope>): <description>
```

Accepted types:

| Type | Use |
|---|---|
| `feat` | A new feature or capability |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `chore` | Build, CI, dependency updates |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |

Scope is optional but encouraged. Use the sub-project name when the change is
localised, e.g. `feat(provii-agegate): add sandbox toggle` or
`fix(backends/go): correct HMAC validation`.

Keep the subject line under 72 characters. Use the body for context on why the
change was made, not what was changed.

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes. Keep commits atomic, one logical change per commit.
4. Run the relevant test suite and linter before pushing.
5. Open a pull request against `main` on `provii-id/provii-demos`.

Your PR description should include a short summary of what changed and why, plus
a note on how reviewers can verify the behaviour. Screenshots or terminal output
help when the change is visual or involves CLI tooling.

A maintainer will review your PR. Expect at least one round of feedback. CI must
pass before merge. If CI fails on something unrelated to your change, note it in
a comment so reviewers can distinguish.

## Coding Style

### TypeScript

All TypeScript code uses strict mode (`"strict": true` in tsconfig.json). The
linter config enforces the project style via ESLint with
`@typescript-eslint/eslint-plugin`. Run `npm run lint` before committing.

### Go

Format all Go code with `gofmt`. Unformatted Go code will not pass review.

### Python

Format Python code with [Black](https://github.com/psf/black) using its default
settings. Type hints are encouraged but not enforced.

### Language in comments and documentation

Use Australian English spelling in all comments, documentation, and user-facing
strings. That means `organisation`, `colour`, `licence` (noun), `defence`,
`behaviour`, `analyse`, `metre`, `centre`. If your editor's spellchecker flags
these, it is wrong.

## Contributor Licence Agreement

Before your first contribution can be merged, you must sign the project CLA. The
full text is in [CLA.md](CLA.md).

To sign, reply to your pull request with:

> I have read the CLA Document and I hereby sign the CLA

Your signature is recorded automatically. You only need to sign once across all
repositories in the organisation.
