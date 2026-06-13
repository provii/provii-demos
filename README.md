<p align="center">
 <picture>
 <source media="(prefers-color-scheme: dark)" srcset="./assets/provii-logo-dark.png">
 <source media="(prefers-color-scheme: light)" srcset="./assets/provii-logo-light.png">
 <img alt="Provii" src="./assets/provii-logo-light.png" width="200">
 </picture>
</p>

<h1 align="center">provii-demos</h1>

<p align="center">Eighteen working demos. Four integration patterns. Copy the one that matches your stack, add your sandbox key, run it.</p>

<p align="center">
 <a href="https://github.com/provii/provii-demos/actions/workflows/ci.yml"><img src="https://github.com/provii/provii-demos/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
 <a href="./LICENSE"><img src="https://img.shields.io/badge/licence-MIT-blue" alt="Licence: MIT"></a>
 <a href="https://docs.provii.app/integration"><img src="https://img.shields.io/badge/docs-integration-green" alt="Integration Docs"></a>
 <a href="https://playground.provii.app"><img src="https://img.shields.io/badge/sandbox-playground-orange" alt="Sandbox Playground"></a>
</p>

## Pick your scenario

Provii has four integration patterns, each targeting a different runtime and level of control.

| Scenario | What it demonstrates |
|----------|---------------------|
| Simple website verification | Drop a `<script>` tag on your page. `provii-agegate` handles the rest via `pk_` public key authentication and server side session cookies. |
| Expert website verification | Your own backend calls `provii-verifier` directly with HMAC-SHA256, a mandatory nonce, and PKCE. Full control over the verification flow. |
| Mobile app verification | Same expert protocol as above, but from a native or cross platform mobile app. The wallet opens via deep link and returns control to your app when done. |
| Mobile app issuance | Your issuer backend authenticates with HMAC-SHA256, then `provii-issuer` signs an Ed25519 attestation internally. The wallet receives it via deep link for blind issuance. |

In-person officer issuance (Yubikey HMAC-SHA1) is documented in [`integration.ref.md`](https://docs.provii.app/integration) but has no demo in this repository.

## Pick your platform

Find your stack in the left column. Follow the link for your scenario.

| Platform | Simple website | Expert verifier backend | Mobile verifier app | Issuer backend | Mobile issuer app |
|----------|:-:|:-:|:-:|:-:|:-:|
| Cloudflare Workers (TypeScript) | [demo-web-provii-agegate](./demo-web-provii-agegate/) [demo-cloudflare-worker](./demo-cloudflare-worker/) | [backends/verifier/cloudflare-workers](./backends/verifier/cloudflare-workers/) | | [backends/issuer/cloudflare-workers](./backends/issuer/cloudflare-workers/) | |
| Node.js (TypeScript) | | [backends/verifier/nodejs](./backends/verifier/nodejs/) | | [backends/issuer/nodejs](./backends/issuer/nodejs/) | |
| Go | | [backends/verifier/go](./backends/verifier/go/) | | [backends/issuer/go](./backends/issuer/go/) | |
| Python (FastAPI) | | [backends/verifier/python](./backends/verifier/python/) | | [backends/issuer/python](./backends/issuer/python/) | |
| Android (Kotlin + Jetpack Compose) | | | [apps/android/verifier](./apps/android/verifier/) | | [apps/android/issuer](./apps/android/issuer/) |
| iOS (Swift + SwiftUI) | | | [apps/ios/ProviiVerifierDemo](./apps/ios/ProviiVerifierDemo/) | | [apps/ios/ProviiIssuerDemo](./apps/ios/ProviiIssuerDemo/) |
| React Native (TypeScript) | | | [apps/react-native/verifier](./apps/react-native/verifier/) | | [apps/react-native/issuer](./apps/react-native/issuer/) |
| Flutter (Dart) | | | [apps/flutter/provii_verifier_demo](./apps/flutter/provii_verifier_demo/) | | [apps/flutter/provii_issuer_demo](./apps/flutter/provii_issuer_demo/) |

All four backend stacks (Node.js, Go, Python, Cloudflare Workers) implement the same API surface. Any backend can be paired with any mobile app demo on the same row type, issuer or verifier.

## Running any demo

Backend demos all follow the same pattern.

```sh
cd backends/verifier/nodejs # or go, python, cloudflare-workers
cp .env.example .env # fill in your sandbox credentials
npm install # or: go build / pip install -r requirements.txt
npm start # or: go run main.go / python main.py / npx wrangler dev
```

Mobile demos default to remote sandbox backends (`https://verifier-demo.provii.app` or `https://issuer-demo.provii.app`). To develop against a local backend, override the backend URL in each app's config file to point at your machine. On Android emulators that means `http://10.0.2.2:3001` instead of `http://localhost:3001`. Each demo directory has its own README with exact build commands, config overrides, and expected output.

For simple website demos, `demo-web-provii-agegate` runs as a Cloudflare Worker serving a full reference page at `http://localhost:8787`. The `demo-cloudflare-worker` shows the edge injection pattern, where an HTMLRewriter injects the agegate script into responses from any origin.

## Before you start

You need a free sandbox account at [playground.provii.app](https://playground.provii.app). Under the "Set up an Issuing Party" or "Set up a Verifier" tab, mint a credential set. Sandbox credentials expire after 72 hours. Production credentials come from [admin.provii.app](https://admin.provii.app).

Install the Provii Wallet on your test device from the iOS App Store or Google Play. Open Settings, tap the version number five times, and toggle Sandbox Mode on. The app restarts in sandbox mode.

Backend demos need one of: Node.js 18+, Go 1.24+, Python 3.10+, or the Wrangler CLI (for Cloudflare Workers). Mobile demos need Android Studio with SDK 26+ and JDK 17+ (Android), Xcode 15+ targeting iOS 16+ (iOS), Node.js 18+ with React Native CLI (React Native), or Flutter 3.16+ (Flutter).

## Install

Clone this repository and navigate to whichever demo matches your stack. Each demo directory contains its own dependency manifest (`package.json`, `go.mod`, `requirements.txt`, or `wrangler.toml`).

```sh
git clone https://github.com/provii/provii-demos.git
cd provii-demos
```

## Quickstart

Pick a backend demo and follow the three-step pattern described in "Running any demo" above. For the fastest path, use the Node.js verifier backend.

```sh
cd backends/verifier/nodejs
cp .env.example .env # fill in your sandbox credentials from playground.provii.app
npm install
npm run dev
```

Open a second terminal and create a verification challenge:

```sh
curl -X POST http://localhost:3001/api/create-challenge \
 -H "Content-Type: application/json" \
 -d '{"minimum_age": 18}'
```

Scan the returned deep link with the Provii Wallet (in sandbox mode) to complete the flow.

## Configuration

Every backend demo reads its credentials from a `.env` file. Copy `.env.example` in the relevant demo directory and fill in the values minted from [playground.provii.app](https://playground.provii.app). The common variables are `CLIENT_ID`, `API_KEY`, `HMAC_SECRET`, and the API base URL. Mobile demos store their backend URL in a platform-specific config file documented in each demo's own README.

## Cross-service integration tests

The [`integration-tests/`](./integration-tests/) directory contains a self-contained vitest project that validates end-to-end verification flows across provii-verifier, provii-issuer, and provii-credit-management. It has its own `package.json` and runs independently of the demo code. See [`integration-tests/README.md`](./integration-tests/README.md) for setup and usage.

## Contributing

Contributions are welcome. Open an issue or pull request on the [provii-demos](https://github.com/provii/provii-demos) repository. Run `npm test` from the relevant demo directory before submitting. All code in this repository is MIT-licenced.

## Licence

MIT. Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792). See [LICENSE](./LICENSE) for the full text.
