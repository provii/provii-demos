# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Maelstrom AI Pty Ltd
#
# Top-level Makefile for provii-demos. Intentionally minimal: the individual
# demo services (demo-web-provii-agegate, demo-express, demo-cloudflare-worker,
# etc.) each have their own package.json / wrangler.toml. This file only
# hosts cross-cutting checks that do not belong inside any single service.

.PHONY: help check-canonical-fixtures

help:
	@echo "provii-demos targets:"
	@echo "  check-canonical-fixtures   Diff the canonical-message fixture JSON files"
	@echo "                             across provii-verifier, provii-issuer, and"
	@echo "                             provii-demos. Fails on drift."

# The canonical HMAC message fixture lives in multiple places and
# MUST stay byte-identical, or the wire contract between services breaks.
# The script computes a SHA-256 over each copy and exits non-zero on any
# divergence. Run from this directory; the script walks up two levels to
# find the parent Provii/ directory (override with PROVII_ROOT=...).
check-canonical-fixtures:
	@./scripts/check-canonical-fixtures.sh
