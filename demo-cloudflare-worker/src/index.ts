// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

/**
 * Reference Cloudflare Worker demonstrating HTMLRewriter-based provii-agegate injection.
 *
 * This Worker sits in front of an origin server and:
 * 1. Passes non-HTML responses through unchanged
 * 2. Injects a FOUC prevention <style> into <head>
 * 3. Injects the provii-agegate <script> tag before </body>
 * 4. Modifies existing CSP headers to allow Provii's CDN and provii-verifier endpoints
 *
 * Configure via environment variables in wrangler.toml or the CF dashboard.
 */

interface Env {
  /** The customer's Provii public key, e.g. "pk_live_abc..." or "pk_test_abc..." */
  PROVII_PUBLIC_KEY: string;

  /** "production" or "sandbox" */
  PROVII_ENVIRONMENT: string;

  /** Optional BCP 47 language code for the age gate UI, e.g. "en", "fr", "de" */
  PROVII_LANG?: string;

  /**
 * Optional SRI hash for the provii-agegate script tag.
 * Format: "sha384-..." (fetch from cdn.provii.app/sdk/provii-agegate/manifest.json)
   */
  PROVII_SRI_HASH?: string;

  /** Optional exact version to pin, e.g. "1.2.3". Defaults to major version "v1". */
  PROVII_SDK_VERSION?: string;
}

const PROVII_CDN_HOST = "cdn.provii.app";
const PROVII_VERIFY_HOST = "verify.provii.app";
const SANDBOX_VERIFY_HOST = "sandbox-verify.provii.app";

/** FOUC prevention CSS injected into <head>. The animation is a 5-second safety net
 * that makes the page visible if provii-agegate fails to load. */
const FOUC_PREVENTION_STYLE =
  "<style>body{visibility:hidden!important;animation:provii-reveal 0s 5s forwards}@keyframes provii-reveal{to{visibility:visible}}</style>";

/** Escape a string for safe use inside an HTML attribute value. */
function escapeHtmlAttr(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function buildScriptTag(env: Env): string {
  const version = env.PROVII_SDK_VERSION
    ? `v${escapeHtmlAttr(env.PROVII_SDK_VERSION)}`
    : "v1";
  const scriptUrl = `https://${PROVII_CDN_HOST}/sdk/provii-agegate/${version}/agegate.browser.js`;

  const attributes: string[] = [
    `src="${scriptUrl}"`,
    `crossorigin="anonymous"`,
    `data-public-key="${escapeHtmlAttr(env.PROVII_PUBLIC_KEY)}"`,
    `data-environment="${escapeHtmlAttr(env.PROVII_ENVIRONMENT)}"`,
  ];

  if (env.PROVII_SRI_HASH) {
    attributes.push(`integrity="${escapeHtmlAttr(env.PROVII_SRI_HASH)}"`);
  }

  if (env.PROVII_LANG) {
    attributes.push(`data-lang="${escapeHtmlAttr(env.PROVII_LANG)}"`);
  }

 // No defer or async: provii-agegate relies on document.currentScript
  return `<script ${attributes.join(" ")}></script>`;
}

function isHtmlResponse(response: Response): boolean {
  const contentType = response.headers.get("content-type");
  if (!contentType) return false;
  return contentType.includes("text/html");
}

/**
 * Modify an existing CSP header to allow Provii's CDN and provii-verifier endpoints.
 * If no CSP header exists, returns null (do not add one).
 */
function modifyCsp(existingCsp: string, environment: string): string {
  let modifiedCsp = existingCsp;

  const verifyHost =
    environment === "sandbox" ? SANDBOX_VERIFY_HOST : PROVII_VERIFY_HOST;

 // Add CDN to script-src
  if (modifiedCsp.includes("script-src")) {
    if (!modifiedCsp.includes(PROVII_CDN_HOST)) {
      modifiedCsp = modifiedCsp.replace(
        "script-src",
        `script-src ${PROVII_CDN_HOST}`,
      );
    }
  }

 // Add provii-verifier endpoint to connect-src
  if (modifiedCsp.includes("connect-src")) {
    if (!modifiedCsp.includes(verifyHost)) {
      modifiedCsp = modifiedCsp.replace(
        "connect-src",
        `connect-src ${verifyHost}`,
      );
    }
  }

 // Add unsafe-inline to style-src for the FOUC prevention style
  if (
    modifiedCsp.includes("style-src") &&
    !modifiedCsp.includes("'unsafe-inline'")
  ) {
    modifiedCsp = modifiedCsp.replace(
      "style-src",
      "style-src 'unsafe-inline'",
    );
  }

  return modifiedCsp;
}

/** HTMLRewriter handler that injects the FOUC prevention style into <head>. */
class HeadHandler implements HTMLRewriterElementContentHandlers {
  handled = false;

  element(element: Element): void {
    if (this.handled) return;
    this.handled = true;
    element.prepend(FOUC_PREVENTION_STYLE, { html: true });
  }
}

/** HTMLRewriter handler that injects the provii-agegate script before </body>. */
class BodyHandler implements HTMLRewriterElementContentHandlers {
  private readonly scriptTag: string;
  handled = false;

  constructor(scriptTag: string) {
    this.scriptTag = scriptTag;
  }

  element(element: Element): void {
    if (this.handled) return;
    this.handled = true;
    element.append(this.scriptTag, { html: true });
  }
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<Response> {
 // Validate required configuration
    if (!env.PROVII_PUBLIC_KEY) {
      return new Response("PROVII_PUBLIC_KEY environment variable not set", {
        status: 500,
      });
    }
    if (!env.PROVII_ENVIRONMENT) {
      return new Response(
        "PROVII_ENVIRONMENT environment variable not set",
        { status: 500 },
      );
    }

 // Fetch from origin. In production, this would be the customer's origin server.
 // For local testing, use the demo origin defined in wrangler.toml routes.
    const originResponse = await fetch(request);

 // Pass through non-HTML responses unchanged
    if (!isHtmlResponse(originResponse)) {
      return originResponse;
    }

    const scriptTag = buildScriptTag(env);

 // Apply HTMLRewriter transformations
    let rewrittenResponse = new HTMLRewriter()
      .on("head", new HeadHandler())
      .on("body", new BodyHandler(scriptTag))
      .transform(originResponse);

 // Clone headers so we can modify CSP
    const responseHeaders = new Headers(rewrittenResponse.headers);

    const existingCsp = responseHeaders.get("content-security-policy");
    if (existingCsp) {
      const modifiedCsp = modifyCsp(existingCsp, env.PROVII_ENVIRONMENT);
      responseHeaders.set("content-security-policy", modifiedCsp);
    }

    return new Response(rewrittenResponse.body, {
      status: rewrittenResponse.status,
      statusText: rewrittenResponse.statusText,
      headers: responseHeaders,
    });
  },
};
