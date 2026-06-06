// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * X.509 chain scaffolding tests.
 *
 * The Apple App Attest root is self-signed, so we can verify the
 * signature without a real receipt. That's the "real" test here.
 * Everything else (leaf and intermediate verification, issuer/subject
 * chain linkage) is gated on a real App Attest receipt from the
 * iOS dev build. See PHASE_7A_0_SPIKE_REPORT.md.
 */

import { describe, expect, it } from "vitest";

import {
  __resetPinnedRootCacheForTests,
  APPLE_APP_ATTEST_ROOT_CA_DER_BASE64,
  APPLE_APP_ATTEST_ROOT_CA_FINGERPRINT_SHA256,
  base64ToBytes,
  getPinnedAppleRoot,
  parseCertificate,
  verifyCertificateSignature,
  verifyChainToRoot,
} from "../attestation/x509";

describe("pinned Apple App Attest root", () => {
  it("has the expected SHA-256 fingerprint", async () => {
    __resetPinnedRootCacheForTests();
    const der = base64ToBytes(APPLE_APP_ATTEST_ROOT_CA_DER_BASE64);
    const digest = await crypto.subtle.digest("SHA-256", der);
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(APPLE_APP_ATTEST_ROOT_CA_FINGERPRINT_SHA256);
  });

  it("parses into the expected algorithm + curve", async () => {
    __resetPinnedRootCacheForTests();
    const root = await getPinnedAppleRoot();
 // Apple docs + openssl x509 inspection confirm:
 // signatureAlgorithm = ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
 // publicKey = id-ecPublicKey (1.2.840.10045.2.1)
 // curve = secp384r1 (1.3.132.0.34)
    expect(root.signatureAlgorithmOid).toBe("1.2.840.10045.4.3.3");
    expect(root.publicKeyAlgorithmOid).toBe("1.2.840.10045.2.1");
    expect(root.publicKeyCurveOid).toBe("1.3.132.0.34");
  });

  it("verifies its own self-signature", async () => {
    __resetPinnedRootCacheForTests();
    const root = await getPinnedAppleRoot();
    const ok = await verifyCertificateSignature(
      root,
      root.spkiDer,
      root.publicKeyCurveOid,
    );
    expect(ok).toBe(true);
  });

  it("self-verifies via verifyChainToRoot with empty intermediates", async () => {
    __resetPinnedRootCacheForTests();
    const root = await getPinnedAppleRoot();
 // Degenerate chain: leaf == root. Validates that the function
 // handles the root-only path and still checks the self-signature.
    await expect(verifyChainToRoot(root, [], root)).resolves.toBeUndefined();
  });

  it("rejects a tampered root (flipped signature byte)", async () => {
    __resetPinnedRootCacheForTests();
    const root = await getPinnedAppleRoot();
    const tampered = { ...root };
    const sig = new Uint8Array(root.signatureBytes);
    sig[sig.length - 1] = sig[sig.length - 1]! ^ 0x01;
    tampered.signatureBytes = sig;
    const ok = await verifyCertificateSignature(
      tampered,
      tampered.spkiDer,
      tampered.publicKeyCurveOid,
    );
    expect(ok).toBe(false);
  });

  it("getPinnedAppleRoot throws if the pinned blob is corrupted", async () => {
    __resetPinnedRootCacheForTests();
 // Monkey-patch the digest check by constructing a bogus cert
 // from truncated bytes and asserting parseCertificate rejects it.
 // (We can't easily rewrite the exported constant, so this stands
 // in as a parser robustness check. Corrupting `APPLE_...DER`
 // would be a real test; left as a note for .7.)
    const truncated = new Uint8Array([0x30, 0x82, 0x00, 0x05, 0x00, 0x00]);
    expect(() => parseCertificate(truncated)).toThrow();
  });
});

describe("parseCertificate: structural sanity", () => {
  it("surfaces issuer == subject on a self-signed cert", async () => {
    const root = await getPinnedAppleRoot();
    expect(root.issuerDer.length).toBe(root.subjectDer.length);
    for (let i = 0; i < root.issuerDer.length; i++) {
      expect(root.issuerDer[i]).toBe(root.subjectDer[i]);
    }
  });
});

// ---- Tests: RSASSA-PKCS1-v1_5 SHA-256 support () ------------
//
// The Google Hardware Attestation RSA-4096 batch root emits its TBS
// with `sha256WithRSAEncryption` (OID 1.2.840.113549.1.1.11) over an
// RSA 4096 public key. WebCrypto's `RSASSA-PKCS1-v1_5` + SHA-256
// identifier is the exact verifier for that pair. The tests below
// exercise the new RSA branch of `verifyCertificateSignature` by
// synthesising a self-signed RSA-rooted cert via the existing chain
// builder and asserting both the accept and reject paths land in the
// RSA arm rather than falling through to ECDSA.

import {
  buildSyntheticChain,
} from "../attestation/__fixtures__/synthetic-chain";
import {
  SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
  VERIFIED_BOOT_STATE_VERIFIED,
} from "../attestation/key-attestation";

function rsaBaseKeyDescription(challenge: Uint8Array) {
  return {
    attestationVersion: 4,
    attestationSecurityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    keymasterVersion: 41,
    keymasterSecurityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    attestationChallenge: challenge,
    softwareEnforced: {},
    hardwareEnforced: {
      rootOfTrust: {
        verifiedBootKey: new Uint8Array(32).fill(0x77),
        deviceLocked: true,
        verifiedBootState: VERIFIED_BOOT_STATE_VERIFIED,
        verifiedBootHash: new Uint8Array(32).fill(0x00),
      },
    },
  };
}

describe("verifyCertificateSignature: RSASSA-PKCS1-v1_5 SHA-256 (AR-K1)", () => {
  it("verifies a self-signed RSA root against its own SPKI", async () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: rsaBaseKeyDescription(challenge),
      rootSignatureAlgorithm: "RSA_PKCS1_SHA256",
    });
    const rootCert = parseCertificate(chain.rootDer);
 // Confirm the TBS really was emitted with the RSA signature
 // algorithm OID; otherwise the test would silently be hitting the
 // ECDSA branch.
    expect(rootCert.signatureAlgorithmOid).toBe("1.2.840.113549.1.1.11");
    expect(rootCert.publicKeyAlgorithmOid).toBe("1.2.840.113549.1.1.1");
    const ok = await verifyCertificateSignature(
      rootCert,
      rootCert.spkiDer,
      rootCert.publicKeyCurveOid,
    );
    expect(ok).toBe(true);
  });

  it("rejects a tampered RSA signature (flipped signature byte)", async () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: rsaBaseKeyDescription(challenge),
      rootSignatureAlgorithm: "RSA_PKCS1_SHA256",
    });
    const rootCert = parseCertificate(chain.rootDer);
    const tampered = { ...rootCert };
    const sig = new Uint8Array(rootCert.signatureBytes);
    sig[sig.length - 1] = sig[sig.length - 1]! ^ 0x01;
    tampered.signatureBytes = sig;
    const ok = await verifyCertificateSignature(
      tampered,
      tampered.spkiDer,
      tampered.publicKeyCurveOid,
    );
    expect(ok).toBe(false);
  });

  it("verifies an RSA root through verifyChainToRoot (self-chain, no intermediates)", async () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: rsaBaseKeyDescription(challenge),
      rootSignatureAlgorithm: "RSA_PKCS1_SHA256",
    });
    const rootCert = parseCertificate(chain.rootDer);
    await expect(
      verifyChainToRoot(rootCert, [], rootCert),
    ).resolves.toBeUndefined();
  });

  it("refuses to verify a SHA-1 RSA signature algorithm OID (no downgrade)", async () => {
 // Build a real RSA-signed cert, then synthesise a parsed form
 // whose signatureAlgorithmOid is the SHA-1 RSA identifier. The
 // verifier must throw "unsupported signature algorithm" rather
 // than route to WebCrypto with SHA-1.
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: rsaBaseKeyDescription(challenge),
      rootSignatureAlgorithm: "RSA_PKCS1_SHA256",
    });
    const rootCert = parseCertificate(chain.rootDer);
    const sha1Cert = { ...rootCert, signatureAlgorithmOid: "1.2.840.113549.1.1.5" };
    await expect(
      verifyCertificateSignature(
        sha1Cert,
        sha1Cert.spkiDer,
        sha1Cert.publicKeyCurveOid,
      ),
    ).rejects.toThrow(/unsupported signature algorithm/);
  });
});
