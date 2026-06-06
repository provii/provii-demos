// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * End-to-end synthetic-chain test for `verifyKeyAttestation`.
 *
 * Addresses . The other key-attestation tests short-circuit on
 * config (empty pinned root, chain-length guard) or exercise
 * sub-functions in isolation. This file builds a full three-cert
 * chain in WebCrypto (root, intermediate, leaf) and runs
 * `verifyKeyAttestation` against it through the real chain walk,
 * extension extraction, KeyDescription parser, challenge match,
 * security-level check, and verified-boot policy.
 *
 * Two paths exercised here:
 * 1. Happy path: VERIFIED + deviceLocked + TEE attestation level.
 * Expected: resolves with the leaf + keyDescription.
 * 2. Reject path: SELF_SIGNED with an unknown OS key; chain
 * signatures are valid end-to-end, parser sees the extension,
 * but the verified-boot policy must still reject.
 */

import { describe, expect, it } from "vitest";

import {
  buildSyntheticChain,
  bytesToBase64,
  type KeyDescriptionInput,
} from "../attestation/__fixtures__/synthetic-chain";
import {
  SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
  VERIFIED_BOOT_STATE_SELF_SIGNED,
  VERIFIED_BOOT_STATE_VERIFIED,
  verifyKeyAttestation,
} from "../attestation/key-attestation";

function baseKeyDescription(
  challenge: Uint8Array,
  overrides: Partial<KeyDescriptionInput> = {},
): KeyDescriptionInput {
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
    ...overrides,
  };
}

describe("verifyKeyAttestation end-to-end (synthetic chain)", () => {
  it("accepts a VERIFIED + locked + TEE chain with a matching challenge", async () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: baseKeyDescription(challenge),
    });

    const result = await verifyKeyAttestation(chain.chainDer, {
      challenge,
      pinnedRootDerBase64Set: [bytesToBase64(chain.rootDer)],
    });
    expect(result.leaf).toBeDefined();
    expect(result.keyDescription.attestationSecurityLevel).toBe(
      SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    );
    expect(result.keyDescription.hardwareEnforced.rootOfTrust).not.toBeNull();
    expect(
      result.keyDescription.hardwareEnforced.rootOfTrust!.verifiedBootState,
    ).toBe(VERIFIED_BOOT_STATE_VERIFIED);
    expect(
      result.keyDescription.hardwareEnforced.rootOfTrust!.deviceLocked,
    ).toBe(true);
  });

  it(
    "rejects SELF_SIGNED with an unknown OS key (chain signatures still valid)",
    async () => {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const unknownOsKey = new Uint8Array(32).fill(0x42);
      const chain = await buildSyntheticChain({
        attestationChallenge: challenge,
        keyDescription: baseKeyDescription(challenge, {
          hardwareEnforced: {
            rootOfTrust: {
              verifiedBootKey: unknownOsKey,
              deviceLocked: true,
              verifiedBootState: VERIFIED_BOOT_STATE_SELF_SIGNED,
              verifiedBootHash: new Uint8Array(32).fill(0x00),
            },
          },
        }),
      });

      await expect(
        verifyKeyAttestation(chain.chainDer, {
          challenge,
          pinnedRootDerBase64Set: [bytesToBase64(chain.rootDer)],
        }),
      ).rejects.toThrow(/SELF_SIGNED.*not in ALLOWED_SELF_SIGNED_OS_KEYS/);
    },
  );

  it("rejects when the challenge does not match", async () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: baseKeyDescription(challenge),
    });

    const wrongChallenge = new Uint8Array(32).fill(0xaa);
    await expect(
      verifyKeyAttestation(chain.chainDer, {
        challenge: wrongChallenge,
        pinnedRootDerBase64Set: [bytesToBase64(chain.rootDer)],
      }),
    ).rejects.toThrow(/attestationChallenge does not match/);
  });

  it("rejects when the chain terminator is not in the pinned set", async () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: baseKeyDescription(challenge),
    });
 // Build a second independent root + chain; pin only the second one
 // so the first chain's terminator is unknown.
    const other = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: baseKeyDescription(challenge),
      rootCommonName: "Unrelated Other Root",
    });

    await expect(
      verifyKeyAttestation(chain.chainDer, {
        challenge,
        pinnedRootDerBase64Set: [bytesToBase64(other.rootDer)],
      }),
    ).rejects.toThrow(/chain root does not match any pinned Google root/);
  });

 // : devices provisioned before Google's 2026-02-01 EC P-384
 // rotation emit chains terminating in the RSA-4096 batch root. The
 // chain-walk runs through verifyCertificateSignature twice against
 // an RSA signer (intermediate's outer signature + root self-signature)
 // so this test confirms the production code path wires through
 // verifyKeyAttestation, not just that RSA verify works in isolation.
  it("accepts an RSA-rooted chain (AR-K1 regression)", async () => {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildSyntheticChain({
      attestationChallenge: challenge,
      keyDescription: baseKeyDescription(challenge),
      rootSignatureAlgorithm: "RSA_PKCS1_SHA256",
    });

    const result = await verifyKeyAttestation(chain.chainDer, {
      challenge,
      pinnedRootDerBase64Set: [bytesToBase64(chain.rootDer)],
    });
    expect(result.leaf).toBeDefined();
    expect(result.keyDescription.attestationSecurityLevel).toBe(
      SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    );
    expect(result.keyDescription.hardwareEnforced.rootOfTrust).not.toBeNull();
    expect(
      result.keyDescription.hardwareEnforced.rootOfTrust!.verifiedBootState,
    ).toBe(VERIFIED_BOOT_STATE_VERIFIED);
  });
});
