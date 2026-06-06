// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii

/**
 * Minimal CBOR decoder targeted at Apple App Attest receipts
 * (.6).
 *
 * Scope is deliberately narrow: we parse unsigned integers, byte
 * strings, text strings, arrays, maps, the `false/true/null/undefined`
 * simple values, and CBOR tags (which App Attest does not actually
 * use in the outer envelope but appear inside the WebAuthn-style
 * attStmt on some Apple test fixtures). Floats, big integers, and
 * indefinite-length items are rejected.
 *
 * App Attest uses a CBOR subset of the WebAuthn attestation object
 * shape (RFC 8152 + spec-inspired layout):
 *
 * {
 * "fmt": "apple-appattest",
 * "attStmt": { "x5c": [<DER bytes>...], "receipt": <bytes> },
 * "authData": <bytes>
 * }
 *
 * We reject map keys that are not text strings because the App
 * Attest envelope only uses text-keyed maps. If Apple ever extends
 * the receipt shape to include integer-keyed maps we will need to
 * broaden this.
 *
 * Why no external dependency. `cbor-x` is a general-purpose encoder
 * and decoder with tag extensions we do not need, and pulls around
 * 80 KB into the bundle once tree-shaken. The App Attest receipt
 * has a fixed shape; a 150-line decoder gives us exact control over
 * the parse paths we want to test and keeps the Worker bundle
 * close to its existing budget. .0 originally penciled in
 * cbor-x; after weighing the bundle footprint and the narrow input
 * grammar we are in, the in-house decoder is the cleaner fit.
 *
 * Reference: RFC 8949 (the CBOR spec).
 * https://datatracker.ietf.org/doc/html/rfc8949
 */

export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | CborValue[]
  | { readonly [key: string]: CborValue }
  | CborTag;

/** CBOR tagged value (major type 6). Not widely used by App Attest. */
export interface CborTag {
  readonly tag: number;
  readonly value: CborValue;
}

/**
 * Maximum nesting depth allowed when decoding CBOR. A deeply nested
 * payload can overflow the call stack; 32 levels is well beyond what
 * any legitimate App Attest receipt requires while still catching
 * adversarial inputs early.
 */
export const MAX_CBOR_DEPTH = 32;

export function isCborTag(value: CborValue): value is CborTag {
  return typeof value === "object"
    && value !== null
    && !Array.isArray(value)
    && !(value instanceof Uint8Array)
    && "tag" in value
    && typeof (value as CborTag).tag === "number";
}

/**
 * Decode the first CBOR item from `bytes`. Throws if the input is
 * not fully consumed; App Attest receipts are single self-delimited
 * CBOR items so a trailing byte implies a framing bug.
 */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const cursor = { offset: 0 };
  const value = readItem(bytes, cursor, 0);
  if (cursor.offset !== bytes.length) {
    throw new Error(
      `CBOR: trailing ${bytes.length - cursor.offset} byte(s) after top-level item`,
    );
  }
  return value;
}

interface Cursor { offset: number }

function readItem(bytes: Uint8Array, cursor: Cursor, depth: number): CborValue {
  if (depth > MAX_CBOR_DEPTH) {
    throw new Error(
      `CBOR: nesting depth exceeds maximum of ${MAX_CBOR_DEPTH}`,
    );
  }
  if (cursor.offset >= bytes.length) {
    throw new Error("CBOR: read past end of buffer");
  }
  const initial = bytes[cursor.offset]!;
  cursor.offset += 1;
  const major = initial >> 5;
  const additional = initial & 0x1f;

  if (additional === 31) {
 // Indefinite-length items. App Attest does not use them; we
 // reject to stop a malicious CBOR payload from stretching past
 // the size bound we expect.
    throw new Error("CBOR: indefinite-length items are not supported");
  }

  const length = readLength(bytes, cursor, additional);

  switch (major) {
    case 0: // unsigned integer
      return coerceUnsigned(length);
    case 1: // negative integer: -1 - length
      return coerceNegative(length);
    case 2: // byte string
      return readFixedBytes(bytes, cursor, numberFromLength(length, "byte string"));
    case 3: // text string (UTF-8)
      return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
        readFixedBytes(bytes, cursor, numberFromLength(length, "text string")),
      );
    case 4: { // array
      const count = numberFromLength(length, "array");
      const out: CborValue[] = new Array(count);
      for (let i = 0; i < count; i++) {
        out[i] = readItem(bytes, cursor, depth + 1);
      }
      return out;
    }
    case 5: { // map
      const count = numberFromLength(length, "map");
      const out: Record<string, CborValue> = Object.create(null);
      for (let i = 0; i < count; i++) {
        const key = readItem(bytes, cursor, depth + 1);
        if (typeof key !== "string") {
          throw new Error("CBOR: only text-keyed maps are supported");
        }
        const value = readItem(bytes, cursor, depth + 1);
        out[key] = value;
      }
      return out;
    }
    case 6: { // semantic tag
      const inner = readItem(bytes, cursor, depth + 1);
      return { tag: numberFromLength(length, "tag"), value: inner };
    }
    case 7: // simple / float
      return readSimple(additional, length);
    default:
      throw new Error(`CBOR: unknown major type ${major}`);
  }
}

function readLength(
  bytes: Uint8Array,
  cursor: Cursor,
  additional: number,
): number | bigint {
  if (additional < 24) return additional;
  if (additional === 24) return readUint(bytes, cursor, 1);
  if (additional === 25) return readUint(bytes, cursor, 2);
  if (additional === 26) return readUint(bytes, cursor, 4);
  if (additional === 27) return readUint(bytes, cursor, 8);
  throw new Error(`CBOR: reserved length code ${additional}`);
}

function readUint(
  bytes: Uint8Array,
  cursor: Cursor,
  width: number,
): number | bigint {
  if (cursor.offset + width > bytes.length) {
    throw new Error("CBOR: truncated length field");
  }
  if (width <= 4) {
    let out = 0;
    for (let i = 0; i < width; i++) {
      out = out * 256 + bytes[cursor.offset + i]!;
    }
    cursor.offset += width;
 // 32-bit values fit safely in Number; we preserve the narrow
 // type so downstream code never has to branch on bigint here.
    return out;
  }
 // 8-byte unsigned. Use BigInt, then narrow if it fits safely.
  let out = 0n;
  for (let i = 0; i < width; i++) {
    out = (out << 8n) | BigInt(bytes[cursor.offset + i]!);
  }
  cursor.offset += width;
  if (out <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(out);
  return out;
}

function coerceUnsigned(length: number | bigint): number | bigint {
  return length;
}

function coerceNegative(length: number | bigint): number | bigint {
  if (typeof length === "number") {
    return -1 - length;
  }
  return -1n - length;
}

function numberFromLength(length: number | bigint, context: string): number {
  if (typeof length === "bigint") {
    if (length > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`CBOR: ${context} length exceeds Number.MAX_SAFE_INTEGER`);
    }
    return Number(length);
  }
  return length;
}

function readFixedBytes(
  bytes: Uint8Array,
  cursor: Cursor,
  length: number,
): Uint8Array {
  if (cursor.offset + length > bytes.length) {
    throw new Error("CBOR: truncated byte string");
  }
  const out = bytes.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return out;
}

function readSimple(additional: number, _length: number | bigint): CborValue {
 // Major type 7. Only the four allocated simple values we need.
  switch (additional) {
    case 20: return false;
    case 21: return true;
    case 22: return null;
    case 23: return undefined;
    default:
      throw new Error(`CBOR: simple value ${additional} not supported`);
  }
}

// ---- Typed accessors -------------------------------------------------

/** Read a map field expecting a byte string. Throws on mismatch. */
export function expectBytes(value: CborValue | undefined, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`CBOR: field "${field}" is not a byte string`);
  }
  return value;
}

/** Read a map field expecting a text string. */
export function expectString(value: CborValue | undefined, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`CBOR: field "${field}" is not a text string`);
  }
  return value;
}

/** Read a map field expecting a map. */
export function expectMap(
  value: CborValue | undefined,
  field: string,
): { readonly [key: string]: CborValue } {
  if (
    typeof value !== "object"
    || value === null
    || Array.isArray(value)
    || value instanceof Uint8Array
    || isCborTag(value)
  ) {
    throw new Error(`CBOR: field "${field}" is not a map`);
  }
  return value;
}

/** Read a map field expecting an array of byte strings. */
export function expectBytesArray(
  value: CborValue | undefined,
  field: string,
): Uint8Array[] {
  if (!Array.isArray(value)) {
    throw new Error(`CBOR: field "${field}" is not an array`);
  }
  return value.map((item, index) => {
    if (!(item instanceof Uint8Array)) {
      throw new Error(`CBOR: field "${field}[${index}]" is not a byte string`);
    }
    return item;
  });
}
