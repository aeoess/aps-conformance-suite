// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// From-scratch minimal CBOR codec (RFC 8949 subset), written for the capsule
// vector verifier. Decode covers what COSE_Sign1 structures need: unsigned and
// negative integers, byte strings, text strings, arrays, maps, tag, null,
// bool, and float64. Encode covers the Sig_structure subset: arrays, byte
// strings, text strings, and integers. No external packages.

export type CborValue =
  | number | bigint | string | Uint8Array | boolean | null | undefined
  | CborValue[] | CborMap | CborTagged

export class CborMap {
  entries: Array<[CborValue, CborValue]> = []
  get(key: number | string): CborValue | undefined {
    for (const [k, v] of this.entries) {
      if (typeof k === 'number' || typeof k === 'bigint') {
        if (Number(k) === key) return v
      } else if (k === key) return v
    }
    return undefined
  }
}

export class CborTagged {
  constructor(public tag: number, public value: CborValue) {}
}

class Reader {
  pos = 0
  constructor(public buf: Uint8Array) {}
  u8(): number {
    if (this.pos >= this.buf.length) throw new Error('cbor: truncated')
    return this.buf[this.pos++]
  }
  bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error('cbor: truncated')
    const out = this.buf.subarray(this.pos, this.pos + n)
    this.pos += n
    return out
  }
}

function readLength(r: Reader, info: number): number {
  if (info < 24) return info
  if (info === 24) return r.u8()
  if (info === 25) { const b = r.bytes(2); return (b[0] << 8) | b[1] }
  if (info === 26) { const b = r.bytes(4); return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0 }
  if (info === 27) {
    const b = r.bytes(8)
    let v = 0n
    for (const x of b) v = (v << 8n) | BigInt(x)
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: length too large')
    return Number(v)
  }
  throw new Error(`cbor: unsupported additional info ${info}`)
}

function decodeItem(r: Reader): CborValue {
  const ib = r.u8()
  const major = ib >> 5
  const info = ib & 0x1f
  switch (major) {
    case 0: return readLength(r, info)
    case 1: return -1 - readLength(r, info)
    case 2: return new Uint8Array(r.bytes(readLength(r, info)))
    case 3: return new TextDecoder('utf-8', { fatal: true }).decode(r.bytes(readLength(r, info)))
    case 4: {
      const n = readLength(r, info)
      const out: CborValue[] = []
      for (let i = 0; i < n; i++) out.push(decodeItem(r))
      return out
    }
    case 5: {
      const n = readLength(r, info)
      const m = new CborMap()
      for (let i = 0; i < n; i++) {
        const k = decodeItem(r)
        const v = decodeItem(r)
        m.entries.push([k, v])
      }
      return m
    }
    case 6: return new CborTagged(readLength(r, info), decodeItem(r))
    case 7: {
      if (info === 20) return false
      if (info === 21) return true
      if (info === 22) return null
      if (info === 23) return undefined
      if (info === 27) {
        const b = r.bytes(8)
        const dv = new DataView(b.buffer, b.byteOffset, 8)
        return dv.getFloat64(0)
      }
      throw new Error(`cbor: unsupported simple/float info ${info}`)
    }
    default: throw new Error(`cbor: unsupported major type ${major}`)
  }
}

export function cborDecode(buf: Uint8Array): CborValue {
  const r = new Reader(buf)
  const v = decodeItem(r)
  if (r.pos !== buf.length) throw new Error(`cbor: ${buf.length - r.pos} trailing bytes`)
  return v
}

/** Decode one item, returning it plus any trailing byte count (some encoders
 *  concatenate items). */
export function cborDecodePrefix(buf: Uint8Array): { value: CborValue; used: number } {
  const r = new Reader(buf)
  const v = decodeItem(r)
  return { value: v, used: r.pos }
}

// ── Encode subset ──────────────────────────────────────────────────────────

function encodeHead(major: number, n: number): Uint8Array {
  if (n < 24) return Uint8Array.of((major << 5) | n)
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n)
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff)
  if (n <= 0xffffffff) {
    return Uint8Array.of((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff)
  }
  throw new Error('cbor encode: length beyond uint32 not needed here')
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

export function cborEncode(value: CborValue): Uint8Array {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('cbor encode: only integers')
    return value >= 0 ? encodeHead(0, value) : encodeHead(1, -1 - value)
  }
  if (typeof value === 'string') {
    const b = new TextEncoder().encode(value)
    return concat([encodeHead(3, b.length), b])
  }
  if (value instanceof Uint8Array) return concat([encodeHead(2, value.length), value])
  if (Array.isArray(value)) return concat([encodeHead(4, value.length), ...value.map(cborEncode)])
  throw new Error(`cbor encode: unsupported type ${typeof value}`)
}
