// Vendored JCS canonicalizer (RFC 8785) for the APS conformance suite.
// Reference: agent-passport-system/src/core/canonical-jcs.ts at the time of
// suite extraction. Kept local so external implementations under test can
// run this runner without depending on agent-passport-system at runtime.

/** RFC 8785 JSON Canonicalization Scheme. */
export function canonicalizeJCS(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number': {
      if (!isFinite(value)) throw new Error('JCS does not support Infinity or NaN')
      return JSON.stringify(value)
    }
    case 'string':
      return JSON.stringify(value)
    case 'object': {
      if (value instanceof Date) return JSON.stringify(value)
      if (Array.isArray(value)) {
        return '[' + value.map(item => canonicalizeJCS(item)).join(',') + ']'
      }
      const obj = value as Record<string, unknown>
      const keys = Object.keys(obj).sort()
      const pairs: string[] = []
      for (const key of keys) {
        const v = obj[key]
        pairs.push(`${JSON.stringify(key)}:${canonicalizeJCS(v)}`)
      }
      return '{' + pairs.join(',') + '}'
    }
    default:
      throw new Error(`JCS: unsupported type ${typeof value}`)
  }
}
