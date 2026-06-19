// APS-primitive grounding for the two constraint-monotonicity scenarios.
// Shows what the shipped APS SDK actually does, so the cross-encoded MoltyCel
// vectors are grounded in real APS behavior (not just a copy of his 08/15).
//
// Loads the shipped SDK from APS_SDK_PATH or $HOME/agent-passport-system/dist.
// Run: node aps_grounding.mjs
//
// Findings (captured in README.md):
//   A cap-relaxing  : APS core subDelegate REJECTS (throws) at sub-delegation time.
//   B currency      : APS core subDelegate does NOT reject a unit change; APS
//                     enforces currency at the v2 payment-rails layer instead.

const SDK = process.env.APS_SDK_PATH || `${process.env.HOME}/agent-passport-system/dist/src/index.js`
const { generateKeyPair, createDelegation, subDelegate, preAuthorize } = await import(SDK)

const line = (k, v) => console.log(`${k.padEnd(46)} ${v}`)

const root = generateKeyPair(), mid = generateKeyPair(), leaf = generateKeyPair()
const parent = createDelegation({
  delegatedTo: mid.publicKey, delegatedBy: root.publicKey,
  scope: ['pay'], spendLimit: 500, spendLimitUnit: 'currency',
  maxDepth: 2, currentDepth: 0, expiresInHours: 24, privateKey: root.privateKey,
})

console.log('== Scenario A: numeric cap monotonicity (core subDelegate) ==')
// A.1 relax cap 500 -> 1000 (same unit): expect THROW
try {
  subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['pay'],
    spendLimit: 1000, spendLimitUnit: 'currency', privateKey: mid.privateKey })
  line('A relax 500->1000 (same unit):', 'ACCEPTED (no throw)  <-- unexpected')
} catch (e) {
  line('A relax 500->1000 (same unit):', `REJECTED -> ${e.message}`)
}
// A.2 tighten cap 500 -> 300 (valid narrowing): expect OK
try {
  const c = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['pay'],
    spendLimit: 300, spendLimitUnit: 'currency', privateKey: mid.privateKey })
  line('A tighten 500->300 (same unit):', `ACCEPTED (valid narrowing); child limit=${c.spendLimit}`)
} catch (e) {
  line('A tighten 500->300 (same unit):', `REJECTED -> ${e.message}  <-- unexpected`)
}

console.log('\n== Scenario B: currency dimension ==')
// B.1 core subDelegate, change unit tag currency -> invocations: APS does NOT reject
try {
  const c = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['pay'],
    spendLimit: 300, spendLimitUnit: 'invocations', privateKey: mid.privateKey })
  line('B core subDelegate unit change:', `ACCEPTED (no throw); child unit=${c.spendLimitUnit}  <-- core gap`)
} catch (e) {
  line('B core subDelegate unit change:', `REJECTED -> ${e.message}`)
}
// B.2 v2 payment-rails preAuthorize: USD delegation, EUR request -> denied
const rail = { isWalletRevoked: () => false }
const deleg = { wallet_id: 'w1', scope: ['commerce.purchase'], currency: 'USD', spend_limit_base_units: '50000' }
const eur = preAuthorize({ delegation: deleg, required_scope: 'commerce.purchase', amount_base_units: '5000', currency: 'EUR' }, rail)
const usd = preAuthorize({ delegation: deleg, required_scope: 'commerce.purchase', amount_base_units: '5000', currency: 'USD' }, rail)
line('B payment-rails EUR vs USD deleg:', JSON.stringify(eur))
line('B payment-rails USD vs USD deleg:', JSON.stringify(usd))

console.log('\nSummary: A is enforced by APS core narrowing (subDelegate). B is enforced')
console.log('by APS at the v2 payment-rails layer (preAuthorize), NOT by core subDelegate,')
console.log('and under reason code spend_limit_exceeded rather than a dedicated currency code.')
