# AAE chain-envelope interop vectors

Four chain-envelope conformance vectors in MoltyCel's **AAE** shape
(`{"chain": [parent, child]}`), each decided by the **shipped APS verifier** via a
small AAE→APS delegation-chain adapter. They show how APS's narrowing, expiry, and
revocation checks decide a two-hop credential chain.

**V4 tests check-time cascade, not next-lookup:** a revoked parent invalidates the
child subtree in the same verification pass, when the chain is verified against
current revocation state.

## How the decision is made

Each AAE credential is mapped to a real APS delegation by [`verify.ts`](./verify.ts):

- `mandate.actions[]` → APS `scope` tokens
- `validity.not_before` / `validity.not_after` → APS `notBefore` / `expiresAt`
- `validity.revocation_check.status == "revoked"` → APS `cachedRevocationState` at check time
- keys are generated per DID so `child.delegatedBy == parent.delegatedTo` (the chain link),
  signed with the SDK's own `canonicalize` + `sign`

The chain is then decided with the **shipped** primitives from
`agent-passport-system` (built `dist`):

- `verifyDelegation`: signature, expiry, `notBefore`, revocation (from supplied state), depth
- `scopeCovers`: monotonic narrowing (`child_scope ⊆ parent_scope`)

The verifier cascades root→leaf: an expired or revoked **ancestor** rejects the whole
chain even when the child hop is independently valid.

## Vectors

| Vector | Expected | Reason | AAE section | APS reason code | APS reference (existing) |
|---|---|---|---|---|---|
| **V1-narrowing-valid** | ACCEPT | child `[read]` ⊆ parent `[read, write]`, both windows current, not revoked | §2.2/2.3 scope | n/a | `tests/property-delegation.test.ts` (INV-2 Scope Monotonic Narrowing); `scopeCovers` |
| **V2-widened-scope-reject** | REJECT | scope-widening: child `[read, write, delete]` ⊄ parent `[read]` (`child_scope ⊄ parent_scope`) | §6 attenuation/cycle | `SCOPE_WIDENING` | `tests/property-delegation.test.ts` (INV-2) and `tests/v2/delegation-escalation.test.ts` (`delegation_scope_expansion`); `subDelegate` raises `Scope violation: [..] not in parent scope [..]` |
| **V3-expired-parent-reject** | REJECT | parent `validity.not_after` in the past; an expired ancestor invalidates the subtree | §2.4 validity (temporal) | `DELEGATION_EXPIRED` | `tests/conformance/golden-fixtures/NEG-DELEGATION-EXPIRED.json`; `verifyDelegation` emits `Delegation expired` |
| **V4-revoked-parent-cascade-reject** | REJECT | parent `revocation_check` resolves to revoked; cascades to the subtree **at verification time** | §6.5 revocation | `DELEGATION_REVOKED` | `tests/conformance/golden-fixtures/NEG-STALE-REVOCATION.json`; `verifyDelegation` marks the node revoked from supplied revocation state |

## V4: check-time cascade (the important one)

In V4 the **child credential is fully valid on its own**: it narrows the parent
correctly, its window is current, and its own `revocation_check` is active. The chain
is rejected solely because the **parent** is revoked, and that decision is taken **when
the chain is verified**: the verifier consults revocation state during this pass and
rejects the subtree. This is the same semantics as
`tests/conformance/golden-fixtures/NEG-STALE-REVOCATION.json`: *"a verifier that ignores
[stale] revocation state would wrongly accept it."* It is **not** a next-lookup model
where the child stays usable until some later refresh; revoking the parent invalidates
the child immediately at check time.

## Run

```
npx tsx interop/aae-envelope/verify.ts
# or
npm run verify:aae-envelope
```

The runner walks all four vectors, maps each to an APS delegation chain, runs the
shipped verifier, and asserts the expected result + reason code per vector. Exit code is
non-zero if any vector's actual decision differs from its AAE-stated expectation.

> Convention note: this repo's fixtures use `tsx` runner scripts (see
> `fixtures/composition/*/verify.ts`), not vitest, so this runner follows that pattern.
> It is a real load-adapt-verify-assert test of the shipped APS verifier.
