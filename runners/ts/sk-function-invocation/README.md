# SK function-invocation filter conformance runner

A thin runner that models the Semantic Kernel function-invocation filter seam
and proves one property: the invocation path cannot bypass the verifier. On any
negative vector the filter denies before the kernel function runs.

Related issue: semantic-kernel #13957.

## What it does

For each vector the runner recomputes the handle (action_ref) and decides
allow or deny, then runs the decision through a modeled filter seam. The kernel
function body executes only inside `next()`. A denial returns without calling
`next()`, so the function never runs and an observable denial is emitted first,
carrying the fixture id, the handle family, and a redacted mismatch reason.

The runner defines no new schema and no new primitive. It imports fixture
classes and asserts. Handle recompute reuses the suite's vendored JCS
canonicalizer (`runners/ts/canonicalize.ts`, extracted from
`agent-passport-system` `src/core/canonical-jcs.ts`) plus node `crypto`
SHA-256. Canonicalization and hashing are not reimplemented here.

## Fixture classes

Byte-level handle-correctness (recompute-drift):
- `giskard09/argentum-core` `examples/conformance/recompute-drift-v1/` (external, giskard09's).
- `fixtures/cross-stack/action-ref-v1-negatives/vectors.json` (ours, a second implementation of the same class).

Issuer-binding and scope-replay (near-miss):
- `giskard09/argentum-core` `examples/conformance/near-miss-v1/near-miss-v1.fixture.json` (external, giskard09's).

The external fixtures are vendored under `test-fixtures/argentum-core/`, pinned
to a commit SHA. See `test-fixtures/argentum-core/PROVENANCE.md`.

## The property

- Positive vector: recompute matches and binding holds, so `next()` is called and the function runs.
- Negative vector: a recompute mismatch, a timestamp grammar violation, an ambiguous issuer binding, a rescoped replay, or a semantic drift. The filter denies before `next()`, the function does not run, and a denial is recorded.

The recompute is genuine. The runner computes the digest from the vector bytes
and compares to the committed value; it never trusts the committed value as-is.

Run:

```bash
npx tsx runners/ts/sk-function-invocation/verify.ts
```

Exit 0 on full pass, 1 on any bypass.

## Mapping to a Semantic Kernel .NET filter

The seam mirrors `IFunctionInvocationFilter`. The filter runs the recompute
check first and short-circuits by not calling `next` when the check fails. The
TS `functionInvocationFilter(verdict, ctx, next)` in `runner.ts` is the same
shape:

```csharp
public sealed class ActionRefAdmissionFilter : IFunctionInvocationFilter
{
    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, Task> next)
    {
        var verdict = AdmissionVerifier.Verify(context); // recompute handle, check binding
        if (!verdict.Allow)
        {
            // Short-circuit: next is never awaited, so the kernel function does not run.
            context.Result = new FunctionResult(context.Function, verdict.Denial);
            return;
        }

        await next(context);
    }
}
```

The C# side is the shape only. The conformance property is exercised by the TS
runner against the shared fixtures.
