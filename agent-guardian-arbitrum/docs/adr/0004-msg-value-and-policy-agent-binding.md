# ADR-0004: msg.value binding and explicit policy-agent ownership

## Status

Accepted (remediation gate, pre-Gate-4).

## Context

Gate 2 shipped `AgentExecutionGuard` with a signed `value` field bound
into the EIP-712 digest, and a `policyHash` field also bound into the
digest but never checked against anything. Gate 3 shipped `PolicyRegistry`
as a fully standalone contract with no relationship to `AgentExecutionGuard`
or to any specific agent. Reviewing both gates together, rather than each
in isolation, surfaced two gaps that neither gate's own adversarial
testing could have caught, because each gap only exists at the seam
between the two contracts (or between a contract and its caller) — not
inside either contract's own logic.

## Decision

### Fix 1: `msg.value` must equal the signed `value` field, exactly

`AgentExecutionGuard.execute` now reverts with `ValueMismatch(msg.value,
value)` unless `msg.value == value`.

**Why `policyHash` alone — or `value` alone — was insufficient:** binding
`value` into the EIP-712 signature (Gate 2) proves the *agent* authorized
moving that amount. It says nothing about what the *caller* of `execute`
actually attaches as `msg.value` in the transaction, because `value` and
`msg.value` were, before this fix, two independent numbers that happened
to share a name. A caller could send more ETH than signed for — with no
withdrawal path, that excess simply accumulated in the contract's balance
— or less, in which case `target.call{value: value}(data)` would attempt
to forward more than the contract just received, silently succeeding
anyway *if* the contract happened to be holding leftover balance from an
earlier mismatched call. That second case is the real danger: it means
one caller's overpayment becomes spendable by a completely unrelated,
later `execute` call, with no signature from anyone authorizing that
specific transfer of the stuck funds. Binding `msg.value` to `value`
closes this at the source: the contract's ETH balance is now
structurally guaranteed to return to exactly 0 after every successful
call (received-then-forwarded, atomically, every time), so there is never
a leftover balance for an unrelated call to spend.

### Fix 2: a policy must be explicitly bound to one agent, and `execute` must check it

`PolicyRegistry.createPolicy` now takes an `agent` parameter and records
it immutably alongside the mandate. `PolicyRegistry.resolvePolicyBinding
(policyHash)` exposes `(agent, active)` for that hash.
`AgentExecutionGuard.execute` now reverts with `PolicyAgentMismatch`
unless the policy that `policyHash` resolves to is bound to the intent's
own `agent`.

**Why `policyHash` alone was insufficient:** an EIP-712 signature over a
struct containing `policyHash` proves the *agent* committed to
referencing *that specific hash* — it says nothing about who that hash
was ever intended for. Before this fix, `PolicyRegistry` had no concept
of "this policy belongs to this agent" at all; a policy was just an
owner-created mandate with a hash. Nothing prevented Agent A's operator
from signing an intent that referenced a `policyHash` that happened to
correspond to a mandate created for Agent B — the signature would be
completely valid (Agent A really did sign exactly that struct), and nothing
downstream had any way to know that hash "wasn't theirs." A valid
signature only proves *what was signed*, never *what was intended* by
someone else's separate, unrelated on-chain action (creating the policy).
Those are different claims, and conflating them is exactly the kind of
authorization confusion this protocol's core thesis (`AI intelligence !=
authorization`, extended here to `a hash you can name != a hash you
own`) exists to prevent.

**Why policy ownership must be explicit, not inferred.** The alternative
to an explicit `agent` field would be inferring intent — e.g., "assume
the most recently created active policy for this signer's known owner is
the one they meant," or "allow any policy whose `owner` matches the
agent's `AgentRegistry` owner." Both are heuristics standing in for an
authorization decision. A wallet owner might legitimately want several
agents, each with a different, narrower mandate from the others — an
owner-scoped (rather than agent-scoped) binding would let Agent A borrow
Agent B's mandate simply because they share the same human owner, which
is precisely the cross-agent confusion this fix exists to prevent. An
explicit, immutable `agent` field recorded at policy-creation time is the
only version of this that doesn't require guessing what the owner meant.

### Why `AgentExecutionGuard` is responsible for final authorization

Neither fix could have been implemented correctly by `PolicyRegistry`
alone or by off-chain tooling alone:

- `PolicyRegistry` can *record* that a policy belongs to an agent, but it
  has no visibility into any specific transaction attempting to use that
  policy — it is a passive data store, correctly so (see ADR-0003: it
  holds no execution-time state on purpose). Only the contract that
  actually receives a signed intent and a `msg.value` — `AgentExecutionGuard`
  — is in a position to compare what was authorized against what is
  actually happening in the current call.
- Off-chain tooling (whatever constructs and submits `execute`
  transactions) could be trusted to only ever submit correctly-matched
  `value`/`msg.value` pairs and correctly-owned `policyHash` references —
  but "trust the caller to behave" is exactly the class of assumption
  this protocol's thesis rejects for financial authorization. The
  deterministic, on-chain execution boundary has to enforce both
  invariants itself, unconditionally, because a hostile or merely buggy
  caller is precisely what it exists to be safe against.

This is why both fixes live in `AgentExecutionGuard.execute` rather than
being pushed to `PolicyRegistry` (which correctly has no execution-time
role) or documented as an off-chain integration requirement (which
correctly is not enforceable on-chain if left there). `AgentExecutionGuard`
is, and must remain, the single place where "what was authorized" is
actually checked against "what is happening right now" — which is exactly
the protocol's stated core thesis, applied to two gaps that had slipped
past it.

## Alternatives considered

**For Fix 1:** allowing `msg.value >= value` and refunding the excess.
Rejected — adds a refund path (another external call, another reentrancy
surface, another failure mode to reason about) to fix a problem that
strict equality eliminates for free with a single comparison. There is no
legitimate reason for a caller to overpay a signed, exact-value intent;
if they do, that is a caller-side bug that should surface immediately as
a revert, not be silently "fixed" by the contract.

**For Fix 2:** checking policy ownership against the agent's `AgentRegistry`
*owner* instead of the agent's own address directly. Rejected — see "why
policy ownership must be explicit" above; owner-scoped sharing across an
owner's multiple agents is a real feature some product might eventually
want, but it must be an explicit, opt-in design (e.g. a policy that
names a *set* of permitted agents, or a wallet-owner-level default
mandate), not the accidental default of checking the wrong field.

## Consequences

- `PolicyRegistry.createPolicy`'s signature changed (added `agent`
  parameter) and `AgentExecutionGuard`'s constructor changed (added
  `policyRegistry` parameter) — both are breaking changes to Gate 2 and
  Gate 3 as originally shipped on their respective branches. This is
  accepted because both gates were still pre-`main`, unreviewed branches
  at the time of this remediation — exactly the point at which fixing an
  interface is cheap.
- Every `execute` call now requires a real, active, correctly-bound
  policy to exist for the intent's agent — there is no "no policy"
  bypass. This is a stricter requirement than Gate 2 originally shipped
  (where `policyHash` was accepted but never checked), and is a
  deliberate tightening: an intent with no meaningful policy binding is
  now rejected rather than silently permitted.
- Full mandate-content enforcement (`maxTxValue`, allowed
  targets/selectors, `dailyLimit`, `approvalThreshold`) is still not
  checked by `AgentExecutionGuard` — only that the *identity* of the
  referenced policy is legitimate for this agent. This is intentionally
  narrower than full Gate 4 integration; see
  `docs/gate-remediation-msg-value-policy-binding.md`.
