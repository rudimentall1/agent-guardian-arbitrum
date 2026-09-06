# ADR-0002: Monotonic per-agent nonce (not a bitmap)

## Status

Accepted (Gate 2).

## Decision

Each agent has exactly one nonce counter (`nextNonce[agent]`), starting at
0 and incrementing by 1 on every successful execution. At any point in
time exactly one nonce value is valid for a given agent: the current
counter value. Nonces cannot be skipped, reused, or executed out of
order.

## Alternatives considered

**Nonce bitmap (Permit2/Seaport-style).** A `mapping(address =>
mapping(uint256 => bool))` (or packed bitmap) lets the signer pick
arbitrary nonce values and consume them in any order, enabling several
independently-valid intents to be outstanding at once and executed
out-of-sequence or in parallel.

Rejected for v1, specifically because:

- It trades a trivially auditable invariant ("the only executable nonce
  is `nextNonce[agent]`, full stop") for a much larger state space
  ("any of 2^256 nonce values might already be consumed, in any
  combination"). For a contract whose entire job is being a
  hard-to-break authorization boundary, that trade is backwards this
  early — Gate 2's brief was explicit that correctness and auditability
  outrank flexibility for v1.
- Out-of-order execution is a feature agentic wallets may eventually
  want (e.g. submitting several independent intents that don't need to
  land in a specific order), but it is *not* a feature the current
  protocol spec asks for, and adding it "for later" now means carrying
  its extra complexity through every gate built on top of this one,
  including the reentrancy and replay reasoning in
  `docs/gate-2-execution-guard.md` — reasoning that is considerably
  simpler with a single monotonic counter.
- A bitmap doesn't remove replay risk, it relocates it: the security
  question changes from "is this the current nonce" to "has this
  specific nonce bit already been set", which is exactly as easy to get
  wrong (off-by-one on bit/word indexing, unbounded storage growth) while
  being harder to reason about at a glance.

**Timestamp- or block-number-derived nonces.** Rejected: couples
authorization to chain timing, which is exactly the kind of
non-deterministic input the protocol's core thesis (deterministic,
enforceable execution boundary) argues against.

## Security implications

- Strict ordering means an agent's operator must submit intents in the
  exact sequence they were signed. If intent N fails and its transaction
  reverts, N's nonce is not consumed (see the atomicity discussion in
  `docs/gate-2-execution-guard.md`) and the same intent can be retried;
  but a *different*, already-signed intent N+1 cannot execute before N
  succeeds or is replaced. This is a deliberate throughput/ordering
  trade-off in exchange for the smaller state space above.
- The counter is `uint256`, incremented with Solidity's default checked
  arithmetic. At `nonce == type(uint256).max`, incrementing reverts
  rather than wrapping to 0 — a wraparound would silently re-permit
  nonce 0, which is a genuine replay bypass, not a cosmetic edge case.
  Reaching `type(uint256).max` executions for a single agent is not
  reachable in practice, but "fails closed" is the correct choice of
  principle even for an unreachable case, and is covered by an explicit
  regression test (`attack 11: uint256 nonce boundary`).

## Future migration considerations

If out-of-order or parallel execution becomes a real product requirement,
it should be a new, explicitly-versioned execution path (e.g. a
`executeWithArbitraryNonce` variant backed by a bitmap, or a fully
separate guard contract with its own EIP-712 domain) rather than a
retrofit of this one. Mixing both models in the same nonce namespace
would reintroduce exactly the reasoning complexity this ADR avoids.
