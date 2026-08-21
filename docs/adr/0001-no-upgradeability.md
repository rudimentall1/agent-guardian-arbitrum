# ADR-0001: AgentRegistry is not upgradeable

## Status

Accepted (Gate 1).

## Context

Upgradeable proxies (transparent, UUPS, beacon) are the default reflex for
"what if we need to change this later." They also add a well-documented
class of bugs that has nothing to do with the registry's actual logic:
storage-layout collisions between implementation versions, uninitialized
implementation contracts, `delegatecall`-based privilege confusion, and a
much larger review surface for anyone auditing the authorization boundary.

`AgentRegistry` is intentionally small: it answers one question
(`isActiveAgent`) and exposes four state-changing entry points. Nothing in
its logic is expected to need in-place mutation, and financial authority
itself never lives here — it lives in the Execution Guard (a later gate),
which is a separate, purpose-built contract.

## Decision

`AgentRegistry` has no proxy, no `initialize()` function, and no admin
upgrade path. If the identity/lifecycle model needs to change, the
protocol deploys a new registry with its own EIP-712 domain
(`name`/`version`/`verifyingContract` all change), and the Execution Guard
is pointed at the new registry address. Existing registrations in the old
registry are not migrated automatically — a deliberate choice, since
automatic migration would mean the new contract inherits trust decisions
(which agents are "active") made under a different contract's logic
without every affected owner explicitly re-confirming them.

## Consequences

**Positive:** no proxy storage-collision class of bug is possible here at
all, because there is no proxy. The deployed bytecode an owner or agent
signs against never changes after deployment — what you audit is what
runs, forever.

**Negative:** a bug found post-deployment in `AgentRegistry` itself
requires a new deployment and an explicit re-registration flow for every
agent, rather than an in-place fix. Given the contract's small size and
the adversarial test coverage in `contracts-test/AgentRegistry.test.ts`,
this is judged an acceptable trade for Gate 1.

## Alternatives considered

**UUPS proxy with owner-gated `upgradeTo`.** Rejected: introduces an
owner-key-compromise blast radius (a compromised deployer key could swap
in arbitrary logic) that is strictly worse than "a new contract needs a
new registration," for a contract this small.

**Beacon proxy shared across future registries.** Rejected for the same
reason, plus it would couple this gate's design to a beacon-migration plan
that doesn't exist yet.
