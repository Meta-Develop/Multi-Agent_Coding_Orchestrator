This is an offline JSON-lines app-server peer for the authored nested Worker
controller tests. It performs local source edits, records the actual command and
timestamps in the precreated Worker journal, and supplies deterministic model
and usage messages. It never contacts a provider or launches another agent.

The test-only Rust runner replaces provider executable and account preflight.
It uses the production app-server driver, authenticated request endpoint,
ExternalCodex containment profile, descriptor capture, journal capture, budget
settlement, frozen-yield controller and final parent collection. Real process
containment evidence is required; Python is not admitted as a production Codex
executable. The active cancellation case starts an ordinary sleeping descendant
to exercise cancellation and process-tree drain.

The authored fixture plan is validated and gives the two Workers disjoint source
paths. The initial parent has the Worker request tool and read-only source; the
final parent has read-only source and no request tool or Worker journal capability.
Both coordination turns attempt a source write and require the outer sandbox to
reject it. The receipt replay case discards an acknowledgment at the peer and
resubmits the same request; separate IPC tests cover a dropped socket response.

These tests stop at final parent collection. They do not qualify provider
executable preflight, independent review-lens dispatch, or crash recovery launches.
