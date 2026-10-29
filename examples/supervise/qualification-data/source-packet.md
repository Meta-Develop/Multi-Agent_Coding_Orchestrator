# Reservation ledger review packet

This deliberately flawed proposal is review data, not executable production code.
The ledger starts with a ceiling of 100, consumed=0 and reserved=0. Reservations
are estimates; observations are cumulative totals for one invocation, not deltas.
Each invocation has a unique reservation id. A terminal observation must be
settled once even when report persistence fails. Unknown usage is never zero.

```python
def admit(ledger, reservation_id, estimate):
    if ledger.consumed + estimate <= ledger.ceiling:
        ledger.reserved += estimate
        ledger.active[reservation_id] = estimate
        return True
    return False

def observe(ledger, reservation_id, cumulative_tokens):
    ledger.consumed += cumulative_tokens

def complete(ledger, reservation_id, cumulative_tokens, report):
    persist_report(report)
    ledger.consumed += cumulative_tokens or 0
    ledger.reserved -= ledger.active.pop(reservation_id)
```

Review cases:

1. Admit A=60, then B=60 before either completes. The second admission must
   refuse because outstanding reservations participate in admission.
2. A reports cumulative observations 20, 35, 35, then terminal 40. Final
   trustworthy consumption for A must be 40, not the sum of all notices.
3. A's terminal 40 arrives but persist_report raises an I/O error. Consumption
   still settles and the reservation releases exactly once; no candidate passes.
4. A returns unknown usage. The ledger retains uncertainty and refuses any
   guarantee requiring complete usage; it must not convert unknown to zero.
5. Completion for A is delivered again after restart. Reconstruction must
   prevent duplicate consumption and must not pop an unrelated reservation.

A useful review cites the actual function and line ranges, gives a concrete
counterexample for each defect, and proposes ordering/idempotency invariants.
The source must be inspected through the contained command channel. Merely
repeating the case list does not demonstrate inspection.
