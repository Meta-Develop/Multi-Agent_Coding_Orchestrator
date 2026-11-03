# MACO versus manual leaf distribution

MACO enters production use only when a paired comparison shows it is not worse
than the current manual method on the quality gates below, and better on cost
or wall-clock by the margin in the decision rule. The manual method is a root
orchestrator that hand-writes prompts, dispatches headless implementation and
review leaves, and merges only after independent review and hosted CI.

This protocol reuses `maco evaluation` for the MACO arm's held-out checks,
usage, and coordination-token projection. It does not reuse the fake model-mix
result documents. Those documents stay ineligible for production or default
decisions. A model-mix pilot compares lanes inside MACO. It is not this gate.
No live comparison has been run under this protocol.

## Arms

Both arms start from the same full git commit, the same task text, and the
same pinned model and effort for the implementation lane and the independent
review lane. Arms run in isolated worktrees. Reviewers of one arm do not see
the other arm's diff. The arm order is fixed before the first task and stays
fixed for the sample. Neither arm may adopt the other's patch.

The manual arm is the root orchestrator dispatching headless leaves
(implementation, independent review, fix rounds) and merging after review and
hosted CI. The root session is not a MACO process. Its provider usage export
for that session is the coordination-token source. Leaf and reviewer usage are
separate and count toward total tokens, not toward coordination tokens.

The MACO arm is `maco supervise run` with those same lanes. When the task has
held-out commands, run it as one `maco evaluation experiment` cell so the
summary below is produced for that plan. The plan, limits, and pricing contract
are frozen before the first paid call. Commands that prepare a live cell
without authorizing one:

```bash
"$maco" evaluation experiment "$manifest" \
  --validate-only --provider-plan "$plan" --json
```

A paid cell uses the held-out real-provider invocation documented for
experiments. Offline validation creates no run and spends no provider tokens.
`production_eligible` on evaluation documents stays false. This protocol is the
production decision. Those booleans are not.

## Task set

Use bounded repository issues in one stratum: one issue, one acceptance set,
and a change that fits in a single module or a pre-registered file list.
Exclude credential, desktop, and owner-gated work, and exclude campaigns that
span many issues. Draw the list from open issues before either arm starts.
Publish the list, the base commit, the model lanes, the primary economic
endpoint, and the margin before the first paid call. Do not add or drop tasks
after seeing results. A replacement list is a new protocol run.

The minimum complete sample is 12 tasks. Twelve is the smallest paired sample
at which a tie-free exact two-sided sign test at 5% can pass with two
discordant pairs (10 of 12 in one direction; three disagreements do not).
Smaller tie-free samples pass only with fewer disagreements: 9, 10, or 11
still pass with one disagreement; 6, 7, or 8 pass only when every pair agrees;
fewer than 6 cannot pass. One extra disagreement past those limits voids the
sample. That arithmetic is for a tie-free effective n. Ties and indeterminate
pairs lower the effective n and are not a smaller-n test. Analyze the 12 once.

A task is complete only when both arms have a merge-ready outcome or a recorded
gate failure, and every metric below is known or explicitly unknown. An unknown
quality, cost, time, or coordination figure fails closed. It is not dropped and
it is not treated as zero.

## Metrics

Record one private row per task per arm. Do not put secrets, account material,
or raw transcripts in the row. The fields are:

| Metric | MACO arm | Manual arm |
| --- | --- | --- |
| Wall-clock to merge-ready | Clock from arm start through the final reviewed head whose required hosted CI is green. `wall_time_ms` on the evaluation cell is supervise duration only. Record both. Do not subtract CI queue time. | Same clock rule. |
| Total tokens and reported cost per accepted change | `aggregate_reported_usage` and `aggregate_reported_cost_usd` when usage is complete and `priced_cost_complete` is true. Sum every attempt, including rejected ones. Divide by the count of changes accepted by both arms. | Provider usage and reported cost for the root, leaves, and reviewers, same inclusion rule. |
| Coordination tokens | `profile_summaries[].coordination_tokens` on the executed summary, or `coordination_token_observation` on `supervisor-final.json` `role_usage`. | Root session tokens only. |
| Review rejection and rework rounds | Count of independent review verdicts that are not a clean accept, plus the fix round that followed each. | Same count from the root's review log. |
| Hosted CI failures after review | Required CI conclusions that failed on a head that already had a review, before the merge-ready head. One red workflow conclusion is one failure. | Same. |
| Defects found later | Defects opened against the merged change inside a window declared before the run (14 days, unless the sheet names a shorter checkpoint). | Same window. |

`coordination_tokens.aggregate_total` is the own provider usage of the
supervising agent plus a process-observed child orchestrator. A missing child
orchestrator counts as zero. Worker, researcher, gate-classifier, auditor, and
review-lens tokens stay in the total and out of this field.

The supervisor row in `role_usage` is `supervisor_aggregate`: a rollup of
launched children, already included in `aggregate_reported_usage`. The
projection refuses that row. `supervisor_aggregate_not_own_usage` means the
coordination total is unknown. Do not add the rollup to child-orchestrator
tokens. `supervisor_usage_not_retained` likewise stays unknown. Synthetic fake
usage is not live coordination evidence.

An explicit zero is `observation: process_observed` with input, output, and
total all zero, meaning that process made no provider call. The current
supervisor report does not emit that shape. It writes the child rollup into the
supervisor row (`src/supervise/reporting.rs`). Until a report carries
process-observed own usage without removing the child rollup from
`total_usage`, every current MACO cell has unknown coordination tokens.
Replacing the aggregate in place would also break execution telemetry, which
treats `supervisor_aggregate` as the completed total-economics observation.

The harness does not count review rounds. Fake-result `churn_count` is not
rework, and scoring already refuses to substitute churn for a retry/rework
observation. Accepted and rejected outcome counts are not round counts. Hosted
CI failures and later defects are outside the supervisor report. Those three
stay on the private sheet. `coordination_tokens_not_projected` on an older
summary means that file was written before this field existed. Recompute the
summary. Do not treat the default as zero.

## Decision rule

MACO is better only when all of the following hold:

1. Quality is not worse. For every task the manual arm passes, the MACO arm
   passes the same gates: clean accept on the final head, required hosted CI
   green on that head, the same held-out commands when the task has them, and
   no later defect in the declared window. A task both arms fail is not a win.
   If the manual arm passes and MACO does not, MACO is worse. Stop.
2. The later-defect window has closed. An open window withholds the decision.
3. Coordination totals are known on every MACO row in the both-accepted subset.
   Unknown coordination cannot win and cannot be scored as zero.
4. At least 12 tasks are accepted by both arms and have known cost, token, and
   merge-ready time. A known zero is not unknown. The primary economic
   endpoint is fixed before the first paid call and is the only source of
   signs and of the 1.25 median. It is exactly one of total tokens per
   accepted change, reported cost per accepted change, or wall-clock to
   merge-ready. For each both-accepted task, compare that task's manual value
   with its MACO value on this endpoint. The ordered sample has 12 values and
   its median is at least 1.25. For an even count the median is the arithmetic
   mean of the two central ordered values. The same endpoint's sign test must
   also pass. The other two of these three do not supply signs.
   Compare known token and cost numbers without dividing by zero:
   - Both positive: the ordered value is manual divided by MACO.
   - Both zero: the arms are equal. The ordered value is 1. The pair is a
     tie. It is not unknown.
   - MACO zero and manual positive: the pair is a MACO sign and orders above
     every finite value.
   - Manual zero and MACO positive: the ordered value is 0 and the pair is a
     manual sign.
   A recorded wall-clock of zero is indeterminate. It is not a token or cost
   zero.
   A MACO sign is a finite value >= 1.25, or the MACO-zero case above. A
   manual sign is a finite value < 1, including 0. A tie is both-zero or a
   finite value in [1, 1.25). Any other unscored pair is indeterminate. Ties
   and indeterminate pairs are dropped from the sign test. Effective n is the
   number of signs that remain. The null is that each decisive sign is equally
   likely. The gate is the exact two-sided sign test at 5% with the MACO
   count strictly larger. Tie-free effective n of 12 passes only with at least
   10 MACO signs. Six values of 0.9 and six of 1.6 have median 1.25 and
   sign-test p = 1, so they are not a win. Effective n below 12 does not meet
   this gate.
5. The other two of these three endpoints each have 12 ordered values and a
   median at least 1, under the same zero and indeterminate rules. Token and
   cost samples use the zero comparison above. A zero wall-clock leaves that
   sample short of 12. A cheaper arm that is slower, or a faster arm that
   costs more, is not better. Ratios of 2 on tokens, 2 on cost, and 0.5 on
   wall-clock in all 12 tasks are not a win.
6. The median hosted-CI failure count for MACO is not higher than the manual
   median. The median non-clean review rounds for MACO is not higher than the
   manual median.

Anything else, including a mixed sample, a 1.25 median with a failed sign
test, or a significant sign test that misses the 1.25 margin, is "not shown".
Effective n below 12 is "not shown". Do not add tasks to the same run to cross
the margin or to replace ties. Pareto status, qualified-accepted fraction, and
fake fixture scores do not satisfy this rule.

## Evidence

Keep the private run directory, the supervisor final report, the executed
summary, the frozen manifest and plan digests, the base commit, and the CI
conclusions for each head. The manual arm keeps the root usage export and the
review log beside those CI conclusions. Redact secrets before the sheet is
copied anywhere else. Publication of either arm's patch is a separate gate and
is not itself a pass.

## What remains outside this repository

Running the 12 paired tasks spends provider quota and needs a human merge
decision. This document and the coordination-token projection do not authorize
that run and do not record a winner.
