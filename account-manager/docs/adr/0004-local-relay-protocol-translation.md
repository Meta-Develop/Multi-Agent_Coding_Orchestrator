# 0004. Local relay with protocol translation

- **Status**: Accepted
- **Date**: 2026-08-18

## Context

Account switching solves "which identity does this tool use". It does not solve
"this tool only speaks OpenAI's format, but my remaining quota is on an
Anthropic account". Most of these tools accept a base-URL override, which makes
a local endpoint speaking their dialect a viable way to close that gap.

This is also the feature with the largest security surface in the project: it is
the only component that opens a socket.

## Decision

Ship a local HTTP relay that accepts OpenAI, Anthropic, and Gemini dialects on
distinct path prefixes and translates between them. It binds to `127.0.0.1` by
default. A non-loopback binding is rejected unless an authentication token is
configured — enforced in `RelayConfig::validate`, with tests.

## Consequences

- Any tool honouring a base-URL override can reach any account the application
  holds, which is what makes quota-aware routing (`FR-7`) possible at all.
- Translation is a pure function of `(from, to, body)` with no I/O, so it is
  golden-file testable — the highest-value test surface in the project.
- Distinct path prefixes per dialect mean a malformed body yields a clear 400
  rather than being silently reinterpreted as another vendor's schema.
- **Cost**: three dialects means three pairwise translations in each direction,
  each with streaming, tool calls, and multi-part content. This is the largest
  single body of work in the roadmap, which is why it is M5 and not M2.
- **Cost**: capability mismatches have no good answer. A reasoning budget with no
  counterpart is mapped or rejected, never silently dropped — a silently dropped
  field produces a subtly wrong response the user cannot debug.
- **Cost**: an open socket is reachable by every process on the host. The
  loopback default and the token requirement are the mitigation, and they are
  enforced in code rather than documented as advice.

## Alternatives considered

- **No relay; switching only.** Much smaller and safer. Rejected because it
  leaves the quota problem — the actual daily pain — unsolved, and rules out
  routing entirely.
- **Sniffing the dialect from the request body.** Rejected: the formats overlap
  enough to misdetect, and a misdetection sends a user's prompt to the wrong
  vendor.
- **Reusing an existing open-source proxy.** Rejected: the relay must resolve
  accounts through this application's credential store and router. That coupling
  is the feature, and it is not something an external proxy can provide without
  being handed the credentials — which defeats `0003`.
