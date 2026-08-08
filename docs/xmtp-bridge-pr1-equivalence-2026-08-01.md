# XMTP bridge PR #1 equivalence report

Date: 2026-08-01

## Conclusion

PR #1 at `27a009010502430dcd745d425180d612ee0998ac` is fully retained by
the draft #2, #4, #3 stack. Closing PR #1 will not discard a commit or a file
from the reviewed baseline because the PR #1 head is a direct ancestor of all
three slice heads. The later slices move conformance code into production
packages and add trust, persistence, and dormant runtime wiring. They do not
revert the PR #1 activation guards or the server-side `shouldPush` filter.

Closure remains a GitHub state change. It should occur only after this report
is present on the remote draft stack and the lane's Git write gates pass.

## Exact fleet

| PR | Branch | Head | Role |
| --- | --- | --- | --- |
| #1 | `feat/hytch-phase0-apns-metadata` | `27a009010502430dcd745d425180d612ee0998ac` | Original hardening baseline |
| #2 | `feat/xmtp-bridge-a9-trust-20260801` | `59ce02c687bcfd86e58f1aefcb6765c23cf9d3d6` | Trust boundary |
| #4 | `feat/xmtp-bridge-a9-api-persistence-20260801` | `b4bbf04d5781512a9124b5508f8a3a5ff76b1850` | API and durable CAS state |
| #3 | `feat/xmtp-bridge-a9-runtime-wiring-20260801` | `0ecdbe3e364ae27ca22e3796d6785ae5042bb34a` | Dormant runtime wiring |

At the time of the audit, both `origin/main` and `origin/dev` resolve to
`0b22838ede4d0b550a3ea2c8465446ed2ce02bc2`. PR #1 and #2 therefore start
from content-identical base branches.

## Mechanical proof

The following ancestry checks all returned exit status 0:

```text
git merge-base --is-ancestor 27a0090 59ce02c
git merge-base --is-ancestor 59ce02c b4bbf04
git merge-base --is-ancestor b4bbf04 0ecdbe3
```

The resulting immutable commit chain is:

```text
origin/main and origin/dev
  -> 61be165 .. 27a0090  PR #1, 11 commits
  -> 59ce02c             PR #2 trust boundary
  -> b4bbf04             PR #4 API and persistence
  -> 0ecdbe3             PR #3 dormant runtime wiring
```

Git reports no whitespace errors across `origin/main..0ecdbe3`. No file added
by PR #1 is removed by the slice stack except
`internal/a9conformance/crypto/verdict.go`; its verdict implementation moves
to `pkg/a9trust/verdict.go` as part of the trust-boundary promotion. Git also
recognizes the conformance schema and crypto moves into `pkg/a9schema` and
`pkg/a9trust` with high similarity.

## Semantic coverage

| PR #1 domain | Carried by the slice stack |
| --- | --- |
| Docker/build hardening, CLI safety, Railway audit documentation | Retained by ancestry; PR #3 adds dormant A9 runtime configuration and documentation. |
| Mirrored A9 adapter artifact, schemas, positive vector, and 54 negative vectors | Retained byte-for-byte in `contracts/xmtp_push/a9_adapter/v1/`; #2 promotes the verifier into reusable trust and schema packages. |
| Outer `shouldPush` enforcement and exact-period self-message suppression | Retained in `pkg/pushpolicy` and called before dispatch from `pkg/xmtp/common.go`; delivery implementations still require the one-use authorization. |
| Secure routing vault and migrations 00006 through 00011 | Retained by ancestry; #4 appends migration 00012 and A9 CAS stores without renumbering or modifying the earlier migrations. |
| APNS and Welcome activation hard-closes | Retained. PR #3 adds A9 configuration but does not remove either hard-close. |
| Listener, API, retention, incident-access, and privacy hardening tests | Retained by ancestry; the three slices add focused A9 trust, storage, and runtime tests. |

The files touched by both PR #1 and later slices were reviewed as the only
places where a semantic override could occur. The later change to
`pkg/pushpolicy/policy.go` only binds the new A9 route snapshot into the
single-use authorization fingerprint. Its conversation eligibility logic is
unchanged. API changes close legacy mutation handlers when A9 is selected.
Runtime changes add fail-closed A9 prerequisites and keep
`WelcomeEnabled: false` in store construction.

## Required dormant invariants

- `BRIDGE_WELCOME_ENABLED=true` is rejected by
  `welcomeRuntimeConfigurationValid`; the runtime QA composition sets it to
  `false` and verifies the container environment.
- `APNS_ENABLED=true` is rejected before database or provider
  initialization; the runtime QA composition sets it to `false`.
- `BRIDGE_A9_ENABLED=false` is the runtime QA default. No A9 trust material is
  accepted while it is false.
- Conversation delivery still requires an explicit outer
  `shouldPush=true`, an active non-silent route, a usable exact-period HMAC
  key, and a non-self sender HMAC. False, missing, stale, malformed, and
  self-originated cases resolve to zero authorization.
- Welcome remains unavailable in the runnable configuration. The harness
  records the Welcome case as denied.
- The stack remains draft-only and is not evidence for deployment, APNS,
  Welcome, Railway, TestFlight, or production activation.

## Closure disposition

The D-BR1 decision authorizes closure once equivalence evidence exists. This
report satisfies the semantic and ancestry evidence requirement. After the
report reaches the remote draft stack and the write gates are approved, close
PR #1 with a link to this report and leave PRs #2, #4, and #3 as drafts.
