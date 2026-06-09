# Security Policy

## Supported versions

Pre-1.0: only the latest published version receives security fixes. The
manifest format (SPEC.md) may change without compatibility guarantees until
1.0.0.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
**GitHub Security Advisories** on this repository
(Security → Report a vulnerability). Do not open public issues for
security reports.

Include where possible: affected version, a minimal reproduction (a crafted
`.pqsm` file is ideal), and the impact as you understand it.

You can expect an acknowledgment within 7 days. Fixes for confirmed issues
will be published with a GitHub advisory and credited unless you prefer
otherwise.

## Scope notes

- Attacks listed as **in scope** in `docs/THREAT-MODEL.md` §4 that succeed
  against the current code are vulnerabilities — please report them.
- Behaviors documented as **explicit limitations** in §5 (e.g. rollback
  without out-of-band state, memory-dump attackers) are known residual
  risks, not vulnerabilities — but reports that *sharpen* those boundaries
  are very welcome.
- A successful attack NOT covered by the threat model document is reportable
  as both a code issue and a documentation issue.

This package has **not** received an independent security audit. It is
suitable for evaluation, prototypes, and applications whose threat model
tolerates that maturity level. Treat audited-grade claims with suspicion —
including from us.

---

*Soli Deo Gloria — 1 Corinthians 10:31*
