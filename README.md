# SolGuard

Static scanner for missing validation in Solana / Anchor programs.

## Why this exists

Solana programs receive **every account from the caller**. The caller supplies the
accounts; the program must prove each one is what it thinks it is. Most
exploitable Solana bugs are not exotic cryptography — they are a missing check:

- an owner check
- a signer check
- a PDA derivation check
- an unchecked arithmetic operation on a balance

SolGuard reads Rust source and flags those missing checks so a human auditor can
triage them quickly. It is a **triage aid**, not a substitute for review. It has
false positives by design: a missed check is worse than a spurious warning.

## Install

No dependencies. Python 3.9+.

```bash
git clone <your-repo-url> solguard
cd solguard
```

## Usage

```bash
python3 solana_audit_scanner.py path/to/programs       # plain text
python3 solana_audit_scanner.py path/to/programs --min high
python3 solana_audit_scanner.py path/to/programs --json
python3 solana_audit_scanner.py path/to/programs --markdown > report.md
```

Exit codes: `0` = clean, `1` = findings at or above `--min`, `2` = error.
Wired into CI, a non-zero exit fails the build.

## Rules

| ID | Severity | What it catches |
|---|---|---|
| SG-001 | high | `UncheckedAccount` accepted without manual validation |
| SG-002 | high | Raw `AccountInfo` in an `#[derive(Accounts)]` struct |
| SG-003 | high | PDA-like account with no `seeds` constraint |
| SG-004 | high | Authority-like field not proven to be a signer |
| SG-005 | high | Unchecked arithmetic on a financial quantity |
| SG-006 | medium | `as` cast that may silently truncate |
| SG-007 | medium | Direct lamport balance manipulation |
| SG-008 | medium | `unwrap()` on an arithmetic result |
| SG-009 | medium | Account closed without validating rent receiver |
| SG-010 | medium | Privileged instruction with no explicit guard |
| SG-011 | medium | Unsigned cross-program invocation |
| SG-012 | low | `remaining_accounts` used without validation |

## Example

```bash
$ python3 solana_audit_scanner.py samples/vulnerable_vault.rs

SolGuard - Solana / Anchor validation scanner
files scanned : 1
findings      : 36
  high=22  medium=13  low=1

[HIGH    ] SG-005 Unchecked arithmetic on a financial quantity  (7)
    samples/vulnerable_vault.rs:27
      state.total_deposits = state.total_deposits + amount;
    ...
```

A full generated report is in `11-solguard-demo-report.md`.

## Limitations

- Regex-based, not a Rust parser. It will miss checks hidden behind helper
  functions and macros it does not understand.
- Rules SG-003, SG-004 and SG-005 are heuristic and will produce false
  positives on well-written code. Treat every finding as "go look", not
  "this is a bug".
- It does not analyse business logic, economic design, or oracle behaviour.
- It reads one file at a time; cross-file and cross-program reasoning is out
  of scope.

## Roadmap

- [ ] Severity tuning via a config file
- [ ] `seeds` / `bump` consistency check against `find_program_address` calls
- [ ] Anchor IDL-driven analysis instead of regex
- [ ] SARIF output for GitHub code scanning

## Author

Wilson Huo — 25 years of production software engineering.
Cryptography, virtual wallets, P2P networking, video encoding and parsers.
