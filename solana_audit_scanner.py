#!/usr/bin/env python3
"""
SolGuard - Static scanner for missing validation in Solana / Anchor programs.

Purpose
-------
Solana programs receive *every* account from the caller. The caller supplies the
accounts; the program is responsible for proving each one is the account it
thinks it is. Most exploitable Solana bugs are not exotic cryptography - they
are a missing check: an owner check, a signer check, a PDA derivation check, or
an unchecked arithmetic operation.

SolGuard reads Rust source and flags those missing checks so a human auditor can
triage them fast. It is a triage aid, not a substitute for review.

Usage
-----
    python3 solana_audit_scanner.py <path>            # file or directory
    python3 solana_audit_scanner.py <path> --json
    python3 solana_audit_scanner.py <path> --markdown
    python3 solana_audit_scanner.py <path> --min medium

Exit codes: 0 = no findings at or above --min, 1 = findings found, 2 = error

Author: Wilson Huo
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    why: str
    fix: str


RULES: dict[str, Rule] = {
    "SG-001": Rule(
        "SG-001", "high", "UncheckedAccount accepted without manual validation",
        "UncheckedAccount is an escape hatch: Anchor performs no owner, "
        "discriminator, or signer check. If the handler does not validate it "
        "manually, a caller can pass any account the program will then trust.",
        "Validate owner and key manually, or replace with Account<'info, T> "
        "so Anchor applies discriminator and owner checks.",
    ),
    "SG-002": Rule(
        "SG-002", "high", "Raw AccountInfo in an Accounts struct",
        "AccountInfo carries no type information. Nothing about it is checked. "
        "This is the most common source of account-confusion bugs on Solana.",
        "Use Account<'info, T>, Signer<'info>, or SystemAccount<'info> so the "
        "type system enforces the checks.",
    ),
    "SG-003": Rule(
        "SG-003", "high", "PDA-like account without a seeds constraint",
        "An account whose name suggests a program-derived address is accepted "
        "without proving the address was derived from the expected seeds. "
        "A caller can substitute a different, attacker-created account.",
        "Add seeds = [...] with bump, and verify the bump is stored or "
        "re-derived with find_program_address.",
    ),
    "SG-004": Rule(
        "SG-004", "high", "Authority-like account is not proven to be a signer",
        "A field named like an authority is neither typed Signer<'info> nor "
        "constrained with is_signer. Any caller can pass an arbitrary pubkey.",
        "Type it as Signer<'info>, or add constraint = <field>.is_signer.",
    ),
    "SG-005": Rule(
        "SG-005", "high", "Unchecked arithmetic on a financial quantity",
        "Arithmetic on balances, amounts, fees or shares without checked_* or "
        "saturating_* can overflow or wrap, producing incorrect accounting that "
        "an attacker can usually turn into a withdrawal.",
        "Use checked_add / checked_sub / checked_mul / checked_div and handle "
        "the None case explicitly.",
    ),
    "SG-006": Rule(
        "SG-006", "medium", "Integer cast may silently truncate",
        "`as` casts in Rust wrap or truncate rather than failing. Casting a "
        "larger integer down can turn a large value into a small one.",
        "Use try_into() and propagate the error, or range-check before casting.",
    ),
    "SG-007": Rule(
        "SG-007", "medium", "Direct lamport balance manipulation",
        "Moving lamports by hand bypasses the account's own accounting and can "
        "desynchronise real balance from recorded balance, or break rent rules.",
        "Prefer system_program::transfer via CPI, or update internal "
        "accounting in the same step.",
    ),
    "SG-008": Rule(
        "SG-008", "medium", "unwrap() on an arithmetic result",
        "unwrap() on a checked_* result panics instead of returning an error. "
        "A panic in a financial path is a denial of service on user funds.",
        "Return the error with ok_or(ErrorCode::Overflow)? instead.",
    ),
    "SG-009": Rule(
        "SG-009", "medium", "Account closed without validating rent receiver",
        "Closing an account sends its rent lamports to a receiver. If the "
        "receiver is not validated, rent can be redirected.",
        "Constrain the receiver explicitly and confirm it is the intended "
        "destination.",
    ),
    "SG-010": Rule(
        "SG-010", "medium", "Privileged instruction without an explicit guard",
        "An instruction whose name suggests a privileged action contains no "
        "require!, assert!, or has_one guard in its body.",
        "Add an explicit authority check with require! and test the failure "
        "path.",
    ),
    "SG-011": Rule(
        "SG-011", "medium", "Unsigned cross-program invocation",
        "invoke() (as opposed to invoke_signed) cannot act with program signer "
        "authority. If the callee expects the program as signer, this silently "
        "fails - or worse, passes with the wrong authority.",
        "Use invoke_signed with seeds derived from this program, and verify "
        "the target program id is hard-coded.",
    ),
    "SG-012": Rule(
        "SG-012", "low", "remaining_accounts used without validation",
        "Accounts passed through ctx.remaining_accounts are supplied by the "
        "caller and are not type-checked by Anchor.",
        "Validate each remaining account's key and owner before use.",
    ),
}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    snippet: str
    detail: str = ""
    fields: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        r = RULES[self.rule]
        out = {
            "rule": self.rule,
            "severity": self.severity,
            "title": r.title,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "detail": self.detail,
            "why": r.why,
            "fix": r.fix,
        }
        out.update(self.fields)
        return out


# ---------------------------------------------------------------- parsing ----

AUTHORITY_HINTS = (
    "authority", "admin", "owner", "payer", "signer", "creator", "manager",
    "operator", "guardian", "updater", "keeper",
)
PDA_HINTS = (
    "vault", "pda", "config", "state", "pool", "escrow", "stake", "position",
    "receipt", "ledger", "treasury", "auth", "global",
)
FINANCIAL_HINTS = (
    "amount", "balance", "lamports", "fee", "total", "shares", "supply",
    "price", "deposit", "withdraw", "locked", "reward", "debt", "collateral",
    "principal", "interest", "rate", "weight", "score", "value", "reserve",
)
PRIVILEGED_HINTS = (
    "set_", "update_", "admin", "withdraw", "mint", "burn", "pause", "config",
    "init", "close", "upgrade", "emergency", "transfer_",
)
NUMERIC_TYPES = ("u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128", "usize")

FIELD_RE = re.compile(r"^\s*pub\s+(\w+)\s*:\s*(.+?),?\s*$")
ATTR_RE = re.compile(r"^\s*#\[account\s*(\(.*\))?\s*\]")
STRUCT_OPEN_RE = re.compile(r"pub\s+struct\s+(\w+)\s*(?:<\s*'info\s*>)?\s*\{")
FN_RE = re.compile(r"\bpub\s+fn\s+(\w+)\s*\(")
ARITH_RE = re.compile(r"[+\-*/]=") 
CAST_RE = re.compile(r"\bas\s+(u8|u16|u32|u64|u128|i8|i16|i32|i64|i128|usize)\b")
CHECKED_RE = re.compile(r"checked_\w+|saturating_\w+|wrapping_\w+")
GUARD_RE = re.compile(r"\brequire!|\bassert!|\brequire_eq!|\brequire_keys_eq!|\brequire_gt!")


def strip_comment(line: str) -> str:
    out = []
    in_str = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        if not in_str and line[i:i + 2] == "//":
            break
        out.append(c)
        i += 1
    return "".join(out)


def extract_accounts_structs(lines: list[str]) -> list[dict]:
    """Return [{name, line, fields:[{name,type,attr,line}]}] for Accounts structs."""
    structs = []
    i = 0
    n = len(lines)
    while i < n:
        if "#[derive(Accounts)]" in lines[i]:
            j = i + 1
            while j < n and STRUCT_OPEN_RE.search(lines[j]) is None:
                j += 1
            if j >= n:
                break
            m = STRUCT_OPEN_RE.search(lines[j])
            struct_name = m.group(1)
            struct_line = j + 1
            depth = lines[j].count("{") - lines[j].count("}")
            body: list[str] = []
            k = j + 1
            while k < n and depth > 0:
                body.append(lines[k])
                depth += lines[k].count("{") - lines[k].count("}")
                k += 1
            fields = parse_fields(body, j + 1)
            structs.append({"name": struct_name, "line": struct_line, "fields": fields})
            i = k
        else:
            i += 1
    return structs


def parse_fields(body: list[str], offset: int) -> list[dict]:
    """Group attribute lines with the field line that follows them."""
    fields = []
    pending_attr = ""
    pending_attr_line = 0
    for idx, raw in enumerate(body):
        line = strip_comment(raw)
        lineno = offset + idx + 1
        if ATTR_RE.match(line):
            pending_attr = line.strip()
            pending_attr_line = lineno
            continue
        m = FIELD_RE.match(line)
        if m:
            fields.append({
                "name": m.group(1),
                "type": m.group(2).strip().rstrip(","),
                "attr": pending_attr,
                "attr_line": pending_attr_line,
                "line": lineno,
            })
            pending_attr = ""
    return fields


def function_bodies(lines: list[str]) -> list[dict]:
    """Crude brace-matched extraction of top-level-ish fn bodies."""
    fns = []
    i = 0
    n = len(lines)
    while i < n:
        m = FN_RE.search(lines[i])
        if m:
            name = m.group(1)
            start = i
            depth = 0
            body: list[str] = []
            j = i
            while j < n:
                depth += lines[j].count("{") - lines[j].count("}")
                if j > start:
                    body.append(lines[j])
                if depth == 0 and "{" in lines[j]:
                    pass
                j += 1
                if depth <= 0 and j > start + 1:
                    break
            fns.append({"name": name, "line": start + 1, "body": body, "body_offset": start + 1})
            i = j
        else:
            i += 1
    return fns


# ----------------------------------------------------------------- rules -----

def scan_structs(structs: list[dict], findings: list[Finding], path: str) -> None:
    for st in structs:
        for f in st["fields"]:
            ftype = f["type"]
            attr = f["attr"]
            fname_l = f["name"].lower()

            if ftype.startswith("UncheckedAccount"):
                findings.append(Finding(
                    "SG-001", RULES["SG-001"].severity, path, f["line"],
                    f"{f['name']}: {ftype}",
                    f"In #[derive(Accounts)] struct `{st['name']}`.",
                    {"struct": st["name"], "field": f["name"]},
                ))

            if ftype.startswith("AccountInfo"):
                findings.append(Finding(
                    "SG-002", RULES["SG-002"].severity, path, f["line"],
                    f"{f['name']}: {ftype}",
                    f"In #[derive(Accounts)] struct `{st['name']}`.",
                    {"struct": st["name"], "field": f["name"]},
                ))

            is_plain_account = (
                "Account<'info" in ftype
                and not ftype.startswith("Unchecked")
                and not ftype.startswith("AccountInfo")
                and not ftype.startswith("SystemAccount")
                and not ftype.startswith("Program")
                and not ftype.startswith("InterfaceAccount")
            )
            if is_plain_account and any(h in fname_l for h in PDA_HINTS):
                if "seeds" not in attr:
                    findings.append(Finding(
                        "SG-003", RULES["SG-003"].severity, path, f["line"],
                        f"{f['name']}: {ftype}",
                        f"Field looks like a PDA but `{st['name']}` declares no "
                        f"seeds constraint for it.",
                        {"struct": st["name"], "field": f["name"]},
                    ))

            if any(h in fname_l for h in AUTHORITY_HINTS):
                is_signer_type = ftype.startswith("Signer") or ftype.startswith("SystemAccount")
                if not is_signer_type and "is_signer" not in attr:
                    findings.append(Finding(
                        "SG-004", RULES["SG-004"].severity, path, f["line"],
                        f"{f['name']}: {ftype}",
                        f"Authority-like field in `{st['name']}` is not proven "
                        f"to be a signer.",
                        {"struct": st["name"], "field": f["name"]},
                    ))

            if "close" in attr and "receiver" not in attr and "close" in attr:
                findings.append(Finding(
                    "SG-009", RULES["SG-009"].severity, path, f["attr_line"] or f["line"],
                    attr or f"{f['name']}: {ftype}",
                    f"Close constraint on `{st['name']}.{f['name']}` - confirm "
                    f"the rent receiver is validated.",
                    {"struct": st["name"], "field": f["name"]},
                ))


def scan_lines(lines: list[str], findings: list[Finding], path: str) -> None:
    for idx, raw in enumerate(lines):
        lineno = idx + 1
        line = strip_comment(raw)
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()

        # SG-006 casts
        if CAST_RE.search(stripped):
            findings.append(Finding(
                "SG-006", RULES["SG-006"].severity, path, lineno, stripped[:120],
                "Integer cast found - confirm the source cannot exceed the target.",
            ))

        # SG-007 lamports
        if "try_borrow_mut_lamports" in stripped or "try_borrow_lamports" in stripped:
            findings.append(Finding(
                "SG-007", RULES["SG-007"].severity, path, lineno, stripped[:120],
                "Direct lamport access - confirm internal accounting stays in sync.",
            ))

        # SG-012 remaining accounts
        if "remaining_accounts" in stripped and "ctx.remaining_accounts" in stripped:
            findings.append(Finding(
                "SG-012", RULES["SG-012"].severity, path, lineno, stripped[:120],
                "Caller-supplied accounts are being read.",
            ))

        # SG-011 unsigned CPI
        if re.search(r"\binvoke\s*\(", stripped) and "invoke_signed" not in stripped:
            findings.append(Finding(
                "SG-011", RULES["SG-011"].severity, path, lineno, stripped[:120],
                "Unsigned CPI - confirm the callee does not require program signer.",
            ))

        # SG-005 / SG-008 arithmetic
        has_arith = (
            ARITH_RE.search(stripped)
            or re.search(r"[\w\)\]]\s*[+\-*]\s*[\w\(\[]", stripped)
            or re.search(r"[\w\)\]]\s*/\s*[\w\(\[]", stripped)
        )
        looks_financial = any(h in lowered for h in FINANCIAL_HINTS)
        has_numeric = any(t in stripped for t in NUMERIC_TYPES)
        if has_arith and (looks_financial or has_numeric):
            if not CHECKED_RE.search(stripped):
                findings.append(Finding(
                    "SG-005", RULES["SG-005"].severity, path, lineno, stripped[:120],
                    "Arithmetic on a quantity without checked_/saturating_ handling.",
                ))
            elif ".unwrap()" in stripped:
                findings.append(Finding(
                    "SG-008", RULES["SG-008"].severity, path, lineno, stripped[:120],
                    "unwrap() on an arithmetic result panics instead of erroring.",
                ))


def scan_functions(fns: list[dict], findings: list[Finding], path: str) -> None:
    for fn in fns:
        name_l = fn["name"].lower()
        if not any(h in name_l for h in PRIVILEGED_HINTS):
            continue
        body_text = "\n".join(strip_comment(b) for b in fn["body"])
        if not GUARD_RE.search(body_text):
            findings.append(Finding(
                "SG-010", RULES["SG-010"].severity, path, fn["line"],
                f"pub fn {fn['name']}(...)",
                "Privileged-looking instruction with no require!/assert! guard "
                "in its body.",
                {"function": fn["name"]},
            ))


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return []
    lines = text.splitlines()
    findings: list[Finding] = []
    rel = str(path)
    scan_structs(extract_accounts_structs(lines), findings, rel)
    scan_lines(lines, findings, rel)
    scan_functions(function_bodies(lines), findings, rel)
    return findings


# ---------------------------------------------------------------- output -----

def render_text(findings: list[Finding], total_files: int) -> str:
    if not findings:
        return f"SolGuard: {total_files} file(s) scanned, no findings."
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    out = [
        "SolGuard - Solana / Anchor validation scanner",
        f"files scanned : {total_files}",
        f"findings      : {len(findings)}",
        "  " + "  ".join(f"{s}={counts[s]}" for s in reversed(SEVERITIES) if counts[s]),
        "",
    ]
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule, []).append(f)
    for rule_id in sorted(by_rule, key=lambda r: -SEV_RANK[RULES[r].severity]):
        r = RULES[rule_id]
        group = by_rule[rule_id]
        out.append(f"[{r.severity.upper():8}] {rule_id} {r.title}  ({len(group)})")
        for f in group:
            out.append(f"    {f.file}:{f.line}")
            out.append(f"      {f.snippet}")
        out.append(f"    why : {r.why}")
        out.append(f"    fix : {r.fix}")
        out.append("")
    return "\n".join(out)


def render_markdown(findings: list[Finding], total_files: int) -> str:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    lines = [
        "# SolGuard scan report",
        "",
        f"- Files scanned: **{total_files}**",
        f"- Findings: **{len(findings)}**",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for s in reversed(SEVERITIES):
        if counts[s]:
            lines.append(f"| {s.capitalize()} | {counts[s]} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| ID | Severity | Location | Code | Note |")
    lines.append("|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: -SEV_RANK[x.severity]):
        snippet = f.snippet.replace("|", "\\|")[:60]
        note = f.detail.replace("|", "\\|")[:70]
        lines.append(
            f"| {f.rule} | {f.severity} | `{Path(f.file).name}:{f.line}` | "
            f"`{snippet}` | {note} |"
        )
    lines.append("")
    lines.append("## Remediation reference")
    lines.append("")
    seen = []
    for f in findings:
        if f.rule not in seen:
            seen.append(f.rule)
    for rule_id in seen:
        r = RULES[rule_id]
        lines.append(f"### {rule_id} - {r.title} ({r.severity})")
        lines.append("")
        lines.append(f"- **Why:** {r.why}")
        lines.append(f"- **Fix:** {r.fix}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="SolGuard - Solana/Anchor validation scanner")
    ap.add_argument("path", help="Rust file or directory to scan")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--markdown", action="store_true", help="emit Markdown")
    ap.add_argument("--min", default="low", choices=SEVERITIES,
                    help="minimum severity to report (default: low)")
    args = ap.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2

    files = [target] if target.is_file() else sorted(target.rglob("*.rs"))
    if not files:
        print(f"error: no .rs files under {target}", file=sys.stderr)
        return 2

    all_findings: list[Finding] = []
    for f in files:
        all_findings.extend(scan_file(f))

    floor = SEV_RANK[args.min]
    all_findings = [x for x in all_findings if SEV_RANK[x.severity] >= floor]
    all_findings.sort(key=lambda x: (-SEV_RANK[x.severity], x.file, x.line))

    if args.json:
        print(json.dumps({
            "files_scanned": len(files),
            "findings": [f.as_dict() for f in all_findings],
        }, indent=2))
    elif args.markdown:
        print(render_markdown(all_findings, len(files)))
    else:
        print(render_text(all_findings, len(files)))

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
