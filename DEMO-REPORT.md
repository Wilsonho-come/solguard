# SolGuard scan report

- Files scanned: **1**
- Findings: **36**

| Severity | Count |
|---|---|
| High | 22 |
| Medium | 13 |
| Low | 1 |

## Findings

| ID | Severity | Location | Code | Note |
|---|---|---|---|---|
| SG-005 | high | `vulnerable_vault.rs:27` | `state.total_deposits = state.total_deposits + amount;` | Arithmetic on a quantity without checked_/saturating_ handling. |
| SG-005 | high | `vulnerable_vault.rs:30` | `vault.balance = vault.balance + amount;` | Arithmetic on a quantity without checked_/saturating_ handling. |
| SG-005 | high | `vulnerable_vault.rs:33` | `**ctx.accounts.vault.to_account_info().try_borrow_mut_lampor` | Arithmetic on a quantity without checked_/saturating_ handling. |
| SG-005 | high | `vulnerable_vault.rs:42` | `vault.balance = vault.balance - amount;` | Arithmetic on a quantity without checked_/saturating_ handling. |
| SG-005 | high | `vulnerable_vault.rs:48` | `let payout = (amount - fee) as u32;` | Arithmetic on a quantity without checked_/saturating_ handling. |
| SG-005 | high | `vulnerable_vault.rs:51` | `**ctx.accounts.vault.to_account_info().try_borrow_mut_lampor` | Arithmetic on a quantity without checked_/saturating_ handling. |
| SG-005 | high | `vulnerable_vault.rs:68` | `**dest.try_borrow_mut_lamports()? += lamports;` | Arithmetic on a quantity without checked_/saturating_ handling. |
| SG-003 | high | `vulnerable_vault.rs:106` | `state: Account<'info, VaultState>` | Field looks like a PDA but `Initialize` declares no seeds constraint f |
| SG-002 | high | `vulnerable_vault.rs:107` | `authority: AccountInfo<'info>` | In #[derive(Accounts)] struct `Initialize`. |
| SG-004 | high | `vulnerable_vault.rs:107` | `authority: AccountInfo<'info>` | Authority-like field in `Initialize` is not proven to be a signer. |
| SG-003 | high | `vulnerable_vault.rs:116` | `state: Account<'info, VaultState>` | Field looks like a PDA but `Deposit` declares no seeds constraint for  |
| SG-003 | high | `vulnerable_vault.rs:118` | `vault: Account<'info, Vault>` | Field looks like a PDA but `Deposit` declares no seeds constraint for  |
| SG-001 | high | `vulnerable_vault.rs:119` | `recipient: UncheckedAccount<'info>` | In #[derive(Accounts)] struct `Deposit`. |
| SG-002 | high | `vulnerable_vault.rs:120` | `authority: AccountInfo<'info>` | In #[derive(Accounts)] struct `Deposit`. |
| SG-004 | high | `vulnerable_vault.rs:120` | `authority: AccountInfo<'info>` | Authority-like field in `Deposit` is not proven to be a signer. |
| SG-003 | high | `vulnerable_vault.rs:126` | `vault: Account<'info, Vault>` | Field looks like a PDA but `Withdraw` declares no seeds constraint for |
| SG-003 | high | `vulnerable_vault.rs:133` | `state: Account<'info, VaultState>` | Field looks like a PDA but `SetFee` declares no seeds constraint for i |
| SG-001 | high | `vulnerable_vault.rs:135` | `authority: UncheckedAccount<'info>` | In #[derive(Accounts)] struct `SetFee`. |
| SG-004 | high | `vulnerable_vault.rs:135` | `authority: UncheckedAccount<'info>` | Authority-like field in `SetFee` is not proven to be a signer. |
| SG-003 | high | `vulnerable_vault.rs:141` | `vault: Account<'info, Vault>` | Field looks like a PDA but `AdminDrain` declares no seeds constraint f |
| SG-001 | high | `vulnerable_vault.rs:143` | `destination: UncheckedAccount<'info>` | In #[derive(Accounts)] struct `AdminDrain`. |
| SG-001 | high | `vulnerable_vault.rs:151` | `recipient: UncheckedAccount<'info>` | In #[derive(Accounts)] struct `Relay`. |
| SG-010 | medium | `vulnerable_vault.rs:14` | `pub fn initialize(...)` | Privileged-looking instruction with no require!/assert! guard in its b |
| SG-006 | medium | `vulnerable_vault.rs:32` | `let lamports = amount as u64;` | Integer cast found - confirm the source cannot exceed the target. |
| SG-007 | medium | `vulnerable_vault.rs:33` | `**ctx.accounts.vault.to_account_info().try_borrow_mut_lampor` | Direct lamport access - confirm internal accounting stays in sync. |
| SG-010 | medium | `vulnerable_vault.rs:38` | `pub fn withdraw(...)` | Privileged-looking instruction with no require!/assert! guard in its b |
| SG-008 | medium | `vulnerable_vault.rs:45` | `let fee = vault.balance.checked_mul(30).unwrap() / 10_000;` | unwrap() on an arithmetic result panics instead of erroring. |
| SG-006 | medium | `vulnerable_vault.rs:48` | `let payout = (amount - fee) as u32;` | Integer cast found - confirm the source cannot exceed the target. |
| SG-006 | medium | `vulnerable_vault.rs:51` | `**ctx.accounts.vault.to_account_info().try_borrow_mut_lampor` | Integer cast found - confirm the source cannot exceed the target. |
| SG-007 | medium | `vulnerable_vault.rs:51` | `**ctx.accounts.vault.to_account_info().try_borrow_mut_lampor` | Direct lamport access - confirm internal accounting stays in sync. |
| SG-010 | medium | `vulnerable_vault.rs:56` | `pub fn set_fee(...)` | Privileged-looking instruction with no require!/assert! guard in its b |
| SG-010 | medium | `vulnerable_vault.rs:62` | `pub fn admin_drain(...)` | Privileged-looking instruction with no require!/assert! guard in its b |
| SG-007 | medium | `vulnerable_vault.rs:67` | `**info.try_borrow_mut_lamports()? = 0;` | Direct lamport access - confirm internal accounting stays in sync. |
| SG-007 | medium | `vulnerable_vault.rs:68` | `**dest.try_borrow_mut_lamports()? += lamports;` | Direct lamport access - confirm internal accounting stays in sync. |
| SG-011 | medium | `vulnerable_vault.rs:79` | `invoke(` | Unsigned CPI - confirm the callee does not require program signer. |
| SG-012 | low | `vulnerable_vault.rs:91` | `for account in ctx.remaining_accounts.iter() {` | Caller-supplied accounts are being read. |

## Remediation reference

### SG-005 - Unchecked arithmetic on a financial quantity (high)

- **Why:** Arithmetic on balances, amounts, fees or shares without checked_* or saturating_* can overflow or wrap, producing incorrect accounting that an attacker can usually turn into a withdrawal.
- **Fix:** Use checked_add / checked_sub / checked_mul / checked_div and handle the None case explicitly.

### SG-003 - PDA-like account without a seeds constraint (high)

- **Why:** An account whose name suggests a program-derived address is accepted without proving the address was derived from the expected seeds. A caller can substitute a different, attacker-created account.
- **Fix:** Add seeds = [...] with bump, and verify the bump is stored or re-derived with find_program_address.

### SG-002 - Raw AccountInfo in an Accounts struct (high)

- **Why:** AccountInfo carries no type information. Nothing about it is checked. This is the most common source of account-confusion bugs on Solana.
- **Fix:** Use Account<'info, T>, Signer<'info>, or SystemAccount<'info> so the type system enforces the checks.

### SG-004 - Authority-like account is not proven to be a signer (high)

- **Why:** A field named like an authority is neither typed Signer<'info> nor constrained with is_signer. Any caller can pass an arbitrary pubkey.
- **Fix:** Type it as Signer<'info>, or add constraint = <field>.is_signer.

### SG-001 - UncheckedAccount accepted without manual validation (high)

- **Why:** UncheckedAccount is an escape hatch: Anchor performs no owner, discriminator, or signer check. If the handler does not validate it manually, a caller can pass any account the program will then trust.
- **Fix:** Validate owner and key manually, or replace with Account<'info, T> so Anchor applies discriminator and owner checks.

### SG-010 - Privileged instruction without an explicit guard (medium)

- **Why:** An instruction whose name suggests a privileged action contains no require!, assert!, or has_one guard in its body.
- **Fix:** Add an explicit authority check with require! and test the failure path.

### SG-006 - Integer cast may silently truncate (medium)

- **Why:** `as` casts in Rust wrap or truncate rather than failing. Casting a larger integer down can turn a large value into a small one.
- **Fix:** Use try_into() and propagate the error, or range-check before casting.

### SG-007 - Direct lamport balance manipulation (medium)

- **Why:** Moving lamports by hand bypasses the account's own accounting and can desynchronise real balance from recorded balance, or break rent rules.
- **Fix:** Prefer system_program::transfer via CPI, or update internal accounting in the same step.

### SG-008 - unwrap() on an arithmetic result (medium)

- **Why:** unwrap() on a checked_* result panics instead of returning an error. A panic in a financial path is a denial of service on user funds.
- **Fix:** Return the error with ok_or(ErrorCode::Overflow)? instead.

### SG-011 - Unsigned cross-program invocation (medium)

- **Why:** invoke() (as opposed to invoke_signed) cannot act with program signer authority. If the callee expects the program as signer, this silently fails - or worse, passes with the wrong authority.
- **Fix:** Use invoke_signed with seeds derived from this program, and verify the target program id is hard-coded.

### SG-012 - remaining_accounts used without validation (low)

- **Why:** Accounts passed through ctx.remaining_accounts are supplied by the caller and are not type-checked by Anchor.
- **Fix:** Validate each remaining account's key and owner before use.

