// Sample Solana / Anchor program used to exercise SolGuard.
// This file is intentionally insecure. Do not deploy it.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_lang::solana_program::system_instruction;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vulnerable_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, fee_bps: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.authority.key();
        state.fee_bps = fee_bps;
        state.total_deposits = 0;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        let vault = &mut ctx.accounts.vault;

        // SG-005: no checked_add, and total_deposits is a financial quantity
        state.total_deposits = state.total_deposits + amount;

        // SG-005 / SG-007: balance updated by hand, lamports moved by hand
        vault.balance = vault.balance + amount;

        let lamports = amount as u64;
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? += lamports;

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // SG-005: subtraction without checked_sub can underflow
        vault.balance = vault.balance - amount;

        // SG-008: unwrap on a checked operation panics instead of erroring
        let fee = vault.balance.checked_mul(30).unwrap() / 10_000;

        // SG-006: cast can truncate
        let payout = (amount - fee) as u32;

        // SG-007: direct lamport write
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= payout as u64;

        Ok(())
    }

    pub fn set_fee(ctx: Context<SetFee>, new_fee_bps: u64) -> Result<()> {
        // SG-010: privileged instruction, but no require! guard on authority
        ctx.accounts.state.fee_bps = new_fee_bps;
        Ok(())
    }

    pub fn admin_drain(ctx: Context<AdminDrain>) -> Result<()> {
        // SG-010: no authority check at all
        let info = ctx.accounts.vault.to_account_info();
        let dest = ctx.accounts.destination.to_account_info();
        let lamports = info.lamports();
        **info.try_borrow_mut_lamports()? = 0;
        **dest.try_borrow_mut_lamports()? += lamports;
        Ok(())
    }

    pub fn relay(ctx: Context<Relay>, amount: u64) -> Result<()> {
        // SG-011: unsigned CPI
        let ix = system_instruction::transfer(
            &ctx.accounts.payer.key(),
            &ctx.accounts.recipient.key(),
            amount,
        );
        invoke(
            &ix,
            &[
                ctx.accounts.payer.to_account_info(),
                ctx.accounts.recipient.to_account_info(),
            ],
        )?;
        Ok(())
    }

    pub fn sweep_extra(ctx: Context<SweepExtra>) -> Result<()> {
        // SG-012: caller-supplied remaining accounts are trusted
        for account in ctx.remaining_accounts.iter() {
            let data = account.try_borrow_data()?;
            if data.len() > 8 {
                msg!("sweeping {}", account.key());
            }
        }
        Ok(())
    }
}

// SG-002: raw AccountInfo in an Accounts struct
// SG-004: authority is not typed Signer and has no is_signer constraint
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 128)]
    pub state: Account<'info, VaultState>,
    pub authority: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

// SG-003: vault looks like a PDA but has no seeds constraint
// SG-001: UncheckedAccount accepted without manual validation
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub state: Account<'info, VaultState>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub recipient: UncheckedAccount<'info>,
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(mut)]
    pub state: Account<'info, VaultState>,
    // SG-004: named authority but typed as UncheckedAccount, not proven signer
    pub authority: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AdminDrain<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: destination is trusted blindly
    pub destination: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Relay<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: recipient
    pub recipient: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SweepExtra<'info> {
    pub operator: Signer<'info>,
}

#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub fee_bps: u64,
    pub total_deposits: u64,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
}
