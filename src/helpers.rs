use cosmwasm_std::{Addr, Attribute, DepsMut, Env, MessageInfo, StdError, StdResult, Uint128};
use crate::state::LAST_GLOBAL_RESET;

/// Generate a standardized log entry with user and timestamp
pub fn create_log_entry(env: &Env, user: &Addr) -> Vec<Attribute> {
    // Get current blockchain timestamp
    let timestamp_seconds = env.block.time.seconds();
    
    // Format timestamp manually
    let formatted_timestamp = format_timestamp(timestamp_seconds);
    
    vec![
        Attribute::new("timestamp_seconds", timestamp_seconds.to_string()),
        Attribute::new("formatted_timestamp", formatted_timestamp),
        Attribute::new("user", user.to_string()),
    ]
}

/// Format a Unix timestamp into "YYYY-MM-DD HH:MM:SS" format without chrono
fn format_timestamp(timestamp: u64) -> String {
    // We'll implement a basic formatter without chrono
    // This converts timestamp to UTC date/time components
    
    // Constants for time calculations
    const SECONDS_PER_MINUTE: u64 = 60;
    const SECONDS_PER_HOUR: u64 = 3600;
    const SECONDS_PER_DAY: u64 = 86400;
    const DAYS_PER_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    
    // Base date for calculations (1970-01-01)
    let mut remaining_seconds = timestamp;
    let mut year = 1970;
    
    // Calculate year
    loop {
        let year_seconds = if is_leap_year(year) { 366 * SECONDS_PER_DAY } else { 365 * SECONDS_PER_DAY };
        if remaining_seconds < year_seconds {
            break;
        }
        remaining_seconds -= year_seconds;
        year += 1;
    }
    
    // Calculate month
    let mut month = 0;
    for (i, &days) in DAYS_PER_MONTH.iter().enumerate() {
        let month_seconds = if i == 1 && is_leap_year(year) {
            (days + 1) * SECONDS_PER_DAY
        } else {
            days * SECONDS_PER_DAY
        };
        
        if remaining_seconds < month_seconds {
            month = i + 1;
            break;
        }
        remaining_seconds -= month_seconds;
    }
    if month == 0 { month = 12; } // Fallback
    
    // Calculate day
    let day = remaining_seconds / SECONDS_PER_DAY + 1;
    remaining_seconds %= SECONDS_PER_DAY;
    
    // Calculate time
    let hour = remaining_seconds / SECONDS_PER_HOUR;
    remaining_seconds %= SECONDS_PER_HOUR;
    let minute = remaining_seconds / SECONDS_PER_MINUTE;
    let second = remaining_seconds % SECONDS_PER_MINUTE;
    
    // Format as YYYY-MM-DD HH:MM:SS
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, minute, second
    )
}

// Helper function to determine if a year is a leap year
fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// Helper function to extract year and month from a timestamp
fn get_year_month(timestamp: u64) -> (u64, u64) {
    // Same calculation as in format_timestamp but returning only year and month
    const SECONDS_PER_DAY: u64 = 86400;
    const DAYS_PER_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    
    let mut remaining_seconds = timestamp;
    let mut year = 1970;
    
    // Calculate year
    loop {
        let year_seconds = if is_leap_year(year) { 366 * SECONDS_PER_DAY } else { 365 * SECONDS_PER_DAY };
        if remaining_seconds < year_seconds {
            break;
        }
        remaining_seconds -= year_seconds;
        year += 1;
    }
    
    // Calculate month (fix: convert i to u64)
    let mut month = 0;
    for (i, &days) in DAYS_PER_MONTH.iter().enumerate() {
        let month_seconds = if i == 1 && is_leap_year(year) {
            (days + 1) * SECONDS_PER_DAY
        } else {
            days * SECONDS_PER_DAY
        };
        
        if remaining_seconds < month_seconds {
            // Convert usize to u64 using try_into().unwrap()
            month = (i + 1) as u64;  // This is the fix - cast to u64
            break;
        }
        remaining_seconds -= month_seconds;
    }
    if month == 0 { month = 12; } // Fallback
    
    (year, month)
}

// Helper function to check if we need a global reset
pub fn check_global_reset(deps: &mut DepsMut, env: &Env) -> StdResult<bool> {
    let now = env.block.time.seconds();
    let last_reset = LAST_GLOBAL_RESET.load(deps.storage)?;
    
    // Extract year and month components
    let (last_year, last_month) = get_year_month(last_reset);
    let (current_year, current_month) = get_year_month(now);
    
    // If we've entered a new month
    if last_month != current_month || last_year != current_year {
        LAST_GLOBAL_RESET.save(deps.storage, &now)?;
        return Ok(true);
    }
    
    Ok(false)
}

/// Simple email validation for redundant safety
/// Note: Primary email verification happens via Burnt wallet/Abstraxion
pub fn is_valid_email(email: &str) -> bool {
    email.contains('@') && email.contains('.')
}

/// Our own implementation of must_pay to avoid version conflicts
pub fn check_payment(info: &MessageInfo, denom: &str) -> StdResult<Uint128> {
    // Find the coin with matching denomination
    if let Some(coin) = info.funds.iter().find(|c| c.denom == denom) {
        if coin.amount.is_zero() {
            return Err(StdError::generic_err(format!("Zero amount for {}", denom)));
        }
        Ok(coin.amount)
    } else {
        Err(StdError::generic_err(format!("No funds sent with denomination {}", denom)))
    }
}