use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("User not found")]
    UserNotFound {},

    #[error("Email already registered")]
    EmailAlreadyRegistered {},

    #[error("Wallet address already registered")]
    WalletAlreadyRegistered {},

    #[error("Invalid email format")]
    InvalidEmail {},

    #[error("Invalid verification code")]
    InvalidVerificationCode {},
    
    #[error("Subscription expired")]
    SubscriptionExpired {},
    
    #[error("CV limit reached")]
    CvLimitReached {},
    
    #[error("Insufficient payment")]
    InsufficientPayment {},
}