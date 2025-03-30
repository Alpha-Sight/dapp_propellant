use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

use crate::state::{User, SubscriptionTier, TierConfig, UserSubscription};

#[cw_serde]
pub struct InstantiateMsg {
    /// Contract administrator address (optional, defaults to sender)
    pub admin: Option<String>,
    /// API key for Burnt wallet integration
    pub burnt_wallet_api_key: String,
    /// Treasury admin address
    pub treasury_admin: Option<String>,
}

//------------------------------------------------------------------------
// EXECUTE MESSAGES
//------------------------------------------------------------------------

#[cw_serde]
pub enum ExecuteMsg {
    //-------------------------------
    // Admin Functions
    //-------------------------------
    
    /// Update contract configuration (admin only)
    UpdateConfig {
        new_admin: Option<String>,
        burnt_wallet_api_key: Option<String>,
        treasury_admin: Option<String>,
    },
    
    /// Configure a subscription tier (admin only)
    ConfigureTier {
        tier: SubscriptionTier,
        price: Uint128,
        cv_limit: u32,
        treasury_address: String,
    },
    
    //-------------------------------
    // User Account Management
    //-------------------------------
    
    /// Register a new user with email-wallet link from Abstraxion
    RegisterUser {
        email: String,
        name: Option<String>,
        public_key: String, // Base64 encoded public key
        signature: String,
        // Wallet address comes from msg.sender
    },
    
    /// Update user's last login timestamp
    UpdateLastLogin {},
    
    /// Update user profile information
    UpdateUserProfile {
        name: Option<String>,
        email: Option<String>,
    },

    // Add message to update public key
    UpdatePublicKey { 
        public_key: String, 
        signature: String, // Signed with old key for verification
    },
    
    //-------------------------------
    // Subscription Management
    //-------------------------------
    
    /// Subscribe to a paid tier (with payment)
    Subscribe {
        tier: SubscriptionTier,
    },
    
    /// Link user to treasury contract (requires treasury_admin)
    LinkUserToTreasury {
        user_address: String,
    },
    
    /// Record a CV generation
    RecordCvGeneration {
        user_address: String,
        signature: String,
    },
    DeductCvCredit { user_address: String, signature: String },
}

//------------------------------------------------------------------------
// QUERY MESSAGES
//------------------------------------------------------------------------

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Get contract configuration
    #[returns(ConfigResponse)]
    GetConfig {},
    
    /// Get user information by address
    #[returns(UserResponse)]
    GetUser { 
        address: Option<String> // If None, uses caller's address
    },
    
    /// Look up a user address by email
    #[returns(UserAddressResponse)]
    GetUserByEmail { 
        email: String 
    },
    
    /// Get total number of registered users
    #[returns(TotalUsersResponse)]
    GetTotalUsers {},
    
    /// Get tier configuration
    #[returns(TierConfigResponse)]
    GetTierConfig {
        tier: SubscriptionTier
    },
    
    /// Get all tier configurations
    #[returns(AllTierConfigsResponse)]
    GetAllTierConfigs {},
    
    /// Get user subscription details
    #[returns(UserSubscriptionResponse)]
    GetUserSubscription {
        address: String
    },
}

// We define a custom struct for each query response
#[cw_serde]

pub struct ConfigResponse {
    pub admin: Addr,
    pub burnt_wallet_api_key: String,
    pub treasury_admin: Addr,
}

#[cw_serde]
pub struct UserResponse {
    pub user: Option<User>,
}

#[cw_serde]
pub struct UserAddressResponse {
    pub address: Option<Addr>,
}

#[cw_serde]
pub struct TotalUsersResponse {
    pub total_users: u64,
}

#[cw_serde]
pub struct TierConfigResponse {
    pub config: TierConfig,
}

#[cw_serde]
pub struct AllTierConfigsResponse {
    pub configs: Vec<(SubscriptionTier, TierConfig)>,
}

#[cw_serde]
pub struct UserSubscriptionResponse {
    pub subscription: UserSubscription,
    pub tier_config: TierConfig,
}