use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};
use std::fmt;

//------------------------------------------------------------------------
// SUBSCRIPTION TIERS
//------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum SubscriptionTier {
    Free,                // Default tier (0 CVs)
    Basic,               // 1,500 XION = 1 CV
    Standard,            // 5,000 XION = 5 CVs
    Premium,             // 10,000 XION = 15 CVs
}

// Add Display implementation to convert to string
impl fmt::Display for SubscriptionTier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SubscriptionTier::Free => write!(f, "free"),
            SubscriptionTier::Basic => write!(f, "basic"),
            SubscriptionTier::Standard => write!(f, "standard"),
            SubscriptionTier::Premium => write!(f, "premium"),
        }
    }
}

// Helper to convert SubscriptionTier to string for storage keys
pub fn tier_to_key(tier: &SubscriptionTier) -> String {
    match tier {
        SubscriptionTier::Free => "free".to_string(),
        SubscriptionTier::Basic => "basic".to_string(),
        SubscriptionTier::Standard => "standard".to_string(),
        SubscriptionTier::Premium => "premium".to_string(),
    }
}

// Helper to convert string key back to SubscriptionTier
pub fn key_to_tier(key: &str) -> Option<SubscriptionTier> {
    match key {
        "free" => Some(SubscriptionTier::Free),
        "basic" => Some(SubscriptionTier::Basic),
        "standard" => Some(SubscriptionTier::Standard),
        "premium" => Some(SubscriptionTier::Premium),
        _ => None,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct TierConfig {
    tier: SubscriptionTier,
    price: Uint128,          // Price in XION
    cv_limit: u32,           // Number of CVs allowed
    treasury_address: Addr,  // Treasury contract address for this tier
}

impl TierConfig {
    pub fn new(tier: SubscriptionTier, price: Uint128, cv_limit: u32, treasury_address: Addr) -> Self {
        Self {
            tier,
            price,
            cv_limit,
            treasury_address,
        }
    }
    
    pub fn tier(&self) -> &SubscriptionTier {
        &self.tier
    }
    
    pub fn price(&self) -> Uint128 {
        self.price
    }
    
    pub fn cv_limit(&self) -> u32 {
        self.cv_limit
    }
    
    pub fn treasury_address(&self) -> &Addr {
        &self.treasury_address
    }
    
    pub fn set_price(&mut self, price: Uint128) {
        self.price = price;
    }
    
    pub fn set_cv_limit(&mut self, cv_limit: u32) {
        self.cv_limit = cv_limit;
    }
    
    pub fn set_treasury_address(&mut self, treasury_address: Addr) {
        self.treasury_address = treasury_address;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct UserSubscription {
    tier: SubscriptionTier,
    cvs_generated: u32,       // Number of CVs already generated
    expiration: u64,          // Timestamp when subscription expires
    treasury_linked: bool,      // Whether user is linked to treasury
    last_reset_time: u64,  
    signature: Option<String>, // Add this field  
    session_token: Option<String>, // For backend communication
}

impl UserSubscription {
    pub fn new(tier: SubscriptionTier, cvs_generated: u32, expiration: u64, treasury_linked: bool, last_reset_time: u64, signature: Option<String>, session_token: Option<String>) -> Self {
        Self {
            tier,
            cvs_generated,
            expiration,
            treasury_linked,
            last_reset_time,
            signature,
            session_token, //: None, // For backend communication
        }
    }
    
    pub fn tier(&self) -> &SubscriptionTier {
        &self.tier
    }

    pub fn cvs_generated(&self) -> u32 {
        self.cvs_generated
    }

    pub fn expiration(&self) -> u64 {
        self.expiration
    }

    pub fn treasury_linked(&self) -> bool {
        self.treasury_linked
    }

    pub fn last_reset_time(&self) -> u64 {
        self.last_reset_time
    }

    pub fn signature(&self) -> Option<String> {
        self.signature.clone()
    }

    // Add getter/setter for session token
    pub fn session_token(&self) -> &Option<String> {
        &self.session_token
    }
    
    pub fn set_session_token(&mut self, token: Option<String>) {
        self.session_token = token;
    }

    pub fn set_cvs_generated(&mut self, cvs_generated: u32) {
        self.cvs_generated = cvs_generated;
    }

    pub fn set_expiration(&mut self, expiration: u64) {
        self.expiration = expiration;
    }

    pub fn set_treasury_linked(&mut self, treasury_linked: bool) {
        self.treasury_linked = treasury_linked;
    }

    pub fn set_last_reset_time(&mut self, last_reset_time: u64) {
        self.last_reset_time = last_reset_time;
    }

    pub fn set_signature(&mut self, signature: Option<String>) {
        self.signature = signature;
    }
}

//------------------------------------------------------------------------
// USER ACCOUNT MANAGEMENT
//------------------------------------------------------------------------

/// User registration and profile information
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct User {
    address: Addr,                   // User's blockchain wallet address
    email: String,                   // User's email address
    email_verified: bool,            // Whether email has been verified
    registration_date: u64,          // When user registered (timestamp)
    last_login: u64,                 // When user last logged in (timestamp)
    name: Option<String>,            // User's display name (optional)
    subscription: UserSubscription,  // User's subscription details
    public_key: Option<String>, // Base64 encoded public key
}

impl User {
    pub fn new(address: Addr, email: String, email_verified: bool, registration_date: u64, last_login: u64, name: Option<String>, subscription: UserSubscription, public_key: Option<String>) -> Self {
        Self {
            address,
            email,
            email_verified,
            registration_date,
            last_login,
            name,
            subscription,
            public_key,
        }
    }

    pub fn address(&self) -> &Addr {
        &self.address
    }

    pub fn email(&self) -> &String {
        &self.email
    }

    pub fn email_verified(&self) -> bool {
        self.email_verified
    }

    pub fn registration_date(&self) -> u64 {
        self.registration_date
    }

    pub fn last_login(&self) -> u64 {
        self.last_login
    }

    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }

    pub fn subscription(&self) -> &UserSubscription {
        &self.subscription
    }
    // Add getter and setter for public key
    pub fn public_key(&self) -> &Option<String> {
        &self.public_key
    }
    
    pub fn set_public_key(&mut self, key: Option<String>) {
        self.public_key = key;
    }

    pub fn set_email_verified(&mut self, email_verified: bool) {
        self.email_verified = email_verified;
    }

    pub fn set_email(&mut self, email: String) {
        self.email = email;
    }

    pub fn set_last_login(&mut self, last_login: u64) {
        self.last_login = last_login;
    }

    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    pub fn set_subscription(&mut self, subscription: UserSubscription) {
        self.subscription = subscription;
    }

    pub fn subscription_mut(&mut self) -> &mut UserSubscription {
        &mut self.subscription
    }
}

//------------------------------------------------------------------------
// CONTRACT CONFIGURATION
//------------------------------------------------------------------------

/// Global contract configuration
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Config {
    admin: Addr,                     // Contract administrator
    burnt_wallet_api_key: String,    // API key for Burnt wallet integration
    treasury_admin: Addr,            // Admin address for treasury operations
}

impl Config {
    pub fn new(admin: Addr, burnt_wallet_api_key: String, treasury_admin: Addr) -> Self {
        Self {
            admin,
            burnt_wallet_api_key,
            treasury_admin,
        }
    }

    pub fn admin(&self) -> &Addr {
        &self.admin
    }

    pub fn burnt_wallet_api_key(&self) -> &String {
        &self.burnt_wallet_api_key
    }

    pub fn treasury_admin(&self) -> &Addr {
        &self.treasury_admin
    }

    pub fn set_admin(&mut self, admin: Addr) {
        self.admin = admin;
    }

    pub fn set_burnt_wallet_api_key(&mut self, api_key: String) {
        self.burnt_wallet_api_key = api_key;
    }

    pub fn set_treasury_admin(&mut self, treasury_admin: Addr) {
        self.treasury_admin = treasury_admin;
    }
}

//------------------------------------------------------------------------
// STORAGE DEFINITIONS
//------------------------------------------------------------------------

// Contract configuration
pub const CONFIG: Item<Config> = Item::new("config");

// User management
pub const USERS: Map<&Addr, User> = Map::new("users");
pub const EMAIL_TO_ADDR: Map<&str, Addr> = Map::new("email_to_addr");

// Subscription tiers - now using &str keys instead of enum directly
pub const TIER_CONFIGS: Map<&str, TierConfig> = Map::new("tier_configs");

// Statistics
pub const TOTAL_USERS: Item<u64> = Item::new("total_users");
pub const TOTAL_PAID_USERS: Map<&str, u64> = Map::new("total_paid_users");

// Add this to your state.rs file
pub const LAST_GLOBAL_RESET: Item<u64> = Item::new("last_global_reset");

// Add this to your state.rs file
pub const TOTAL_CVS: Item<u64> = Item::new("total_cv");


#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{
        Config, SubscriptionTier, TierConfig, User, UserSubscription,
        tier_to_key, key_to_tier
    };

    #[test]
    fn test_subscription_tier_conversions() {
        // Test tier_to_key conversions
        assert_eq!(tier_to_key(&SubscriptionTier::Free), "free");
        assert_eq!(tier_to_key(&SubscriptionTier::Basic), "basic");
        assert_eq!(tier_to_key(&SubscriptionTier::Standard), "standard");
        assert_eq!(tier_to_key(&SubscriptionTier::Premium), "premium");

        // Test key_to_tier conversions
        assert_eq!(key_to_tier("free"), Some(SubscriptionTier::Free));
        assert_eq!(key_to_tier("basic"), Some(SubscriptionTier::Basic));
        assert_eq!(key_to_tier("standard"), Some(SubscriptionTier::Standard));
        assert_eq!(key_to_tier("premium"), Some(SubscriptionTier::Premium));
        assert_eq!(key_to_tier("invalid"), None);

        // Test Display implementation
        assert_eq!(format!("{}", SubscriptionTier::Free), "free");
        assert_eq!(format!("{}", SubscriptionTier::Basic), "basic");
        assert_eq!(format!("{}", SubscriptionTier::Standard), "standard");
        assert_eq!(format!("{}", SubscriptionTier::Premium), "premium");
    }

    #[test]
    fn test_tier_config() {
        let treasury = Addr::unchecked("treasury");
        let price = Uint128::new(5000);
        let cv_limit = 10u32;

        // Create a new tier config
        let mut config = TierConfig::new(
            SubscriptionTier::Standard,
            price,
            cv_limit,
            treasury.clone(),
        );

        // Test getters
        assert_eq!(*config.tier(), SubscriptionTier::Standard);
        assert_eq!(config.price(), price);
        assert_eq!(config.cv_limit(), cv_limit);
        assert_eq!(*config.treasury_address(), treasury);

        // Test setters
        let new_price = Uint128::new(7500);
        let new_cv_limit = 15u32;
        let new_treasury = Addr::unchecked("new_treasury");

        config.set_price(new_price);
        config.set_cv_limit(new_cv_limit);
        config.set_treasury_address(new_treasury.clone());

        assert_eq!(config.price(), new_price);
        assert_eq!(config.cv_limit(), new_cv_limit);
        assert_eq!(*config.treasury_address(), new_treasury);
    }

    #[test]
    fn test_user_subscription() {
        let tier = SubscriptionTier::Basic;
        let cvs_generated = 3u32;
        let expiration = 1714500000u64; // Some future timestamp
        let treasury_linked = false;
        let last_reset_time = 1714400000u64;
        let signature = Some("test_signature".to_string());
        let session_token = Some("encrypted_token".to_string());

        // Create a new user subscription
        let mut subscription = UserSubscription::new(
            tier,
            cvs_generated,
            expiration,
            treasury_linked,
            last_reset_time,
            signature.clone(),
            session_token.clone(),
        );

        // Test getters
        assert_eq!(*subscription.tier(), SubscriptionTier::Basic);
        assert_eq!(subscription.cvs_generated(), cvs_generated);
        assert_eq!(subscription.expiration(), expiration);
        assert_eq!(subscription.treasury_linked(), treasury_linked);
        assert_eq!(subscription.last_reset_time(), last_reset_time);
        assert_eq!(subscription.signature(), signature);
        assert_eq!(*subscription.session_token(), session_token);

        // Test setters
        let new_cvs_generated = 5u32;
        let new_expiration = 1714600000u64;
        let new_treasury_linked = true;
        let new_last_reset_time = 1714500000u64;
        let new_signature = Some("new_signature".to_string());
        let new_session_token = Some("new_encrypted_token".to_string());

        subscription.set_cvs_generated(new_cvs_generated);
        subscription.set_expiration(new_expiration);
        subscription.set_treasury_linked(new_treasury_linked);
        subscription.set_last_reset_time(new_last_reset_time);
        subscription.set_signature(new_signature.clone());
        subscription.set_session_token(new_session_token.clone());

        assert_eq!(subscription.cvs_generated(), new_cvs_generated);
        assert_eq!(subscription.expiration(), new_expiration);
        assert_eq!(subscription.treasury_linked(), new_treasury_linked);
        assert_eq!(subscription.last_reset_time(), new_last_reset_time);
        assert_eq!(subscription.signature(), new_signature);
        assert_eq!(*subscription.session_token(), new_session_token);

        // Test setting token to None
        subscription.set_session_token(None);
        assert_eq!(*subscription.session_token(), None);
    }

    #[test]
    fn test_user() {
        let address = Addr::unchecked("user1");
        let email = "test@example.com".to_string();
        let email_verified = true;
        let registration_date = 1714400000u64;
        let last_login = 1714400100u64;
        let name = Some("Test User".to_string());
        
        // Create a subscription for the user
        let subscription = UserSubscription::new(
            SubscriptionTier::Free,
            0,
            u64::MAX, // Free tier doesn't expire
            false,
            registration_date,
            None,
            None,
        );

        let public_key = Some("base64_encoded_public_key".to_string());

        // Create a new user
        let mut user = User::new(
            address.clone(),
            email.clone(),
            email_verified,
            registration_date,
            last_login,
            name.clone(),
            subscription,
            public_key.clone(),
        );

        // Test getters
        assert_eq!(*user.address(), address);
        assert_eq!(*user.email(), email);
        assert_eq!(user.email_verified(), email_verified);
        assert_eq!(user.registration_date(), registration_date);
        assert_eq!(user.last_login(), last_login);
        assert_eq!(user.name(), name.as_ref());
        assert_eq!(user.subscription().tier(), &SubscriptionTier::Free);
        assert_eq!(*user.public_key(), public_key);

        // Test setters
        let new_email = "newemail@example.com".to_string();
        let new_email_verified = false;
        let new_last_login = 1714400200u64;
        let new_name = Some("New Name".to_string());
        let new_public_key = Some("new_base64_encoded_key".to_string());

        // Create a new subscription
        let new_subscription = UserSubscription::new(
            SubscriptionTier::Basic,
            0,
            1714500000u64, // 30 days from registration
            false,
            registration_date,
            None,
            None,
        );

        user.set_email(new_email.clone());
        user.set_email_verified(new_email_verified);
        user.set_last_login(new_last_login);
        user.set_name(new_name.clone());
        user.set_subscription(new_subscription);
        user.set_public_key(new_public_key.clone());

        assert_eq!(*user.email(), new_email);
        assert_eq!(user.email_verified(), new_email_verified);
        assert_eq!(user.last_login(), new_last_login);
        assert_eq!(user.name(), new_name.as_ref());
        assert_eq!(user.subscription().tier(), &SubscriptionTier::Basic);
        assert_eq!(*user.public_key(), new_public_key);

        // Test subscription_mut
        user.subscription_mut().set_cvs_generated(2);
        assert_eq!(user.subscription().cvs_generated(), 2);
    }

    #[test]
    fn test_config() {
        let admin = Addr::unchecked("admin");
        let burnt_wallet_api_key = "api_key_12345".to_string();
        let treasury_admin = Addr::unchecked("treasury_admin");

        // Create a new config
        let mut config = Config::new(
            admin.clone(),
            burnt_wallet_api_key.clone(),
            treasury_admin.clone(),
        );

        // Test getters
        assert_eq!(*config.admin(), admin);
        assert_eq!(*config.burnt_wallet_api_key(), burnt_wallet_api_key);
        assert_eq!(*config.treasury_admin(), treasury_admin);

        // Test setters
        let new_admin = Addr::unchecked("new_admin");
        let new_api_key = "new_api_key_67890".to_string();
        let new_treasury_admin = Addr::unchecked("new_treasury_admin");

        config.set_admin(new_admin.clone());
        config.set_burnt_wallet_api_key(new_api_key.clone());
        config.set_treasury_admin(new_treasury_admin.clone());

        assert_eq!(*config.admin(), new_admin);
        assert_eq!(*config.burnt_wallet_api_key(), new_api_key);
        assert_eq!(*config.treasury_admin(), new_treasury_admin);
    }
}