#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cw2::set_contract_version;

use cosmwasm_std::{to_json_binary, BankMsg, Binary, Coin, Deps, DepsMut, Env, Event, MessageInfo, Response, StdError, StdResult, Uint128};

use crate::crypto::{generate_encrypted_secure_token, verify_signature, decrypt_and_verify_secure_token};

use sha2::{Sha256, Digest};

// use crate::auth::jwt::verify;
use crate::error::ContractError;
use crate::helpers::{check_global_reset, check_payment, create_log_entry, is_valid_email};
use crate::msg::{
    AllTierConfigsResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, QueryMsg,
    TierConfigResponse, TotalUsersResponse, UserAddressResponse, UserResponse,
    UserSubscriptionResponse,
};
use crate::state::{
    tier_to_key, Config, SubscriptionTier, TierConfig, User, UserSubscription, CONFIG, EMAIL_TO_ADDR, LAST_GLOBAL_RESET, TIER_CONFIGS, TOTAL_CVS, TOTAL_PAID_USERS, TOTAL_USERS, USERS
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:dapp_propellant";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // Set the admin (either from message or default to sender)
    let admin = match msg.admin {
        Some(admin) => deps.api.addr_validate(&admin)?,
        None => info.sender.clone(),
    };

    // Set treasury admin (either from message or use regular admin)
    let treasury_admin = match msg.treasury_admin {
        Some(treasury_admin) => deps.api.addr_validate(&treasury_admin)?,
        None => admin.clone(),
    };

    // Store the configuration
    let config = Config::new(admin.clone(), msg.burnt_wallet_api_key, treasury_admin);
    CONFIG.save(deps.storage, &config)?;

    // Initialize total users counter
    TOTAL_USERS.save(deps.storage, &0u64)?;

    // Initialize the global reset timestamp
    let now = env.block.time.seconds();
    LAST_GLOBAL_RESET.save(deps.storage, &now)?;

    // Initialize total CV counter
    TOTAL_CVS.save(deps.storage, &0u64)?;

    // Set up default subscription tiers
    let default_treasury = admin.clone();

    // Create the Free tier
    let free_tier = TierConfig::new(
        SubscriptionTier::Free,
        Uint128::zero(),
        2, // 2 free credits per month
        default_treasury.clone(),
    );

    // Use tier_to_key for string conversion
    let free_key = tier_to_key(&SubscriptionTier::Free);
    TIER_CONFIGS.save(deps.storage, &free_key, &free_tier)?;

    // Add placeholders for other tiers (to be configured properly by admin later)
    for tier in [
        SubscriptionTier::Basic,
        SubscriptionTier::Standard,
        SubscriptionTier::Premium,
    ] {
        let placeholder_config = TierConfig::new(
            tier.clone(),
            Uint128::zero(), // Will be set by admin
            0,               // Will be set by admin
            default_treasury.clone(),
        );
        let tier_key = tier_to_key(&tier);
        TIER_CONFIGS.save(deps.storage, &tier_key, &placeholder_config)?;
    }

    // Log who initialized the contract and when
    let log_entry = create_log_entry(&env, &admin);

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let response = Response::new()
        .add_attribute("action", "instantiate")
        .add_attributes(log_entry);

    Ok(response)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        // Admin functions
        ExecuteMsg::UpdateConfig {
            new_admin,
            burnt_wallet_api_key,
            treasury_admin,
        } => execute_update_config(
            deps,
            env,
            info,
            new_admin,
            burnt_wallet_api_key,
            treasury_admin,
        ),
        ExecuteMsg::ConfigureTier {
            tier,
            price,
            cv_limit,
            treasury_address,
        } => execute_configure_tier(deps, env, info, tier, price, cv_limit, treasury_address),

        // User management
        ExecuteMsg::RegisterUser { email, name, public_key, signature } => {
            execute_register_user(deps, env, info, email, name, public_key, signature)
        },
        ExecuteMsg::UpdateLastLogin {} => execute_update_last_login(deps, env, info),
        ExecuteMsg::UpdateUserProfile { name, email } => {
            execute_update_profile(deps, env, info, name, email)
        }
        ExecuteMsg::UpdatePublicKey { public_key, signature } => {
            execute_update_public_key(deps, env, info, public_key, signature)
        },
        // Subscription management
        ExecuteMsg::Subscribe { tier } => execute_subscribe(deps, env, info, tier),
        ExecuteMsg::LinkUserToTreasury { user_address } => {
            execute_link_user_to_treasury(deps, env, info, user_address)
        }
        ExecuteMsg::RecordCvGeneration { user_address, signature } => {
            let timestamp = env.block.time.seconds();
            execute_record_cv_generation(deps, env, info, user_address, timestamp, signature)
        }
        ExecuteMsg::DeductCvCredit { user_address, signature } => {
            execute_deduct_cv_credit(deps, env, info, user_address, signature)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_json_binary(&query_config(deps)?),
        QueryMsg::GetUser { address } => to_json_binary(&query_user(deps, address)?),
        QueryMsg::GetUserByEmail { email } => to_json_binary(&query_user_by_email(deps, email)?),
        QueryMsg::GetTotalUsers {} => to_json_binary(&query_total_users(deps)?),
        QueryMsg::GetTierConfig { tier } => to_json_binary(&query_tier_config(deps, tier)?),
        QueryMsg::GetAllTierConfigs {} => to_json_binary(&query_all_tier_configs(deps)?),
        QueryMsg::GetUserSubscription { address } => {
            to_json_binary(&query_user_subscription(deps, address)?)
        }
    }
}

pub fn execute_register_user(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    email: String,
    name: Option<String>,
    public_key: String,
    signature: String,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Basic validation
    if !is_valid_email(&email) {
        return Err(ContractError::InvalidEmail {});
    }

    // Check if email is already registered
    if EMAIL_TO_ADDR.may_load(deps.storage, &email)?.is_some() {
        return Err(ContractError::EmailAlreadyRegistered {});
    }

    // Check if wallet address is already registered
    if USERS.may_load(deps.storage, &sender)?.is_some() {
        return Err(ContractError::WalletAlreadyRegistered {});
    }
    
    // Validate public key format (try to decode from base64)
    match base64::decode(&public_key) {
        Ok(bytes) => {
            // Check if it's a valid ed25519 public key (32 bytes)
            if bytes.len() != 32 {
                return Err(ContractError::Std(StdError::generic_err(
                    "Invalid public key length"
                )));
            }
        },
        Err(_) => {
            return Err(ContractError::Std(StdError::generic_err(
                "Invalid public key encoding"
            )));
        }
    }
    
    // Verify signature to prove ownership of the private key
    // Message should be a combination of address, email, and timestamp
    let timestamp = env.block.time.seconds().to_string();
    let message_to_verify = format!("{}:{}:{}", sender, email, timestamp);
    
    if !crate::crypto::verify_signature(&public_key, &message_to_verify, &signature)? {
        return Err(ContractError::Std(StdError::generic_err(
            "Invalid signature - cannot verify ownership of private key"
        )));
    }

    // Current timestamp
    let now = env.block.time.seconds();

    // Load the Free tier config using string key
    // let free_key = tier_to_key(&SubscriptionTier::Free);
    // let free_tier_config = TIER_CONFIGS.load(deps.storage, &free_key)?;

    // Create free subscription for the user
    let subscription = UserSubscription::new(
        SubscriptionTier::Free,
        0,
        u64::MAX,   // Free tier doesn't expire
        false,      // Not linked to treasury yet
        now,        // Set initial reset time to now
        None,
        None,
    );

    // Create new user with free subscription and public key
    let user = User::new(
        sender.clone(),
        email.clone(),
        true, // Pre-verified by Abstraxion/Burnt wallet
        now,
        now,
        name,
        subscription,
        Some(public_key.clone()),
    );

    // Save user data
    USERS.save(deps.storage, &sender, &user)?;
    EMAIL_TO_ADDR.save(deps.storage, &email, &sender)?;

    // Increment user counter
    let total_users = TOTAL_USERS.load(deps.storage)? + 1;
    TOTAL_USERS.save(deps.storage, &total_users)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_attribute("action", "register_user")
        .add_attribute("email", email)
        .add_attribute("tier", "Free")
        .add_attribute("public_key_registered", "true")
        .add_attribute("signature_verified", "true")
        .add_attributes(log_entry))
}

pub fn execute_update_public_key(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    public_key: String,
    signature: String,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;
    
    // Get the current public key
    let current_public_key = user.public_key().clone()
        .ok_or(ContractError::Std(StdError::generic_err("No public key found")))?;
    
    // Validate new public key format (try to decode from base64)
    match base64::decode(&public_key) {
        Ok(bytes) => {
            // Check if it's a valid ed25519 public key (32 bytes)
            if bytes.len() != 32 {
                return Err(ContractError::Std(StdError::generic_err(
                    "Invalid public key length"
                )));
            }
        },
        Err(_) => {
            return Err(ContractError::Std(StdError::generic_err(
                "Invalid public key encoding"
            )));
        }
    }

    // Verify signature with the current public key
    // Message should include the new public key to prove ownership of both keys
    let timestamp = env.block.time.seconds().to_string();
    let message = format!("update_key:{}:{}:{}", sender, public_key, timestamp);
    
    if !verify_signature(&current_public_key, &message, &signature)? {
        return Err(ContractError::Unauthorized {});
    }

    // Update the user's public key
    user.set_public_key(Some(public_key.clone()));
    
    // Save updated user data
    USERS.save(deps.storage, &sender, &user)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_attribute("action", "update_public_key")
        .add_attribute("user", sender.to_string())
        .add_attribute("public_key_updated", "true")
        .add_attribute("timestamp", timestamp)
        .add_attributes(log_entry))
}


pub fn execute_update_config(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    new_admin: Option<String>,
    burnt_wallet_api_key: Option<String>,
    treasury_admin: Option<String>,
) -> Result<Response, ContractError> {
    // Load config and check admin authorization
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != *config.admin() {
        return Err(ContractError::Unauthorized {});
    }

    // Update admin if provided
    if let Some(new_admin) = new_admin {
        config.set_admin(deps.api.addr_validate(&new_admin)?);
    }

    // Update Burnt wallet API key if provided
    if let Some(burnt_wallet_api_key) = burnt_wallet_api_key {
        config.set_burnt_wallet_api_key(burnt_wallet_api_key);
    }

    // Update treasury admin if provided
    if let Some(treasury_admin) = treasury_admin {
        config.set_treasury_admin(deps.api.addr_validate(&treasury_admin)?);
    }

    // Save updated config
    CONFIG.save(deps.storage, &config)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &info.sender);

    Ok(Response::new()
        .add_attribute("action", "update_config")
        .add_attributes(log_entry))
}

// Configure subscription tier (admin only)
pub fn execute_configure_tier(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    tier: SubscriptionTier,
    price: Uint128,
    cv_limit: u32,
    treasury_address: String,
) -> Result<Response, ContractError> {
    // Check admin authorization
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin() {
        return Err(ContractError::Unauthorized {});
    }

    // Validate treasury address
    let treasury_addr = deps.api.addr_validate(&treasury_address)?;
    

    // CV limit check - different limits for different tiers
    if matches!(tier, SubscriptionTier::Free) && cv_limit > 2 {
        return Err(ContractError::Std(StdError::generic_err(
            "Free tier CV limit cannot exceed 2"
        )));
    } else if !matches!(tier, SubscriptionTier::Free) && cv_limit > 1000 {
        return Err(ContractError::Std(StdError::generic_err(
            "Paid tier CV limit cannot exceed 1000"
        )));
    }
    

    // Create tier configuration 
    let tier_config = TierConfig::new(
        tier.clone(),
        price,
        cv_limit,
        treasury_addr.clone(),
    );

    // Convert tier to string key for storage
    let tier_key = tier_to_key(&tier);

    // Save tier configuration
    TIER_CONFIGS.save(deps.storage, &tier_key, &tier_config)?;
    
    // Create a proper event
    let event = Event::new("tier_configured")
        .add_attribute("tier", format!("{:?}", tier))
        .add_attribute("price", price.to_string())
        .add_attribute("cv_limit", cv_limit.to_string())
        .add_attribute("treasury", treasury_addr.to_string())
        .add_attribute("admin", info.sender.to_string())
        .add_attribute("timestamp", env.block.time.seconds().to_string());

    // Log tier configuration
    Ok(Response::new()
        .add_event(event)
        .add_attribute("action", "configure_tier")
        .add_attribute("tier", format!("{:?}", tier))
        .add_attribute("price", price.to_string())
        .add_attribute("cv_limit", cv_limit.to_string())
        .add_attribute("treasury_address", treasury_addr.to_string())
        .add_attribute("timestamp", env.block.time.seconds().to_string()))
}

// Record a CV generation (authorized users only)
pub fn execute_record_cv_generation(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user_address: String,
    timestamp: u64,
    signature: String,
) -> Result<Response, ContractError> {
    // Validate user address
    let user_addr = deps.api.addr_validate(&user_address)?;

    // Check if we need a global reset
    let global_reset = check_global_reset(&mut deps, &env)?;

    // Check if user exists and get their data
    let mut user = USERS
        .may_load(deps.storage, &user_addr)?
        .ok_or(ContractError::UserNotFound {})?;
    
    // Check if the user has a public key
    let public_key = user.public_key().clone().ok_or(
        ContractError::Std(StdError::generic_err("User has no public key registered"))
    )?;

    // If global reset happened and user is on free tier, reset their credits
    let mut user_reset = false;
    if global_reset && matches!(user.subscription().tier(), SubscriptionTier::Free) {
        user.subscription_mut().set_cvs_generated(0);
        user_reset = true;
    }

    // Get user's tier config
    let tier_key = tier_to_key(&user.subscription().tier());
    let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;

    // Create the message that was signed (user address + timestamp)
    let message = format!("{}{}", user_addr, timestamp);
    
    // Verify signature
    if !verify_signature(&public_key, &message, &signature)? {
        return Err(ContractError::Unauthorized {});
    }
    
    // Check authorization (allow admin, treasury, or the user themselves)
    let config = CONFIG.load(deps.storage)?;
    let is_authorized = info.sender == user_addr 
        || info.sender == config.admin()
        || info.sender == tier_config.treasury_address();
    
    if !is_authorized {
        return Err(ContractError::Unauthorized {});
    }

    // Check if user's subscription is expired
    let now = env.block.time.seconds();
    if now > user.subscription().expiration() {
        return Err(ContractError::Std(StdError::generic_err(
            "Subscription expired",
        )));
    }

    // Check if user has reached CV limit
    if user.subscription().cvs_generated() >= tier_config.cv_limit() && tier_config.cv_limit() > 0 {
        return Err(ContractError::Std(StdError::generic_err(format!(
            "CV limit reached: {}. Next reset on the 1st of the month.",
            tier_config.cv_limit()
        ))));
    }
    
    // Generate a secure token for backend communication
    let nonce = format!("{:x}", Sha256::digest(signature.as_bytes()));
    let session_token = generate_encrypted_secure_token(
        &user_addr.to_string(), 
        now, 
        &nonce, 
        &public_key
    )?;    
    // Store the signature associated with the user
    user.subscription_mut().set_signature(Some(signature.clone()));
    user.subscription_mut().set_session_token(Some(session_token.clone()));
    
    // Save updated user data
    USERS.save(deps.storage, &user_addr, &user)?;

    // Emit an event with the session token for backend
    let event = Event::new("cv_request")
        .add_attribute("user", user_addr.to_string())
        .add_attribute("timestamp", timestamp.to_string())
        .add_attribute("token", session_token);

    Ok(Response::new()
        .add_event(event)
        .add_attribute("action", "record_cv_generation")
        .add_attribute("user", user_addr.to_string())
        .add_attribute("tier", format!("{:?}", user.subscription().tier()))
        .add_attribute("cv_count", user.subscription().cvs_generated().to_string())
        .add_attribute("cv_limit", tier_config.cv_limit().to_string())
        .add_attribute("remaining_credits", 
            (tier_config.cv_limit() - user.subscription().cvs_generated()).to_string())
        .add_attribute("global_reset", global_reset.to_string())
        .add_attribute("credits_reset", user_reset.to_string()))
}

// Update credit deduction function
pub fn execute_deduct_cv_credit(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    user_address: String,
    signature: String,
) -> Result<Response, ContractError> {
    // Validate user address
    let user_addr = deps.api.addr_validate(&user_address)?;

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &user_addr)?
        .ok_or(ContractError::UserNotFound {})?;
    
    // Get the user's public key
    let public_key = user.public_key().clone().ok_or(
        ContractError::Std(StdError::generic_err("User has no public key registered"))
    )?;
    
    // Get session token from previous request
    let encrypted_token = user.subscription().session_token().clone().ok_or(
        ContractError::Std(StdError::generic_err("No active CV generation request"))
    )?;
    
  // First verify the signature matches the encrypted token
    let message = format!("{}{}", user_addr, encrypted_token);
    if !verify_signature(&public_key, &message, &signature)? {
        return Err(ContractError::Unauthorized {});
    }

    // Then decrypt and verify the token itself (validates timestamp, etc.)
    let _decrypted_token = decrypt_and_verify_secure_token(
        &encrypted_token,
        &user_addr.to_string(),
        &public_key,
        3600, // 1 hour validity
        env.block.time.seconds()
    )?;
       
     // Get user's tier config to check their credit limit
    let tier_key = tier_to_key(&user.subscription().tier());
    let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;

    // Check if user has credits remaining
    if user.subscription().cvs_generated() < tier_config.cv_limit() {
        // Increment user's CV count
        let cvs_generated = user.subscription().cvs_generated() + 1;
        user.subscription_mut().set_cvs_generated(cvs_generated);
        
        // Clear the session token after using it
        user.subscription_mut().set_session_token(None);
        
        // Save updated user data
        USERS.save(deps.storage, &user_addr, &user)?;
        
        // Increment the total CV count in the app
        let total_cvs = TOTAL_CVS.load(deps.storage)? + 1;
        TOTAL_CVS.save(deps.storage, &total_cvs)?;
        
        let remaining = tier_config.cv_limit() - cvs_generated;
        
        return Ok(Response::new()
            .add_attribute("action", "deduct_cv_credit")
            .add_attribute("user", user_addr.to_string())
            .add_attribute("cv_count", cvs_generated.to_string())
            .add_attribute("credits_remaining", remaining.to_string())
            .add_attribute("total_cvs", total_cvs.to_string()));
    } else {
        return Err(ContractError::Std(StdError::generic_err(format!(
            "Credit limit reached: {}", tier_config.cv_limit()
        ))));
    }
}

// Subscribe to a paid tier - requires payment
pub fn execute_subscribe(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    tier: SubscriptionTier,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;

    // Check if the requested tier is Free - can't "subscribe" to free tier
    if matches!(tier, SubscriptionTier::Free) {
        return Err(ContractError::Std(StdError::generic_err(
            "Cannot subscribe to Free tier, it's the default tier",
        )));
    }

    // Load tier configuration using string key
    let tier_key = tier_to_key(&tier);
    let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;

    // Check if user has sent enough payment - Using our custom checker
    let payment = check_payment(&info, "uxion").map_err(|e| ContractError::Std(e))?;

    if payment < tier_config.price() {
        return Err(ContractError::Std(StdError::generic_err(format!(
            "Insufficient payment. Required: {} uxion, Received: {} uxion",
            tier_config.price(), payment
        ))));
    }

    // Forward payment to tier's treasury
    let forward_msg = BankMsg::Send {
        to_address: tier_config.treasury_address().to_string(),
        amount: vec![Coin {
            denom: "uxion".to_string(),
            amount: payment,
        }],
    };

    // Current timestamp
    let now = env.block.time.seconds();

    // Set expiration (30 days from now)
    let expiration = now + 30 * 24 * 60 * 60;

    // Get old tier key for stats update
    let old_tier_key = tier_to_key(&user.subscription().tier());

    // Update user's subscription
    let old_tier = user.subscription().tier().clone();
    user.set_subscription(UserSubscription::new(
        tier.clone(),
        0, // Reset on new subscription
        expiration,
        false, // Will be linked separately
        now,
        None,
        None,
    ));

    // Save updated user data
    USERS.save(deps.storage, &sender, &user)?;

    // Update tier statistics
    if !matches!(old_tier, SubscriptionTier::Free) {
        // Decrement old tier counter if not free
        let mut old_tier_count = TOTAL_PAID_USERS
            .load(deps.storage, &old_tier_key)
            .unwrap_or(0);
        if old_tier_count > 0 {
            old_tier_count -= 1;
            TOTAL_PAID_USERS.save(deps.storage, &old_tier_key, &old_tier_count)?;
        }
    }

    // Increment new tier counter
    let new_tier_count = TOTAL_PAID_USERS.load(deps.storage, &tier_key).unwrap_or(0) + 1;
    TOTAL_PAID_USERS.save(deps.storage, &tier_key, &new_tier_count)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_message(forward_msg)
        .add_attribute("action", "subscribe")
        .add_attribute("tier", format!("{:?}", tier))
        .add_attribute("payment", payment.to_string())
        .add_attribute("expiration", expiration.to_string())
        .add_attributes(log_entry))
}

// Update user's last login timestamp
pub fn execute_update_last_login(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;

    // Update last login timestamp
    let now = env.block.time.seconds();
    user.set_last_login(now);

    // Save updated user data
    USERS.save(deps.storage, &sender, &user)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_attribute("action", "update_last_login")
        .add_attribute("user", sender.to_string())
        .add_attribute("timestamp", now.to_string())
        .add_attributes(log_entry))
}

// Update user profile information
pub fn execute_update_profile(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    name: Option<String>,
    email: Option<String>,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;

    // Update email if provided
    if let Some(new_email) = email {
        // Validate email format
        if !is_valid_email(&new_email) {
            return Err(ContractError::InvalidEmail {});
        }

        // Check if new email is already registered
        if new_email != *user.email() {
            if let Some(_) = EMAIL_TO_ADDR.may_load(deps.storage, &new_email)? {
                return Err(ContractError::EmailAlreadyRegistered {});
            }

            // Remove old email mapping
            EMAIL_TO_ADDR.remove(deps.storage, &user.email());

            // Add new email mapping
            EMAIL_TO_ADDR.save(deps.storage, &new_email, &sender)?;

            // Update user's email
            user.set_email(new_email);
            // Keep email verified status (pre-verified by integration)
            user.set_email_verified(true);
        }
    }

    // Update name if provided
    if let Some(new_name) = name {
        user.set_name(Some(new_name));
    }

    // Save updated user data
    USERS.save(deps.storage, &sender, &user)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_attribute("action", "update_profile")
        .add_attributes(log_entry))
}

// Link user to treasury (treasury admin only)
pub fn execute_link_user_to_treasury(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user_address: String,
) -> Result<Response, ContractError> {
    // Check treasury admin authorization
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.treasury_admin() && info.sender != config.admin() {
        return Err(ContractError::Unauthorized {});
    }

    // Validate user address
    let user_addr = deps.api.addr_validate(&user_address)?;

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &user_addr)?
        .ok_or(ContractError::UserNotFound {})?;

    // Check if user is on a paid tier
    if matches!(user.subscription().tier(), SubscriptionTier::Free) {
        return Err(ContractError::Std(StdError::generic_err(
            "Cannot link free tier users to treasury",
        )));
    }

    // Mark user as linked to treasury
    // user.subscription.set_treasury_linked(true);
    user.subscription_mut().set_treasury_linked(true);


    // Save updated user data
    USERS.save(deps.storage, &user_addr, &user)?;

    // Log the action
    let log_entry = create_log_entry(&env, &info.sender);

    Ok(Response::new()
        .add_attribute("action", "link_user_to_treasury")
        .add_attribute("user", user_addr.to_string())
        .add_attribute("tier", format!("{:?}", user.subscription().tier()))
        .add_attributes(log_entry))
}

pub fn query_user_subscription(deps: Deps, address: String) -> StdResult<UserSubscriptionResponse> {
    let addr = deps.api.addr_validate(&address)?;

    let user = USERS.load(deps.storage, &addr)?;
    let tier_key = tier_to_key(&user.subscription().tier());
    let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;

    Ok(UserSubscriptionResponse {
        subscription: user.subscription().clone(),
        tier_config,
    })
}

// Get contract configuration
pub fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;

    Ok(ConfigResponse {
        admin: config.admin().clone(),
        burnt_wallet_api_key: config.burnt_wallet_api_key().clone(),
        treasury_admin: config.treasury_admin().clone(),
    })
}

// Query user by address
pub fn query_user(deps: Deps, address: Option<String>) -> StdResult<UserResponse> {
    let addr = match address {
        Some(addr) => deps.api.addr_validate(&addr)?,
        None => return Err(StdError::generic_err("User address is required")),
    };

    let user = USERS.may_load(deps.storage, &addr)?;

    Ok(UserResponse { user })
}

// Find user address by email
pub fn query_user_by_email(deps: Deps, email: String) -> StdResult<UserAddressResponse> {
    let address = EMAIL_TO_ADDR.may_load(deps.storage, &email)?;

    Ok(UserAddressResponse { address })
}

// Get total users count
pub fn query_total_users(deps: Deps) -> StdResult<TotalUsersResponse> {
    let total_users = TOTAL_USERS.load(deps.storage)?;

    Ok(TotalUsersResponse { total_users })
}

// Get tier configuration
pub fn query_tier_config(deps: Deps, tier: SubscriptionTier) -> StdResult<TierConfigResponse> {
    let tier_key = tier_to_key(&tier);
    let config = TIER_CONFIGS.load(deps.storage, &tier_key)?;
    Ok(TierConfigResponse { config })
}

// Get all tier configs
pub fn query_all_tier_configs(deps: Deps) -> StdResult<AllTierConfigsResponse> {
    let tiers = [
        SubscriptionTier::Free,
        SubscriptionTier::Basic,
        SubscriptionTier::Standard,
        SubscriptionTier::Premium,
    ];

    let mut configs = Vec::new();

    for tier in tiers.iter() {
        let key = tier_to_key(tier);
        if let Ok(config) = TIER_CONFIGS.load(deps.storage, &key) {
            configs.push((tier.clone(), config));
        }
    }

    Ok(AllTierConfigsResponse { configs })
}



#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{Addr, Attribute, OwnedDeps, Uint128};

    #[test]
    fn initialization_with_sender_as_default_admin() {
        // Create mock dependencies, environment and info
        let mut deps = mock_dependencies();
        let env = mock_env();
        let sender = "xion1creator";
        let info = message_info(&Addr::unchecked(sender), &vec![]);
        
        // Don't provide explicit admin, let it default to sender
        let msg = InstantiateMsg {
            admin: None,
            burnt_wallet_api_key: "test_api_key".to_string(),
            treasury_admin: None, // This should default to admin (which is sender)
        };
        
        // Execute initialization
        instantiate(deps.as_mut(), env, info, msg).unwrap();
        
        // Verify sender became both admin and treasury_admin
        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(*config.admin(), Addr::unchecked(sender));
        assert_eq!(*config.treasury_admin(), Addr::unchecked(sender));
    }


    //================================================
    //Configuration and Admin Functions
    //================================================

        // Setup helper function to initialize contract for testing
        fn setup_contract() -> (
            OwnedDeps<MockStorage, MockApi, MockQuerier>,
            Env,
            Addr, // admin address
        ) {
            let mut deps = mock_dependencies();
            let env = mock_env();
            
            // Initialize with standard test values
            let admin = Addr::unchecked("xion1admin");
            let treasury_admin = Addr::unchecked("xion1treasury");
            let api_key = "test_api_key".to_string();
            
            // Create config directly
            let config = Config::new(
                admin.clone(),
                api_key,
                treasury_admin,
            );
            
            // Save config
            CONFIG.save(deps.as_mut().storage, &config).unwrap();
            
            // Set up last global reset for testing
            LAST_GLOBAL_RESET.save(deps.as_mut().storage, &env.block.time.seconds()).unwrap();
            
            // Set up free tier as baseline
            let free_tier = TierConfig::new(
                SubscriptionTier::Free,
                Uint128::zero(),
                2,
                admin.clone(),
            );
            let free_key = tier_to_key(&SubscriptionTier::Free);
            TIER_CONFIGS.save(deps.as_mut().storage, &free_key, &free_tier).unwrap();
            
            (deps, env, admin)
        }
        
        #[test]
        fn test_query_config() {
            let (deps, _env, admin) = setup_contract();
            
            // Query the config
            let response = query_config(deps.as_ref()).unwrap();
            
            // Verify response matches what we saved
            assert_eq!(response.admin, admin);
            assert_eq!(response.burnt_wallet_api_key, "test_api_key");
            assert_eq!(response.treasury_admin, Addr::unchecked("xion1treasury"));
        }

        #[test]
        fn test_update_config_unauthorized() {
            let (mut deps, env, _admin) = setup_contract();
            
            // Create non-admin info
            let unauthorized_info = message_info(&Addr::unchecked("xion1unauthorized"), &[]);
            
            // Try to update config
            let result = execute_update_config(
                deps.as_mut(),
                env,
                unauthorized_info,
                Some("xion1hacker".to_string()),
                Some("hacked_key".to_string()),
                Some("xion1hacker".to_string()),
            );
            
            // Verify error
            assert!(matches!(result, Err(ContractError::Unauthorized {})));
            
            // Verify config was not changed
            let unchanged_config = CONFIG.load(&deps.storage).unwrap();
            assert_eq!(*unchanged_config.admin(), Addr::unchecked("xion1admin"));
            assert_eq!(*unchanged_config.burnt_wallet_api_key(), "test_api_key");
            assert_eq!(*unchanged_config.treasury_admin(), Addr::unchecked("xion1treasury"));
        }
        
        #[test]
        fn test_update_config_partial() {
            let (mut deps, env, admin) = setup_contract();
            
            // Create admin info
            let info = message_info(&admin, &[]);
            
            // Update only API key
            let response = execute_update_config(
                deps.as_mut(),
                env.clone(),
                info,
                None,
                Some("partial_update_key".to_string()),
                None,
            ).unwrap();
            
            // Verify basic response
            assert_eq!(response.attributes[0], Attribute::new("action", "update_config"));
            
            // Verify partial update
            let updated_config = CONFIG.load(&deps.storage).unwrap();
            assert_eq!(*updated_config.admin(), Addr::unchecked("xion1admin")); // Unchanged
            assert_eq!(*updated_config.burnt_wallet_api_key(), "partial_update_key"); // Changed
            assert_eq!(*updated_config.treasury_admin(), Addr::unchecked("xion1treasury")); // Unchanged
        }
        
        #[test]
        fn test_query_tier_config() {
            let (mut deps, _env, admin) = setup_contract();
            
            // Set up a test tier
            let standard_tier = TierConfig::new(
                SubscriptionTier::Standard,
                Uint128::new(5000),
                10,
                admin.clone(),
            );
            let tier_key = tier_to_key(&SubscriptionTier::Standard);
            TIER_CONFIGS.save(deps.as_mut().storage, &tier_key, &standard_tier).unwrap();
            
            // Query the tier
            let response = query_tier_config(deps.as_ref(), SubscriptionTier::Standard).unwrap();
            
            // Verify tier config
            assert_eq!(*response.config.tier(), SubscriptionTier::Standard);
            assert_eq!(response.config.price(), Uint128::new(5000));
            assert_eq!(response.config.cv_limit(), 10);
            assert_eq!(*response.config.treasury_address(), admin);
        }

        #[test]
        fn test_configure_tier_unauthorized() {
            let (mut deps, env, _admin) = setup_contract();
            
            // Create non-admin info
            let unauthorized_info = message_info(&Addr::unchecked("xion1unauthorized"), &[]);
            
            // Try to configure a tier
            let result = execute_configure_tier(
                deps.as_mut(),
                env,
                unauthorized_info,
                SubscriptionTier::Premium,
                Uint128::new(10000),
                15,
                "xion1treasury".to_string(),
            );
            
            // Verify error
            assert!(matches!(result, Err(ContractError::Unauthorized {})));
        }

        #[test]
        fn test_query_all_tier_configs() {
            let (mut deps, _env, admin) = setup_contract();
            
            // Setup all tiers
            let tiers = [
                (SubscriptionTier::Basic, Uint128::new(1500), 3),
                (SubscriptionTier::Standard, Uint128::new(5000), 5),
                (SubscriptionTier::Premium, Uint128::new(10000), 15),
            ];
            
            for (tier, price, cv_limit) in tiers.iter() {
                let tier_config = TierConfig::new(
                    tier.clone(),
                    *price,
                    *cv_limit,
                    admin.clone(),
                );
                let tier_key = tier_to_key(tier);
                TIER_CONFIGS.save(deps.as_mut().storage, &tier_key, &tier_config).unwrap();
            }
            
            // Query all tiers
            let response = query_all_tier_configs(deps.as_ref()).unwrap();
            
            // Verify all tiers are returned (4 including Free)
            assert_eq!(response.configs.len(), 4);
            
            // Verify specific tier data
            for (tier, config) in response.configs.iter() {
                match tier {
                    SubscriptionTier::Free => {
                        assert_eq!(config.price(), Uint128::zero());
                        assert_eq!(config.cv_limit(), 2);
                    }
                    SubscriptionTier::Basic => {
                        assert_eq!(config.price(), Uint128::new(1500));
                        assert_eq!(config.cv_limit(), 3);
                    }
                    SubscriptionTier::Standard => {
                        assert_eq!(config.price(), Uint128::new(5000));
                        assert_eq!(config.cv_limit(), 5);
                    }
                    SubscriptionTier::Premium => {
                        assert_eq!(config.price(), Uint128::new(10000));
                        assert_eq!(config.cv_limit(), 15);
                    }
                }
            }
        }
}
