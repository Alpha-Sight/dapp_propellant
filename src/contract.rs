#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cw2::set_contract_version;

use cosmwasm_std::{to_json_binary, BankMsg, Binary, Coin, Deps, DepsMut, Env, Event, MessageInfo, Response, StdError, StdResult, Uint128};

use crate::crypto::{generate_encrypted_secure_token, verify_signature, decrypt_and_verify_secure_token};

use sha2::{Sha256, Digest};

// use crate::auth::jwt::verify;
use crate::error::ContractError;
use crate::helpers::{check_global_reset, check_payment, create_log_entry};
use crate::msg::{
    AllTierConfigsResponse, ConfigResponse, ExecuteMsg, GetUserTokenResponse, InstantiateMsg, QueryMsg, TierConfigResponse, TotalUsersResponse, UserResponse, UserSubscriptionResponse
};
use crate::state::{
    tier_to_key, Config, SubscriptionTier, TierConfig, User, UserSubscription, CONFIG, LAST_GLOBAL_RESET, TIER_CONFIGS, TOTAL_CVS, TOTAL_PAID_USERS, TOTAL_USERS, USERS
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
        ExecuteMsg::RegisterUser { name } => {
            execute_register_user(deps, env, info, name)
        },
        ExecuteMsg::UpdateLastLogin {} => execute_update_last_login(deps, env, info),
        ExecuteMsg::UpdateUserProfile { name } => {
            execute_update_profile(deps, env, info, name)
        }
        ExecuteMsg::UpdatePublicKey { public_key, signature } => {
            execute_update_public_key(deps, env, info, public_key, signature)
        },
        // Subscription management
        ExecuteMsg::Subscribe { tier } => execute_subscribe(deps, env, info, tier),
        ExecuteMsg::LinkUserToTreasury { user_address } => {
            execute_link_user_to_treasury(deps, env, info, user_address)
        }
        ExecuteMsg::RecordCvGeneration {} => {
            // let timestamp = env.block.time.seconds();
            execute_record_cv_generation(deps, env, info)
        }
        ExecuteMsg::DeductCvCredit { user_address, secure_token } => {
            execute_deduct_cv_credit(deps, env, info, user_address, secure_token)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_json_binary(&query_config(deps)?),
        QueryMsg::GetUser { address } => to_json_binary(&query_user(deps, address)?),
        QueryMsg::GetUserToken { address } => to_json_binary(&query_user_token(deps, address)?),
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
    name: Option<String>,
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if wallet address is already registered
    if let Some(existing_user) = USERS.may_load(deps.storage, &sender)? {
        // Wallet already registered, return existing user data
        return Ok(Response::new()
            .add_attribute("action", "get_existing_user")
            .add_attribute("name", existing_user.name().cloned().unwrap_or_default())
            .add_attribute("tier", existing_user.subscription().tier().to_string())
            .add_attribute("cvs_generated", existing_user.subscription().cvs_generated().to_string())
            .add_attribute("is_existing_user", "true")
            // Load tier config to get CV limit
            .add_attribute("cv_limit", {
                let tier_key = tier_to_key(existing_user.subscription().tier());
                let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;
                tier_config.cv_limit().to_string()
            })
        );
    }

    // Current timestamp
    let now = env.block.time.seconds();

    // Load the Free tier config to get its CV limit
    let free_key = tier_to_key(&SubscriptionTier::Free);
    let free_tier_config = TIER_CONFIGS.load(deps.storage, &free_key)?;
    
    // Create free subscription with CV limit from tier config
    let subscription = UserSubscription::new(
        SubscriptionTier::Free,
        0,  // No CVs generated yet
        u64::MAX,  // Free tier doesn't expire
        false,     // Not linked to treasury yet
        now,       // Set initial reset time to now
        None,      // No signature needed
        None,      // No session token needed
    );

    // Create new user with free subscription
    let user = User::new(
        sender.clone(),
        now,
        now,
        name,
        subscription,
        None,
    );

    // Save user data
    USERS.save(deps.storage, &sender, &user)?;

    // Increment user counter
    let total_users = TOTAL_USERS.load(deps.storage)? + 1;
    TOTAL_USERS.save(deps.storage, &total_users)?;

    // Standard log entry format
    let log_entry = create_log_entry(&env, &sender);

    Ok(Response::new()
        .add_attribute("action", "register_user")
        .add_attribute("tier", "Free")
        .add_attribute("cv_limit", free_tier_config.cv_limit().to_string())
        .add_attribute("is_existing_user", "false")
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
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;
    
    // Check if user already has an active CV generation request
    if user.subscription().session_token().is_some() {
        return Err(ContractError::Std(StdError::generic_err(
            "You already have an active CV generation request"
        )));
    }

    // Check for global reset (monthly)
    let global_reset = check_global_reset(&mut deps, &env)?;

    // If global reset happened and user is on free tier, reset their credits
    let mut _user_reset = false;
    if global_reset && matches!(user.subscription().tier(), SubscriptionTier::Free) {
        user.subscription_mut().set_cvs_generated(0);
        _user_reset = true;
    }

    // Get user's tier config
    let tier_key = tier_to_key(user.subscription().tier());
    let tier_config = TIER_CONFIGS.load(deps.storage, &tier_key)?;

    // Check if user's subscription is expired
    let now = env.block.time.seconds();
    if now > user.subscription().expiration() {
        return Err(ContractError::Std(StdError::generic_err("Subscription expired")));
    }

    // Check if user has reached CV limit
    if user.subscription().cvs_generated() >= tier_config.cv_limit() && tier_config.cv_limit() > 0 {
        return Err(ContractError::Std(StdError::generic_err(format!(
            "CV limit reached: {}. Next reset on the 1st of the month.",
            tier_config.cv_limit()
        ))));
    }
    
    // Retrieve or generate public key for the user
    let public_key = match user.public_key() {
        Some(pk) => pk.clone(),
        None => {
            // Generate a deterministic public key based on user address and timestamp
            let seed_material = format!("{}:{}", sender.to_string(), now / 86400); // Daily rotation
            let key_hash = Sha256::digest(seed_material.as_bytes());
            base64::encode(&key_hash[0..32]) // Use first 32 bytes as key
        }
    };
    
    // Generate a unique nonce using block data
    let nonce = format!("{}:{}:{}", 
        env.block.height,
        env.block.time.nanos(),
        hex::encode(&Sha256::digest(sender.to_string().as_bytes())[0..4])
    );
    
    // Generate an encrypted secure token
    let encrypted_token = generate_encrypted_secure_token(
        &sender.to_string(),
        now,
        &nonce,
        &public_key
    )?;
    
    // Store the token in the user's session_token
    user.subscription_mut().set_session_token(Some(encrypted_token.clone()));
    
    // Store/update the public key
    user.set_public_key(Some(public_key.clone()));
    
    // Update user's last login time
    user.set_last_login(now);
    
    // Save updated user data
    USERS.save(deps.storage, &sender, &user)?;
    
    // Create a frontend token (different format for passing to backend)
    // Format: encrypted_token:public_key:address
    let frontend_token = format!("{}:{}:{}", 
        encrypted_token,
        public_key,
        sender.to_string()
    );
    
    // Build the response with the token in attributes
    Ok(Response::new()
        .add_attribute("action", "record_cv_generation")
        .add_attribute("token", frontend_token))
}

// Update credit deduction function
pub fn execute_deduct_cv_credit(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user_address: String,
    secure_token: String,
) -> Result<Response, ContractError> {
    // Load config
    let config = CONFIG.load(deps.storage)?;
    
    // Only admins or authorized services can call this function
    if info.sender != config.admin() && 
       info.sender != config.treasury_admin() {
        return Err(ContractError::Unauthorized {});
    }
    
    // Validate user address
    let user_addr = deps.api.addr_validate(&user_address)?;

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &user_addr)?
        .ok_or(ContractError::UserNotFound {})?;
    
    // Parse the frontend token: encrypted_token:public_key:address
    let token_parts: Vec<&str> = secure_token.split(':').collect();
    if token_parts.len() < 5 {  // We need at least 5 parts (3 for encrypted token + public_key + address)
        return Err(ContractError::Std(StdError::generic_err(
            "Invalid token format"
        )));
    }
    
    // Extract parts - the first 3 parts belong to the encrypted token
    let encrypted_token = format!("{}:{}:{}", token_parts[0], token_parts[1], token_parts[2]);
    let provided_public_key = token_parts[3];
    let provided_address = token_parts[4];
    
    // Verify address matches
    if provided_address != user_address {
        return Err(ContractError::Std(StdError::generic_err(
            "Token address mismatch"
        )));
    }
    
    // Get stored token from user record
    let stored_token = user.subscription().session_token().clone().ok_or(
        ContractError::Std(StdError::generic_err("No active CV generation request"))
    )?;
    
    // Tokens must match exactly
    if stored_token != encrypted_token {
        return Err(ContractError::Std(StdError::generic_err(
            "Token doesn't match user's stored token"
        )));
    }
    
    // Get stored public key
    let stored_public_key = user.public_key().clone().ok_or(
        ContractError::Std(StdError::generic_err("No public key found for user"))
    )?;
    
    // Public keys must match
    if stored_public_key != provided_public_key {
        return Err(ContractError::Std(StdError::generic_err(
            "Public key mismatch"
        )));
    }
    
    // Decrypt and verify the token
    let _ = decrypt_and_verify_secure_token(
        &encrypted_token,
        &user_address,
        &stored_public_key,
        3600, // 1 hour validity
        env.block.time.seconds()
    )?;
    
    // Token is valid - proceed with credit deduction
    
    // Get user's tier config
    let tier_key = tier_to_key(user.subscription().tier());
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
        .add_attribute("credits_remaining", remaining.to_string()));
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
) -> Result<Response, ContractError> {
    let sender = info.sender.clone();

    // Check if user exists
    let mut user = USERS
        .may_load(deps.storage, &sender)?
        .ok_or(ContractError::UserNotFound {})?;


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


// Get total users count
pub fn query_total_users(deps: Deps) -> StdResult<TotalUsersResponse> {
    let total_users = TOTAL_USERS.load(deps.storage)?;

    Ok(TotalUsersResponse { total_users })
}

fn query_user_token(deps: Deps, address: String) -> StdResult<GetUserTokenResponse> {
    // Validate address
    let addr = deps.api.addr_validate(&address)?;
    
    // Get user data
    let user = USERS.load(deps.storage, &addr)?;
    
    // Extract the token and check if it exists
    let token = user.subscription().session_token().clone();
    let has_active_token = token.is_some();
    
    // Return the properly structured response
    Ok(GetUserTokenResponse {
        user_address: addr.to_string(),
        has_active_token,
        token,
        timestamp: user.last_login(),
    })
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
