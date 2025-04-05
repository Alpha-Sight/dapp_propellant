# Propellant Smart Contract Documentation

## 1. Project Overview

Propellant is a CV analysis and enhancement platform built on the Xion blockchain. The system provides a subscription-based service where users can create, enhance, and manage their CVs with different tiers of access.

The smart contract implements:

- User authentication with ED25519 cryptography.
- Tiered subscription management with Xion token payments.
- Secure token generation for CV processing requests.
- Monthly usage limits with automatic resets

## 2. Architecture
### 2.1 Smart Contract Components 

```sh
propellant-contract/
├── src/
│   ├── contract.rs      # Main contract logic
│   ├── crypto.rs        # Cryptographic functions
│   ├── state.rs         # Storage definitions
│   ├── msg.rs           # Message structures
│   ├── error.rs         # Error definitions
│   └── helpers.rs       # Utility functions
└── Cargo.toml
```

### 2.2 Entry Points
The contract exposes three standard CosmWasm entry points:

```sh
// Initialize the contract
pub fn instantiate(deps: DepsMut, env: Env, info: MessageInfo, msg: InstantiateMsg) 
    -> Result<Response, ContractError>

// Execute state-changing operations
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) 
    -> Result<Response, ContractError>

// Read-only query operations
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) 
    -> StdResult<Binary>
```

## 3. Subscription System
### 3.1 Tier Structure



### 3.2 Configuration
```sh
pub fn execute_configure_tier(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    tier: SubscriptionTier,
    price: Uint128,
    cv_limit: u32,
    treasury_address: String,
) -> Result<Response, ContractError>
```


## 4. Security Implementation
### 4.2 Secure Token Generation
The contract uses AES-GCM encryption for secure token generation:

Key security features:

- Deterministic encryption keys derived from user data and time
- Nonce generation to prevent replay attacks
- Signature validation for token integrity


## 5. CV Generation Flow
### Request Token Generation

```sh
pub fn execute_record_cv_generation(deps: DepsMut, env: Env, info: MessageInfo)
```

### Process CV in External System

- Frontend uses token to authenticate with API
- CV is processed in the AI system

### Deduct CV Credit
```sh
pub fn execute_deduct_cv_credit(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    user_address: String,
    secure_token: String
)
```


## 6. Development and Deployment
### 6.1 Build Instructions
```sh
# Install Rust and Wasm target
rustup default stable
rustup target add wasm32-unknown-unknown

# Clone repository
git clone https://github.com/xion-network/propellant-contract
cd propellant-contract

# Build contract
cargo wasm

# Optimize Wasm binary
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.12.8
```

### 6.2 Testing
```sh
# Run all tests
cargo test

# Run specific test
cargo test test_verify_signature
```
## 7. Usage Examples
### 7.1 Registering a User
```sh
xion tx wasm execute $CONTRACT_ADDR '{"register_user":{"name":"John Doe"}}' \
  --from user1 --chain-id xion-testnet-2 --gas-prices 0.025uxion --gas auto --gas-adjustment 1.3
```

### 7.2 Subscribing to a Tier
```sh
xion tx wasm execute $CONTRACT_ADDR '{"subscribe":{"tier":"Standard"}}' \
  --amount 5000uxion --from user1 --chain-id xion-testnet-2
```
### 7.3 Updating Public Key
```sh
xion tx wasm execute $CONTRACT_ADDR '{
  "update_public_key":{
    "public_key":"BASE64_ENCODED_KEY",
    "signature":"HEX_ENCODED_SIGNATURE"
  }
}' --from user1 --chain-id xion-testnet-2
```
### 7.4 Generating CV Token

```sh
xion tx wasm execute $CONTRACT_ADDR '{"record_cv_generation":{}}' \
  --from user1 --chain-id xion-testnet-2
```
## 8. Security Considerations

- All tokens expire after 1 hour
- Monthly limits are enforced through global reset mechanism
- Treasury addresses are validated for payment security
- All cryptographic primitives use industry-standard algorithms
- Comprehensive test suite covers edge cases and attack vectors

## 9. Contract Queries
The contract supports various queries to retrieve state information:
```sh
enum QueryMsg {
    GetConfig {},
    GetUser { address: Option<String> },
    GetUserToken { address: String },
    GetTotalUsers {},
    GetTierConfig { tier: SubscriptionTier },
    GetAllTierConfigs {},
    GetUserSubscription { address: String },
}
```
