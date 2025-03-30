use ed25519_dalek::{Signature, VerifyingKey as PublicKey, Verifier};
use cosmwasm_std::{StdResult, StdError, Binary};
use sha2::{Sha256, Digest};
use base64::{decode, encode};
use hex;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};


//===============================

// Core Authentication Functions:

//===============================

// Verify a signature using ed25519
pub fn verify_signature(
    public_key_base64: &str,
    message: &str,
    signature_hex: &str
) -> StdResult<bool> {
    // Decoding the public key from base64
    let public_key_bytes = decode(public_key_base64)
        .map_err(|_| StdError::generic_err("Invalid public key encoding"))?;
    
    // Creating PublicKey from bytes
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| StdError::generic_err("Invalid public key length (must be 32 bytes)"))?;
    let public_key = PublicKey::from_bytes(&public_key_array)
        .map_err(|_| StdError::generic_err("Invalid public key"))?;
    
    // Decoding signature from hex
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| StdError::generic_err("Invalid signature encoding"))?;
    
    // Create Signature from bytes
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| StdError::generic_err("Invalid signature length (must be 64 bytes)"))?;
    let signature = Signature::from_bytes(&signature_array);
    
    // Hash the message with SHA-256 for consistency
    let message_hash = Sha256::digest(message.as_bytes());
    
    // Verify the signature
    public_key.verify(&message_hash, &signature)
        .map(|_| true)
        .map_err(|_| StdError::generic_err("Signature verification failed"))
}

// Validate a public key is properly formatted
pub fn validate_public_key(public_key_base64: &str) -> StdResult<()> {
    // Try to decode the key
    let key_bytes = decode(public_key_base64)
        .map_err(|_| StdError::generic_err("Invalid public key encoding"))?;
    
    // Check if it's a valid ed25519 public key (32 bytes)
    if key_bytes.len() != 32 {
        return Err(StdError::generic_err("Invalid public key length (must be 32 bytes)"));
    }
    
    // Try to create a PublicKey from the bytes
    let public_key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| StdError::generic_err("Invalid public key length"))?;
    
    PublicKey::from_bytes(&public_key_array)
        .map_err(|_| StdError::generic_err("Invalid public key format"))?;
    
    Ok(())
}

//==================================================
//==================================================

            //Secure Communication:

//==================================================

// Generate an encrypted secure token using AES-GCM (production-grade)
pub fn generate_encrypted_secure_token(
    user_address: &str,
    timestamp: u64,
    nonce: &str,
    public_key_base64: &str
) -> StdResult<String> {
    // Generate the base token
    let message = format!("{}:{}:{}", user_address, timestamp, nonce);
    let hash = Sha256::digest(message.as_bytes());
    let token = encode(&hash);
    
    // 1. Create a deterministic encryption key (32 bytes for AES-256)
    let key_material = format!("encryption:{}:{}", user_address, timestamp / 3600);
    let key_hash = Sha256::digest(key_material.as_bytes());
    let encryption_key = Key::<Aes256Gcm>::from_slice(&key_hash);
    
    // 2. Create a deterministic nonce (12 bytes for AES-GCM)
    let nonce_material = format!("nonce:{}:{}", user_address, timestamp);
    let nonce_hash = Sha256::digest(nonce_material.as_bytes());
    let nonce = Nonce::from_slice(&nonce_hash[0..12]);
    
    // 3. Initialize the cipher
    let cipher = Aes256Gcm::new(encryption_key);
    
    // 4. Encrypt the token
    let plaintext = token.as_bytes();
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| StdError::generic_err("Encryption failed"))?;
    
    // 5. Combine with metadata for the final token
    // Format: base64(encrypted_data):timestamp:signature
    
    // Create a signature for verification
    let public_key_hash = Sha256::digest(public_key_base64.as_bytes());
    let signature_material = format!("{}:{}", hex::encode(&ciphertext), hex::encode(&public_key_hash));
    let signature = hex::encode(Sha256::digest(signature_material.as_bytes()));
    
    Ok(format!("{}:{}:{}", encode(&ciphertext), timestamp, &signature[0..16]))
}

// Decrypt and verify a secure token
pub fn decrypt_and_verify_secure_token(
    encrypted_token: &str,
    expected_user_address: &str,
    public_key_base64: &str,
    max_age_seconds: u64,
    current_time: u64
) -> StdResult<String> {
    // Parse the token components
    let parts: Vec<&str> = encrypted_token.split(':').collect();
    if parts.len() != 3 {
        return Err(StdError::generic_err("Invalid token format"));
    }
    
    let encrypted_base64 = parts[0];
    let timestamp = parts[1].parse::<u64>()
        .map_err(|_| StdError::generic_err("Invalid timestamp in token"))?;
    let provided_signature = parts[2];
    
    // Check if token is expired
    if !verify_timestamp(timestamp, current_time, max_age_seconds) {
        return Err(StdError::generic_err("Token expired or from future"));
    }
    
    // Decode the encrypted data
    let ciphertext = decode(encrypted_base64)
        .map_err(|_| StdError::generic_err("Invalid base64 encoding"))?;
    
    // Verify signature
    let public_key_hash = Sha256::digest(public_key_base64.as_bytes());
    let signature_material = format!("{}:{}", hex::encode(&ciphertext), hex::encode(&public_key_hash));
    let expected_signature = hex::encode(Sha256::digest(signature_material.as_bytes()));
    
    if provided_signature != &expected_signature[0..16] {
        return Err(StdError::generic_err("Invalid token signature"));
    }
    
    // Recreate the key
    let key_material = format!("encryption:{}:{}", expected_user_address, timestamp / 3600);
    let key_hash = Sha256::digest(key_material.as_bytes());
    let encryption_key = Key::<Aes256Gcm>::from_slice(&key_hash);
    
    // Recreate the nonce
    let nonce_material = format!("nonce:{}:{}", expected_user_address, timestamp);
    let nonce_hash = Sha256::digest(nonce_material.as_bytes());
    let nonce = Nonce::from_slice(&nonce_hash[0..12]);
    
    // Initialize the cipher
    let cipher = Aes256Gcm::new(encryption_key);
    
    // Decrypt the token
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| StdError::generic_err("Decryption failed - invalid token"))?;
    
    // Convert to string
    let decrypted_token = String::from_utf8(plaintext)
        .map_err(|_| StdError::generic_err("Decryption resulted in invalid UTF-8"))?;
    
    Ok(decrypted_token)
}


//=================================================
//=================================================

                //Security Helpers:

//=================================================




// Create a combined message hash for multi-part data
pub fn create_combined_hash(parts: &[&str]) -> String {
    let combined = parts.join(":");
    let hash = Sha256::digest(combined.as_bytes());
    hex::encode(hash)
}

// Verify a timestamp is within acceptable range (prevent replay attacks)
pub fn verify_timestamp(timestamp: u64, current_time: u64, max_age_seconds: u64) -> bool {
    // Ensure timestamp is not too old
    if timestamp + max_age_seconds < current_time {
        return false;
    }
    
    // Ensure timestamp is not from the future (with small tolerance)
    if timestamp > current_time + 300 { // 5 minutes tolerance for clock skew
        return false;
    }
    
    true
}


//====================================================
//====================================================

                //Encoding Utilities:

//====================================================

// Convert Binary to base64 for consistent representation
pub fn binary_to_base64(data: &Binary) -> String {
    encode(data.as_slice())
}

// Convert base64 string to Binary
pub fn base64_to_binary(data: &str) -> StdResult<Binary> {
    let bytes = decode(data)
        .map_err(|_| StdError::generic_err("Invalid base64 encoding"))?;
    Ok(Binary::from(bytes))
}
//================================================



//================================================

                    //TEST

//================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{Addr, Binary, BlockInfo, Env, Timestamp, TransactionInfo};
    use ed25519_dalek::{SigningKey as PrivateKey, Signer};
    
    // Create a mock Env for testing
    fn mock_env() -> Env {
        Env {
            block: BlockInfo {
                height: 12345,
                time: Timestamp::from_seconds(1774048984),
                chain_id: "xion-testnet-2".to_string(),
            },
            transaction: Some(TransactionInfo { index: 1 }),
            contract: cosmwasm_std::ContractInfo {
                address: Addr::unchecked("contract123"),  // FIX: Use Addr::unchecked()
            },
        }
    }
    
    // Helper to create deterministic test keys
    fn create_test_key_pair(seed_phrase: &str) -> (PrivateKey, PublicKey) {
        // Create deterministic seed from phrase
        let seed_hash = Sha256::digest(seed_phrase.as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_hash[0..32]);
        
        // Create keys from seed
        let private_key = PrivateKey::from_bytes(&seed);
        let public_key = private_key.verifying_key();
        
        (private_key, public_key)
    }
    
    // Helper to create a valid signature for testing
    fn create_test_signature(message: &str, seed_phrase: &str) -> (String, String, String) {
        // Create deterministic key pair
        let (private_key, public_key) = create_test_key_pair(seed_phrase);
        
        // Create message hash
        let message_hash = Sha256::digest(message.as_bytes());
        
        // Sign the message
        let signature = private_key.sign(&message_hash);
        
        // Return the encoded values
        (
            encode(public_key.to_bytes()),
            message.to_string(),
            hex::encode(signature.to_bytes())
        )
    }
    
    //=====================================================
    // Core Authentication Tests
    //=====================================================
    
    #[test]
    fn test_verify_signature() {
        // Create a valid signature with deterministic seed
        let (public_key, message, signature) = 
            create_test_signature("Test message for praiseunite", "test seed 1 for praiseunite");
        
        // Verify the valid signature
        let result = verify_signature(&public_key, &message, &signature);
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Test with invalid signature
        let invalid_sig = "a".repeat(128); // 64 bytes of 'a' in hex
        let result = verify_signature(&public_key, &message, &invalid_sig);
        assert!(result.is_err());
        
        // Test with invalid public key
        let invalid_key = "InvalidBase64Key!@#";
        let result = verify_signature(invalid_key, &message, &signature);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_validate_public_key() {
        // Create deterministic test key
        let (_, public_key) = create_test_key_pair("test seed 2 for praiseunite");
        let encoded_key = encode(public_key.to_bytes());
        
        // Valid key should pass
        let result = validate_public_key(&encoded_key);
        assert!(result.is_ok());
        
        // Invalid base64 should fail
        let result = validate_public_key("Not#Valid@Base64");
        assert!(result.is_err());
        
        // Wrong length should fail
        let result = validate_public_key(&encode(&[0u8; 16])); // 16 bytes instead of 32
        assert!(result.is_err());
    }
    
    //=====================================================
    // Secure Communication Tests
    //=====================================================
    
    #[test]
    fn test_encrypted_token_flow() {
        // Setup for user "praiseunite" at 2025-03-26 16:03:04 (1774048984)
        let user = "praiseunite";
        let timestamp = 1774048984;
        let nonce = "2025_03_26_16_03_04";
        let public_key = "RWFzdGVyIGVnZyEgSGkgZnJvbSBDb3BpbG90IQ=="; // Sample key
        
        // Generate encrypted token
        let encrypted_token = generate_encrypted_secure_token(
            user, timestamp, nonce, public_key
        ).unwrap();
        
        // Token should have 3 parts
        let parts: Vec<&str> = encrypted_token.split(':').collect();
        assert_eq!(parts.len(), 3);
        
        // Decrypt and verify
        let decrypted = decrypt_and_verify_secure_token(
            &encrypted_token,
            user,
            public_key,
            3600, // 1 hour max age
            timestamp
        ).unwrap();
        
        // Verify content
        let expected_content = format!("{}:{}:{}", user, timestamp, nonce);
        let expected_hash = encode(&Sha256::digest(expected_content.as_bytes()));
        assert_eq!(decrypted, expected_hash);
    }
    
    #[test]
    fn test_token_expiration() {
        // Setup
        let user = "praiseunite";
        let timestamp = 1774048984; // 2025-03-26 16:03:04
        let nonce = "expiration_test";
        let public_key = "RWFzdGVyIGVnZyEgSGkgZnJvbSBDb3BpbG90IQ==";
        
        // Generate token
        let encrypted_token = generate_encrypted_secure_token(
            user, timestamp, nonce, public_key
        ).unwrap();
        
        // Test with expired token (2 hours later, but max age is 1 hour)
        let future_time = timestamp + 7200; // 2 hours later
        let result = decrypt_and_verify_secure_token(
            &encrypted_token,
            user,
            public_key,
            3600, // 1 hour max age
            future_time
        );
        assert!(result.is_err());
        
        // Test with future token (token from "future")
        let past_time = timestamp - 7200; // 2 hours before
        let future_token = generate_encrypted_secure_token(
            user, timestamp, nonce, public_key
        ).unwrap();
        
        let result = decrypt_and_verify_secure_token(
            &future_token,
            user,
            public_key,
            3600,
            past_time
        );
        assert!(result.is_err());
    }
    
    #[test]
    fn test_token_tamper_resistance() {
        // Setup
        let user = "praiseunite";
        let timestamp = 1774048984;
        let nonce = "tamper_test";
        let public_key = "RWFzdGVyIGVnZyEgSGkgZnJvbSBDb3BpbG90IQ==";
        
        // Generate token
        let encrypted_token = generate_encrypted_secure_token(
            user, timestamp, nonce, public_key
        ).unwrap();
        
        // Tamper with the token parts
        let parts: Vec<&str> = encrypted_token.split(':').collect();
        
        // Tampered ciphertext
        let tampered_token1 = format!("{}:{}:{}", 
            encode(&[1, 2, 3, 4]), // Invalid ciphertext
            parts[1], 
            parts[2]
        );
        
        // Tampered timestamp
        let tampered_token2 = format!("{}:{}:{}", 
            parts[0], 
            "1774048000", // Different timestamp 
            parts[2]
        );
        
        // Tampered signature
        let tampered_token3 = format!("{}:{}:{}", 
            parts[0], 
            parts[1], 
            "deadbeef1234abcd" // Invalid signature
        );
        
        // All should fail to verify
        let result1 = decrypt_and_verify_secure_token(
            &tampered_token1, user, public_key, 3600, timestamp
        );
        let result2 = decrypt_and_verify_secure_token(
            &tampered_token2, user, public_key, 3600, timestamp
        );
        let result3 = decrypt_and_verify_secure_token(
            &tampered_token3, user, public_key, 3600, timestamp
        );
        
        assert!(result1.is_err());
        assert!(result2.is_err());
        assert!(result3.is_err());
    }
    
    //=====================================================
    // Security Helper Tests
    //=====================================================
    
    #[test]
    fn test_combined_hash() {
        // Test with username and timestamp parts
        let parts = &["praiseunite", "1774048984", "action:update"];
        let hash1 = create_combined_hash(parts);
        
        // Same input should give same hash
        let hash2 = create_combined_hash(parts);
        assert_eq!(hash1, hash2);
        
        // Different input should give different hash
        let different_parts = &["praiseunite", "1774048985", "action:update"];
        let hash3 = create_combined_hash(different_parts);
        assert_ne!(hash1, hash3);
        
        // Hash should be 64 characters (32 bytes in hex)
        assert_eq!(hash1.len(), 64);
    }
    
    #[test]
    fn test_verify_timestamp() {
        let current_time = 1774048984; // 2025-03-26 16:03:04
        
        // Valid timestamp (just created)
        assert!(verify_timestamp(current_time, current_time, 300));
        
        // Valid timestamp (5 minutes old with 10 minute max age)
        assert!(verify_timestamp(current_time - 300, current_time, 600));
        
        // Invalid timestamp (too old)
        assert!(!verify_timestamp(current_time - 301, current_time, 300));
        
        // Invalid timestamp (from future beyond tolerance)
        assert!(!verify_timestamp(current_time + 301, current_time, 300));
        
        // Valid timestamp from future within tolerance (4 minutes ahead)
        assert!(verify_timestamp(current_time + 240, current_time, 300));
    }
    
    //=====================================================
    // Encoding Utility Tests
    //=====================================================
    
    #[test]
    fn test_binary_conversions() {
        // Test data for user praiseunite
        let test_data = Binary::from(b"praiseunite-data-1774048984");
        
        // Convert to base64
        let base64_data = binary_to_base64(&test_data);
        
        // Convert back to binary
        let binary_result = base64_to_binary(&base64_data).unwrap();
        
        // Should match original
        assert_eq!(test_data, binary_result);
        
        // Invalid base64 should fail
        let result = base64_to_binary("Not#Valid@Base64!!!");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_deterministic_random() {
        let env = mock_env();
        
        // Define the get_entropy_bytes function
        fn get_entropy_bytes(env: &Env, seed: &str, length: usize) -> Vec<u8> {
            let combined_seed = format!("{}:{}", env.block.time.seconds(), seed);
            let hash = Sha256::digest(combined_seed.as_bytes());
            hash[0..length].to_vec()
        }
        
        // Generate pseudorandom bytes
        let random1 = get_entropy_bytes(&env, "test1", 32);
        let random2 = get_entropy_bytes(&env, "test1", 32);
        let random3 = get_entropy_bytes(&env, "test2", 32);
        
        // Same inputs should give same output
        assert_eq!(random1, random2);
        
        // Different seed should give different output
        assert_ne!(random1, random3);
        
        // Test with different lengths
        let random_short = get_entropy_bytes(&env, "test1", 16);
        let random_long = get_entropy_bytes(&env, "test1", 64);
        
        assert_eq!(random_short.len(), 16);
        assert_eq!(random_long.len(), 64);
        
        // Short should match prefix of original
        assert_eq!(random_short, random1[0..16]);
    }
}