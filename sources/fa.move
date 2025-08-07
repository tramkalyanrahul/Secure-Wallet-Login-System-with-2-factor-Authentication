module ram_addr::SecureWallet {
    use aptos_framework::signer;
    use aptos_framework::timestamp;
    use std::string::{Self, String};
    
    /// Error codes
    const E_WALLET_NOT_FOUND: u64 = 1;
    const E_INVALID_OTP: u64 = 2;
    const E_OTP_EXPIRED: u64 = 3;
    const E_WALLET_ALREADY_EXISTS: u64 = 4;
    
    /// OTP expiry time in seconds (5 minutes)
    const OTP_EXPIRY_TIME: u64 = 300;
    
    /// Struct representing a secure wallet with 2FA
    struct SecureWallet has store, key {
        owner: address,           // Wallet owner address
        phone_hash: String,       // Hashed phone number for 2FA
        current_otp: u64,         // Current OTP code
        otp_timestamp: u64,       // OTP generation timestamp
        is_verified: bool,        // Verification status
        login_attempts: u64,      // Failed login attempts counter
    }
    
    /// Function to register a new secure wallet with phone number
    public fun register_wallet(
        owner: &signer, 
        phone_hash: String
    ) {
        let owner_addr = signer::address_of(owner);
        
        // Check if wallet already exists
        assert!(!exists<SecureWallet>(owner_addr), E_WALLET_ALREADY_EXISTS);
        
        let wallet = SecureWallet {
            owner: owner_addr,
            phone_hash,
            current_otp: 0,
            otp_timestamp: 0,
            is_verified: false,
            login_attempts: 0,
        };
        
        move_to(owner, wallet);
    }
    
    /// Function to verify login with OTP (2FA)
    public fun verify_login(
        user: &signer,
        wallet_owner: address,
        provided_otp: u64
    ) acquires SecureWallet {
        let wallet = borrow_global_mut<SecureWallet>(wallet_owner);
        let current_time = timestamp::now_seconds();
        
        // Check if OTP is not expired
        assert!(current_time - wallet.otp_timestamp <= OTP_EXPIRY_TIME, E_OTP_EXPIRED);
        
        // Verify OTP
        if (wallet.current_otp == provided_otp) {
            wallet.is_verified = true;
            wallet.login_attempts = 0;
        } else {
            wallet.login_attempts = wallet.login_attempts + 1;
            wallet.is_verified = false;
            assert!(false, E_INVALID_OTP);
        };
    }
}