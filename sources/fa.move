module ram_addr::SecureWallet {
    use aptos_framework::signer;
    use aptos_framework::timestamp;
    use std::string::{Self, String};
    
    const E_WALLET_NOT_FOUND: u64 = 1;
    const E_INVALID_OTP: u64 = 2;
    const E_OTP_EXPIRED: u64 = 3;
    const E_WALLET_ALREADY_EXISTS: u64 = 4;
    
    const OTP_EXPIRY_TIME: u64 = 300;
    
    struct SecureWallet has store, key {
        owner: address,           
        phone_hash: String,       
        current_otp: u64,         
        otp_timestamp: u64,       
        is_verified: bool,        
        login_attempts: u64,      
    }
    
    public fun register_wallet(
        owner: &signer, 
        phone_hash: String
    ) {
        let owner_addr = signer::address_of(owner);
        
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
    
    public fun verify_login(
        user: &signer,
        wallet_owner: address,
        provided_otp: u64
    ) acquires SecureWallet {
        let wallet = borrow_global_mut<SecureWallet>(wallet_owner);
        let current_time = timestamp::now_seconds();
        
        assert!(current_time - wallet.otp_timestamp <= OTP_EXPIRY_TIME, E_OTP_EXPIRED);
        
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
