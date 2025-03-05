use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;

// Transaction: Tracks Peace movements
#[derive(Serialize, Deserialize, Debug)]
struct Transaction {
    sender_id: String,
    receiver_id: String,
    amount: f64,
    timestamp: String,
    global_tx_id: String,
}

// Interaction: Records actions earning Peace
#[derive(Serialize, Deserialize, Debug)]
struct Interaction {
    event_type: String,
    user_id: String,
    target_id: String,
    score: u32,
}

// RawProfileData: Unencrypted profile data
#[derive(Serialize, Deserialize, Debug)]
struct RawProfileData {
    name: String,
    age: u32,
    bio: String,
    interests: Vec<String>,
}

// Profile: User’s dating profile (encrypted)
#[derive(Serialize, Deserialize, Debug)]
struct Profile {
    user_id: String,
    encrypted_data: Vec<u8>,
    is_deleted: bool,
}

impl Profile {
    fn new(user_id: String, raw_data: RawProfileData, key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = serde_json::to_vec(&raw_data)
            .expect("Failed to serialize profile data");
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("Encryption failed");

        let mut encrypted_data = nonce_bytes.to_vec();
        encrypted_data.extend(ciphertext);

        Profile {
            user_id,
            encrypted_data,
            is_deleted: false,
        }
    }

    fn decrypt(&self, key: &[u8; 32]) -> Option<RawProfileData> {
        if self.is_deleted {
            return None;
        }

        let cipher = Aes256Gcm::new(key.into());

        if self.encrypted_data.len() < 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = self.encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => serde_json::from_slice(&plaintext).ok(),
            Err(_) => None,
        }
    }
}

// UserShard: Precise shard for one user
#[derive(Serialize, Deserialize, Debug)]
struct UserShard {
    user_id: String,
    balance: f64,
    transactions: Vec<Transaction>,
    interactions: Vec<Interaction>,
    profile: Profile,
    relevant_profiles: Vec<Profile>,
}

// GlobalBlock: Global ledger block for full nodes
#[derive(Serialize, Deserialize, Debug)]
struct GlobalBlock {
    transactions: Vec<Transaction>,
    previous_hash: String,
    nonce: u64,
    hash: String,
}

impl GlobalBlock {
    fn new(transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let mut block = GlobalBlock {
            transactions,
            previous_hash,
            nonce: 0,
            hash: String::new(),
        };
        block.hash = block.compute_hash();
        block
    }

    fn compute_hash(&self) -> String {
        let mut hasher = Sha3_256::new(); // Line causing Rust Analyzer error
        let tx_bytes = serde_json::to_vec(&self.transactions)
            .expect("Failed to serialize transactions");
        hasher.update(&tx_bytes);
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hex::encode(hasher.finalize())
    }
}

fn main() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let raw_data = RawProfileData {
        name: "Alice".to_string(),
        age: 28,
        bio: "Loves hiking and coffee".to_string(),
        interests: vec!["hiking".to_string(), "photography".to_string()],
    };

    let profile = Profile::new("user1".to_string(), raw_data, &key);

    let tx = Transaction {
        sender_id: "system".to_string(),
        receiver_id: "user1".to_string(),
        amount: 5.0,
        timestamp: "2025-03-04".to_string(),
        global_tx_id: "tx001".to_string(),
    };
    let int = Interaction {
        event_type: "match".to_string(),
        user_id: "user1".to_string(),
        target_id: "user2".to_string(),
        score: 5,
    };
    let user_shard = UserShard {
        user_id: "user1".to_string(),
        balance: 5.0,
        transactions: vec![tx],
        interactions: vec![int],
        profile,
        relevant_profiles: Vec::new(),
    };

    match user_shard.profile.decrypt(&key) {
        Some(decrypted_data) => println!("Decrypted Profile: {:?}", decrypted_data),
        None => println!("Failed to decrypt profile"),
    }

    let global_block = GlobalBlock::new(
        vec![Transaction {
            sender_id: "system".to_string(),
            receiver_id: "user1".to_string(),
            amount: 5.0,
            timestamp: "2025-03-04".to_string(),
            global_tx_id: "tx001".to_string(),
        }],
        "000000".to_string(),
    );

    println!("User Shard: {:?}", user_shard);
    println!("Global Block Hash: {}", global_block.hash);
}