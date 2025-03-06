use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, EphemeralSecret};

// TransactionType: Enum to distinguish transaction types
#[derive(Serialize, Deserialize, Debug, Clone)]
enum TransactionType {
    PeaceTransfer,
    ProfileDeletion,
}

// Transaction: Tracks events in the ledger
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Transaction {
    transaction_type: TransactionType,
    sender_id: String,
    receiver_id: String,
    amount: Option<f64>,
    user_id: Option<String>,
    timestamp: String,
    global_tx_id: String,
}

impl Transaction {
    fn new_peace_transfer(sender_id: String, receiver_id: String, amount: f64, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::PeaceTransfer,
            sender_id,
            receiver_id,
            amount: Some(amount),
            user_id: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_profile_deletion(user_id: String, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::ProfileDeletion,
            sender_id: user_id.clone(),
            receiver_id: "system".to_string(),
            amount: None,
            user_id: Some(user_id),
            timestamp,
            global_tx_id,
        }
    }
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
    location: String,
}

// Profile: User’s dating profile (encrypted)
#[derive(Serialize, Deserialize, Debug, Clone)]
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

    fn delete(&mut self) {
        self.is_deleted = true;
    }
}

// UserKeyPair: Represents a user's key exchange pair and symmetric key
struct UserKeyPair {
    secret_key: EphemeralSecret,
    public_key: PublicKey,
    symmetric_key: [u8; 32], // AES key for profile encryption
}

impl UserKeyPair {
    fn new() -> Self {
        let secret_key = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);
        let mut symmetric_key = [0u8; 32];
        OsRng.fill_bytes(&mut symmetric_key);
        UserKeyPair {
            secret_key,
            public_key,
            symmetric_key,
        }
    }

    fn derive_shared_secret(self, other_public: &PublicKey) -> [u8; 32] {
        self.secret_key.diffie_hellman(other_public).to_bytes()
    }
}

// ProfileFilter: Represents user-defined filters for fetching profiles
#[derive(Debug)]
struct ProfileFilter {
    location: Option<String>,
    min_age: Option<u32>,
    max_age: Option<u32>,
    interests: Option<Vec<String>>,
}

impl ProfileFilter {
    fn new(location: Option<String>, min_age: Option<u32>, max_age: Option<u32>, interests: Option<Vec<String>>) -> Self {
        ProfileFilter {
            location,
            min_age,
            max_age,
            interests,
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

impl UserShard {
    fn new(
        user_id: String,
        balance: f64,
        transactions: Vec<Transaction>,
        interactions: Vec<Interaction>,
        profile: Profile,
    ) -> Self {
        UserShard {
            user_id,
            balance,
            transactions,
            interactions,
            profile,
            relevant_profiles: Vec::new(),
        }
    }

    fn fetch_relevant_profiles(
        &mut self,
        filter: &ProfileFilter,
        mock_profile_db: &[Profile],
        shared_keys: &HashMap<(String, String), [u8; 32]>,
        fetcher_id: &str,
    ) -> Vec<String> {
        self.relevant_profiles.clear();
        let mut inaccessible_profiles = Vec::new();

        for profile in mock_profile_db {
            if profile.is_deleted {
                continue;
            }

            let key_pair = (fetcher_id.to_string(), profile.user_id.clone());
            match shared_keys.get(&key_pair) {
                Some(decryption_key) => {
                    if let Some(raw_data) = profile.decrypt(decryption_key) {
                        let mut matches = true;

                        if let Some(loc) = &filter.location {
                            if raw_data.location != *loc {
                                matches = false;
                            }
                        }

                        if let Some(min_age) = filter.min_age {
                            if raw_data.age < min_age {
                                matches = false;
                            }
                        }
                        if let Some(max_age) = filter.max_age {
                            if raw_data.age > max_age {
                                matches = false;
                            }
                        }

                        if let Some(interests) = &filter.interests {
                            let has_matching_interest = raw_data.interests.iter()
                                .any(|interest| interests.contains(interest));
                            if !has_matching_interest {
                                matches = false;
                            }
                        }

                        if matches {
                            self.relevant_profiles.push(profile.clone());
                        }
                    }
                }
                None => {
                    inaccessible_profiles.push(profile.user_id.clone());
                }
            }
        }

        inaccessible_profiles
    }

    fn delete_profile(&mut self, ledger: &mut GlobalLedger, timestamp: String, global_tx_id: String) {
        self.profile.delete();
        let deletion_tx = Transaction::new_profile_deletion(
            self.user_id.clone(),
            timestamp,
            global_tx_id,
        );
        ledger.add_block(vec![deletion_tx]);
    }
}

// GlobalBlock: Global ledger block for full nodes
#[derive(Serialize, Deserialize, Debug)]
struct GlobalBlock {
    transactions: Vec<Transaction>,
    previous_hash: String,
    nonce: u64,
    hash: String,
    timestamp: u64,
}

impl GlobalBlock {
    fn new(transactions: Vec<Transaction>, previous_hash: String, difficulty: usize) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let mut block = GlobalBlock {
            transactions,
            previous_hash,
            nonce: 0,
            hash: String::new(),
            timestamp,
        };
        block.mine_block(difficulty);
        block
    }

    fn compute_hash(&self) -> String {
        let mut hasher = Sha3_256::new();
        let tx_bytes = serde_json::to_vec(&self.transactions)
            .expect("Failed to serialize transactions");
        hasher.update(&tx_bytes);
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hex::encode(hasher.finalize())
    }

    fn mine_block(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);
        loop {
            self.hash = self.compute_hash();
            if self.hash.starts_with(&target) {
                break;
            }
            self.nonce += 1;
        }
    }
}

// GlobalLedger: Manages the chain of GlobalBlocks
#[derive(Debug)]
struct GlobalLedger {
    chain: Vec<GlobalBlock>,
    difficulty: usize,
    max_difficulty: usize, // Added to cap difficulty
    target_block_time: u64,
    adjustment_interval: usize,
}

impl GlobalLedger {
    fn new(initial_difficulty: usize, max_difficulty: usize, target_block_time: u64, adjustment_interval: usize) -> Self {
        let genesis_block = GlobalBlock::new(
            vec![Transaction::new_peace_transfer(
                "system".to_string(),
                "genesis".to_string(),
                0.0,
                "2025-03-04".to_string(),
                "genesis_tx".to_string(),
            )],
            "0".to_string(),
            initial_difficulty,
        );
        GlobalLedger {
            chain: vec![genesis_block],
            difficulty: initial_difficulty,
            max_difficulty,
            target_block_time,
            adjustment_interval,
        }
    }

    fn add_block(&mut self, transactions: Vec<Transaction>) {
        let previous_hash = self.chain.last()
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| "0".to_string());
        let start = Instant::now();
        let new_block = GlobalBlock::new(transactions, previous_hash, self.difficulty);
        start.elapsed();

        self.chain.push(new_block);

        if self.chain.len() % self.adjustment_interval == 0 {
            self.adjust_difficulty();
        }
    }

    fn adjust_difficulty(&mut self) {
        let start_idx = if self.chain.len() > self.adjustment_interval {
            self.chain.len() - self.adjustment_interval
        } else {
            0
        };

        let recent_blocks = &self.chain[start_idx..];
        if recent_blocks.len() < 2 {
            return;
        }

        let mut total_time = 0;
        for i in 1..recent_blocks.len() {
            let time_diff = recent_blocks[i].timestamp - recent_blocks[i - 1].timestamp;
            total_time += time_diff;
        }
        let avg_block_time = total_time as f64 / (recent_blocks.len() - 1) as f64;

        let target_time = self.target_block_time as f64;
        if avg_block_time < target_time * 0.8 {
            if self.difficulty < self.max_difficulty { // Cap at max_difficulty
                self.difficulty += 1;
                println!("Increasing difficulty to {} (avg block time: {}s)", self.difficulty, avg_block_time);
            }
        } else if avg_block_time > target_time * 1.2 {
            if self.difficulty > 1 {
                self.difficulty -= 1;
                println!("Decreasing difficulty to {} (avg block time: {}s)", self.difficulty, avg_block_time);
            }
        }
    }

    fn get_chain(&self) -> &Vec<GlobalBlock> {
        &self.chain
    }

    fn get_difficulty(&self) -> usize {
        self.difficulty
    }
}

fn main() {
    const INITIAL_DIFFICULTY: usize = 3;
    const MAX_DIFFICULTY: usize = 4; // Added to cap difficulty
    const TARGET_BLOCK_TIME: u64 = 5;
    const ADJUSTMENT_INTERVAL: usize = 3;

    let mut key_pairs: HashMap<String, UserKeyPair> = HashMap::new();
    let mut mock_profile_db = Vec::new();
    let users = vec![
        ("bob", "Bob", 30, "Enjoys hiking and reading", "CA", vec!["hiking", "reading"]),
        ("charlie", "Charlie", 25, "Loves music and travel", "NY", vec!["music", "travel"]),
        ("diana", "Diana", 28, "Into photography and coffee", "CA", vec!["photography", "coffee"]),
        ("alice", "Alice", 28, "Loves hiking and coffee", "CA", vec!["hiking", "photography"]),
    ];

    for (user_id, name, age, bio, location, interests) in users {
        let key_pair = UserKeyPair::new();
        key_pairs.insert(user_id.to_string(), key_pair);

        let raw_data = RawProfileData {
            name: name.to_string(),
            age,
            bio: bio.to_string(),
            interests: interests.into_iter().map(String::from).collect(),
            location: location.to_string(),
        };
        let key_pair = key_pairs.get(user_id).expect("Key pair should exist");
        let profile = Profile::new(user_id.to_string(), raw_data, &key_pair.symmetric_key);
        mock_profile_db.push(profile);
    }

    let mut shared_symmetric_keys: HashMap<(String, String), [u8; 32]> = HashMap::new();

    // Extract Alice's and Bob's key pairs and fields before deriving shared secrets
    let alice_keys = key_pairs.remove("alice").unwrap();
    let alice_symmetric_key = alice_keys.symmetric_key;
    let alice_public_key = alice_keys.public_key;

    let bob_keys = key_pairs.remove("bob").unwrap();
    let bob_symmetric_key = bob_keys.symmetric_key;
    let bob_public_key = bob_keys.public_key;

    // Now derive shared secrets (this consumes alice_keys and bob_keys)
    let shared_secret_alice_bob = alice_keys.derive_shared_secret(&bob_public_key);
    let shared_secret_bob_alice = bob_keys.derive_shared_secret(&alice_public_key);

    // Encrypt Alice's symmetric key with the shared secret for Bob
    let cipher = Aes256Gcm::new(&shared_secret_alice_bob.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_key = cipher.encrypt(nonce, alice_symmetric_key.as_ref())
        .expect("Failed to encrypt symmetric key");
    let mut encrypted_key_with_nonce = nonce_bytes.to_vec();
    encrypted_key_with_nonce.extend(encrypted_key);
    shared_symmetric_keys.insert(("bob".to_string(), "alice".to_string()), alice_symmetric_key);

    // Encrypt Bob's symmetric key with the shared secret for Alice
    let cipher = Aes256Gcm::new(&shared_secret_bob_alice.into());
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_key = cipher.encrypt(nonce, bob_symmetric_key.as_ref())
        .expect("Failed to encrypt symmetric key");
    let mut encrypted_key_with_nonce = nonce_bytes.to_vec();
    encrypted_key_with_nonce.extend(encrypted_key);
    shared_symmetric_keys.insert(("alice".to_string(), "bob".to_string()), bob_symmetric_key);

    // Allow Alice to access her own profile by adding her symmetric key to shared_symmetric_keys
    shared_symmetric_keys.insert(("alice".to_string(), "alice".to_string()), alice_symmetric_key);

    let alice_profile = mock_profile_db.iter()
        .find(|p| p.user_id == "alice")
        .expect("Alice's profile should exist")
        .clone();

    let mut ledger = GlobalLedger::new(INITIAL_DIFFICULTY, MAX_DIFFICULTY, TARGET_BLOCK_TIME, ADJUSTMENT_INTERVAL);

    let tx = Transaction::new_peace_transfer(
        "system".to_string(),
        "alice".to_string(),
        5.0,
        "2025-03-04".to_string(),
        "tx001".to_string(),
    );
    let int = Interaction {
        event_type: "match".to_string(),
        user_id: "alice".to_string(),
        target_id: "bob".to_string(),
        score: 5,
    };
    let mut user_shard = UserShard::new(
        "alice".to_string(),
        5.0,
        vec![tx.clone()],
        vec![int],
        alice_profile,
    );

    let start = Instant::now();
    ledger.add_block(vec![tx]);
    let duration = start.elapsed();
    println!("Time to mine block 1: {:?}", duration);

    let filter = ProfileFilter::new(
        Some("CA".to_string()),
        Some(25),
        Some(30),
        Some(vec!["hiking".to_string(), "photography".to_string()]),
    );

    println!("Fetching profiles before deletion:");
    let inaccessible = user_shard.fetch_relevant_profiles(&filter, &mock_profile_db, &shared_symmetric_keys, "alice");
    for profile in &user_shard.relevant_profiles {
        if let Some(key) = shared_symmetric_keys.get(&("alice".to_string(), profile.user_id.clone())) {
            if let Some(raw_data) = profile.decrypt(key) {
                println!("User {}: {:?}", profile.user_id, raw_data);
            }
        }
    }
    println!("Inaccessible profiles (missing keys): {:?}", inaccessible);

    println!("\nSimulating Charlie deleting their profile...");
    let charlie_profile = mock_profile_db.iter_mut()
        .find(|p| p.user_id == "charlie")
        .expect("Charlie's profile should exist");
    charlie_profile.delete();

    let start = Instant::now();
    ledger.add_block(vec![Transaction::new_profile_deletion(
        "charlie".to_string(),
        "2025-03-05".to_string(),
        "delete_charlie".to_string(),
    )]);
    let duration = start.elapsed();
    println!("Time to mine block 2: {:?}", duration);

    for i in 3..=6 {
        let start = Instant::now();
        ledger.add_block(vec![Transaction::new_peace_transfer(
            "system".to_string(),
            format!("user{}", i),
            5.0,
            format!("2025-03-0{}", i),
            format!("tx00{}", i),
        )]);
        let duration = start.elapsed();
        println!("Time to mine block {}: {:?}", i, duration);
        println!("Current difficulty: {}", ledger.get_difficulty());
    }

    println!("\nFetching profiles after Charlie deletes their profile:");
    let inaccessible = user_shard.fetch_relevant_profiles(&filter, &mock_profile_db, &shared_symmetric_keys, "alice");
    for profile in &user_shard.relevant_profiles {
        if let Some(key) = shared_symmetric_keys.get(&("alice".to_string(), profile.user_id.clone())) {
            if let Some(raw_data) = profile.decrypt(key) {
                println!("User {}: {:?}", profile.user_id, raw_data);
            }
        }
    }
    println!("Inaccessible profiles (missing keys): {:?}", inaccessible);

    println!("\nGlobal Ledger Chain:");
    for (i, block) in ledger.get_chain().iter().enumerate() {
        println!("Block {}: Hash = {}", i, block.hash);
        println!("  Previous Hash: {}", block.previous_hash);
        println!("  Timestamp: {}", block.timestamp);
        println!("  Transactions: {:?}", block.transactions);
        println!("  Nonce: {}", block.nonce);
    }
}