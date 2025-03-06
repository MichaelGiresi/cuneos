// Cuneos Blockchain: A decentralized dating app backend with dynamic difficulty and secure key exchange
// Built for the Weave platform

use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{Rng, RngCore}; // Added RngCore import
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, EphemeralSecret};

// Miner: Represents a miner in the Cuneos network with a name and mining power
#[derive(Debug, Clone)]
struct Miner {
    name: String,
    mining_power: f64,
}

impl Miner {
    fn new(name: String, mining_power: f64) -> Self {
        Miner { name, mining_power }
    }

    fn mine_block(&self, block: &mut GlobalBlock, difficulty: usize) {
        let target = "0".repeat(difficulty);
        let increment = (self.mining_power * 1000.0) as u64;
        loop {
            block.hash = block.compute_hash();
            if block.hash.starts_with(&target) {
                break;
            }
            block.nonce += increment;
        }
    }
}

// TransactionType: Enum to distinguish transaction types in Cuneos
#[derive(Serialize, Deserialize, Debug, Clone)]
enum TransactionType {
    PeaceTransfer,
    ProfileDeletion,
}

// Transaction: Tracks events in the Cuneos ledger
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

// Interaction: Records actions earning Peace in the Cuneos system
#[derive(Serialize, Deserialize, Debug)]
struct Interaction {
    event_type: String,
    user_id: String,
    target_id: String,
    score: u32,
}

// RawProfileData: Unencrypted profile data for Weave users
#[derive(Serialize, Deserialize, Debug)]
struct RawProfileData {
    name: String,
    age: u32,
    bio: String,
    interests: Vec<String>,
    location: String,
}

// Profile: User’s dating profile (encrypted) in Cuneos
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

// UserKeyPair: Represents a user's key exchange pair and symmetric key in Cuneos
struct UserKeyPair {
    secret_key: EphemeralSecret,
    public_key: PublicKey,
    symmetric_key: [u8; 32],
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

// ProfileFilter: Represents user-defined filters for fetching profiles in Weave
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

// UserShard: Precise shard for one user in Cuneos
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

// GlobalBlock: Global ledger block for full nodes in Cuneos
#[derive(Serialize, Deserialize, Debug)]
struct GlobalBlock {
    transactions: Vec<Transaction>,
    previous_hash: String,
    nonce: u64,
    hash: String,
    timestamp: u64,
}

impl GlobalBlock {
    fn new(transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let block = GlobalBlock {
            transactions,
            previous_hash,
            nonce: 0,
            hash: String::new(),
            timestamp,
        };
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
}

// GlobalLedger: Manages the chain of GlobalBlocks in Cuneos
#[derive(Debug)]
struct GlobalLedger {
    chain: Vec<GlobalBlock>,
    difficulty: f64,
    max_difficulty: usize,
    min_difficulty: usize,
    target_block_time: f64,
    adjustment_interval: usize,
    miners: Vec<Miner>,
    mining_durations: Vec<f64>,
    ema_block_time: Option<f64>,
}

impl GlobalLedger {
    fn new(initial_difficulty: usize, max_difficulty: usize, min_difficulty: usize, target_block_time: f64, adjustment_interval: usize, miners: Vec<Miner>) -> Self {
        let genesis_block = GlobalBlock::new(
            vec![Transaction::new_peace_transfer(
                "system".to_string(),
                "genesis".to_string(),
                0.0,
                "2025-03-04".to_string(),
                "genesis_tx".to_string(),
            )],
            "0".to_string(),
        );
        GlobalLedger {
            chain: vec![genesis_block],
            difficulty: initial_difficulty as f64,
            max_difficulty,
            min_difficulty,
            target_block_time,
            adjustment_interval,
            miners,
            mining_durations: Vec::new(),
            ema_block_time: None,
        }
    }

    fn add_block(&mut self, transactions: Vec<Transaction>) -> String {
        let previous_hash = self.chain.last()
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| "0".to_string());
        
        let mut block = GlobalBlock::new(transactions, previous_hash);
        
        let miner = self.miners.choose(&mut rand::thread_rng()).expect("At least one miner should exist");
        let miner_name = miner.name.clone();
        
        let start = Instant::now();
        miner.mine_block(&mut block, self.difficulty as usize);
        let duration = start.elapsed().as_secs_f64();
        
        self.mining_durations.push(duration);
        self.chain.push(block);

        const ALPHA: f64 = 0.3;
        self.ema_block_time = match self.ema_block_time {
            Some(ema) => Some(ALPHA * duration + (1.0 - ALPHA) * ema),
            None => Some(duration),
        };

        if self.chain.len() % self.adjustment_interval == 0 {
            self.adjust_difficulty();
        }

        miner_name
    }

    fn adjust_difficulty(&mut self) {
        let start_idx = if self.mining_durations.len() > self.adjustment_interval {
            self.mining_durations.len() - self.adjustment_interval
        } else {
            0
        };

        let recent_durations = &self.mining_durations[start_idx..];
        if recent_durations.len() < 2 {
            return;
        }

        let avg_block_time = self.ema_block_time.unwrap_or_else(|| {
            recent_durations.iter().sum::<f64>() / recent_durations.len() as f64
        });

        let min_time = recent_durations.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_time = recent_durations.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        println!(
            "Adjustment stats: EMA block time: {:.2}s, Min: {:.2}s, Max: {:.2}s, Recent durations: {:?}", 
            avg_block_time, min_time, max_time, recent_durations
        );

        let lower_threshold = self.target_block_time * 0.5;
        let upper_threshold = self.target_block_time * 1.5;

        if avg_block_time < lower_threshold {
            let factor = self.target_block_time / avg_block_time;
            self.difficulty *= factor;
            if self.difficulty > self.max_difficulty as f64 {
                self.difficulty = self.max_difficulty as f64;
            }
            println!(
                "Increasing difficulty to {:.2} (EMA block time: {:.2}s, target: {:.2}s)", 
                self.difficulty, avg_block_time, self.target_block_time
            );
        } else if avg_block_time > upper_threshold {
            let factor = self.target_block_time / avg_block_time;
            self.difficulty *= factor;
            if self.difficulty < self.min_difficulty as f64 {
                self.difficulty = self.min_difficulty as f64;
            }
            println!(
                "Decreasing difficulty to {:.2} (EMA block time: {:.2}s, target: {:.2}s)", 
                self.difficulty, avg_block_time, self.target_block_time
            );
        }
    }

    fn get_chain(&self) -> &Vec<GlobalBlock> {
        &self.chain
    }

    fn get_difficulty(&self) -> f64 {
        self.difficulty
    }
}

fn main() {
    const INITIAL_DIFFICULTY: usize = 3;
    const MAX_DIFFICULTY: usize = 4;
    const MIN_DIFFICULTY: usize = 1;
    const TARGET_BLOCK_TIME: f64 = 5.0;
    const ADJUSTMENT_INTERVAL: usize = 3;
    const TOTAL_BLOCKS: usize = 20;

    let miners = vec![
        Miner::new("Miner1".to_string(), 1.0),
        Miner::new("Miner2".to_string(), 1.5),
        Miner::new("Miner3".to_string(), 0.7),
    ];

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

    let alice_keys = key_pairs.remove("alice").unwrap();
    let alice_symmetric_key = alice_keys.symmetric_key;
    let alice_public_key = alice_keys.public_key;

    let bob_keys = key_pairs.remove("bob").unwrap();
    let bob_symmetric_key = bob_keys.symmetric_key;
    let bob_public_key = bob_keys.public_key;

    let shared_secret_alice_bob = alice_keys.derive_shared_secret(&bob_public_key);
    let shared_secret_bob_alice = bob_keys.derive_shared_secret(&alice_public_key);

    let cipher = Aes256Gcm::new(&shared_secret_alice_bob.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_key = cipher.encrypt(nonce, alice_symmetric_key.as_ref())
        .expect("Failed to encrypt symmetric key");
    let mut encrypted_key_with_nonce = nonce_bytes.to_vec();
    encrypted_key_with_nonce.extend(encrypted_key);
    shared_symmetric_keys.insert(("bob".to_string(), "alice".to_string()), alice_symmetric_key);

    let cipher = Aes256Gcm::new(&shared_secret_bob_alice.into());
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_key = cipher.encrypt(nonce, bob_symmetric_key.as_ref())
        .expect("Failed to encrypt symmetric key");
    let mut encrypted_key_with_nonce = nonce_bytes.to_vec();
    encrypted_key_with_nonce.extend(encrypted_key);
    shared_symmetric_keys.insert(("alice".to_string(), "bob".to_string()), bob_symmetric_key);

    shared_symmetric_keys.insert(("alice".to_string(), "alice".to_string()), alice_symmetric_key);

    let alice_profile = mock_profile_db.iter()
        .find(|p| p.user_id == "alice")
        .expect("Alice's profile should exist")
        .clone();

    let mut ledger = GlobalLedger::new(INITIAL_DIFFICULTY, MAX_DIFFICULTY, MIN_DIFFICULTY, TARGET_BLOCK_TIME, ADJUSTMENT_INTERVAL, miners);

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
    let miner_name = ledger.add_block(vec![tx]);
    let duration = start.elapsed();
    println!("Block 1 mined by {} in {:?}", miner_name, duration);

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
    let miner_name = ledger.add_block(vec![Transaction::new_profile_deletion(
        "charlie".to_string(),
        "2025-03-05".to_string(),
        "delete_charlie".to_string(),
    )]);
    let duration = start.elapsed();
    println!("Block 2 mined by {} in {:?}", miner_name, duration);

    let user_ids: Vec<String> = vec!["alice".to_string(), "bob".to_string(), "charlie".to_string(), "diana".to_string()];
    for i in 3..=TOTAL_BLOCKS {
        let start = Instant::now();
        let num_txs = rand::thread_rng().gen_range(1..=10);
        let mut transactions = Vec::new();
        for j in 0..num_txs {
            let sender = user_ids.choose(&mut rand::thread_rng()).unwrap();
            let receiver = user_ids.choose(&mut rand::thread_rng()).unwrap();
            transactions.push(Transaction::new_peace_transfer(
                sender.clone(),
                receiver.clone(),
                rand::thread_rng().gen_range(1.0..10.0),
                format!("2025-03-{:02}", i),
                format!("tx{:03}_{}", i, j),
            ));
        }
        let miner_name = ledger.add_block(transactions);
        let duration = start.elapsed();
        println!("Block {} mined by {} in {:?}", i, miner_name, duration);
        println!("Current difficulty: {:.2}", ledger.get_difficulty());
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

    println!("\nCuneos Global Ledger Chain:");
    for (i, block) in ledger.get_chain().iter().enumerate() {
        println!("Block {}: Hash = {}", i, block.hash);
        println!("  Previous Hash: {}", block.previous_hash);
        println!("  Timestamp: {}", block.timestamp);
        println!("  Transactions: {:?}", block.transactions);
        println!("  Nonce: {}", block.nonce);
    }

    println!("\nNote: Miner win stats not tracked per block in this version. Extend GlobalBlock to include miner_name if needed.");
}