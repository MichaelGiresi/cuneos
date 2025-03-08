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
use rand::{Rng, RngCore};
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
    ProfileUpdate,
    Match,
    KeyRevocation,
    Message,
    Like,
    PhotoShare,
    BlockUser,
    VideoCall,
    ReportUser,
    KeyShare,
}

// Transaction: Tracks events in the Cuneos ledger
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Transaction {
    transaction_type: TransactionType,
    sender_id: String,
    receiver_id: String,
    amount: Option<f64>,
    duration: Option<u32>,
    reason: Option<String>,
    user_id: Option<String>,
    updated_profile: Option<Vec<u8>>,
    match_pair: Option<(String, String)>,
    revoked_key_pair: Option<(String, String)>,
    encrypted_key: Option<Vec<u8>>,
    encrypted_content: Option<Vec<u8>>,
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
            duration: None,
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: None,
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
            duration: None,
            reason: None,
            user_id: Some(user_id),
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_profile_update(user_id: String, updated_profile: Vec<u8>, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::ProfileUpdate,
            sender_id: user_id.clone(),
            receiver_id: "system".to_string(),
            amount: None,
            duration: None,
            reason: None,
            user_id: Some(user_id),
            updated_profile: Some(updated_profile),
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_match(user_id1: String, user_id2: String, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::Match,
            sender_id: user_id1.clone(),
            receiver_id: user_id2.clone(),
            amount: None,
            duration: None,
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: Some((user_id1, user_id2)),
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_key_revocation(revoker_id: String, target_id: String, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::KeyRevocation,
            sender_id: revoker_id.clone(),
            receiver_id: target_id.clone(),
            amount: None,
            duration: None,
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: Some((revoker_id, target_id)),
            encrypted_key: None,
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_message(sender_id: String, receiver_id: String, content: &str, shared_key: &[u8; 32], timestamp: String, global_tx_id: String) -> Self {
        let cipher = Aes256Gcm::new(shared_key.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, content.as_bytes())
            .expect("Failed to encrypt message content");
        let mut encrypted_content = nonce_bytes.to_vec();
        encrypted_content.extend(ciphertext);

        Transaction {
            transaction_type: TransactionType::Message,
            sender_id,
            receiver_id,
            amount: None,
            duration: None,
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: Some(encrypted_content),
            timestamp,
            global_tx_id,
        }
    }

    #[allow(dead_code)]
    fn new_like(sender_id: String, receiver_id: String, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::Like,
            sender_id,
            receiver_id,
            amount: None,
            duration: None,
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_photo_share(sender_id: String, receiver_id: String, content: &str, shared_key: &[u8; 32], timestamp: String, global_tx_id: String) -> Self {
        let cipher = Aes256Gcm::new(shared_key.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, content.as_bytes())
            .expect("Failed to encrypt photo content");
        let mut encrypted_content = nonce_bytes.to_vec();
        encrypted_content.extend(ciphertext);

        Transaction {
            transaction_type: TransactionType::PhotoShare,
            sender_id,
            receiver_id,
            amount: None,
            duration: None,
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: Some(encrypted_content),
            timestamp,
            global_tx_id,
        }
    }

    fn new_block_user(sender_id: String, receiver_id: String, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::BlockUser,
            sender_id,
            receiver_id,
            amount: None,
            duration: None,
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_video_call(sender_id: String, receiver_id: String, duration: u32, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::VideoCall,
            sender_id,
            receiver_id,
            amount: None,
            duration: Some(duration),
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_report_user(sender_id: String, receiver_id: String, reason: String, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::ReportUser,
            sender_id,
            receiver_id,
            amount: None,
            duration: None,
            reason: Some(reason),
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: None,
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn new_key_share(sender_id: String, receiver_id: String, encrypted_key: Vec<u8>, timestamp: String, global_tx_id: String) -> Self {
        Transaction {
            transaction_type: TransactionType::KeyShare,
            sender_id,
            receiver_id,
            amount: None,
            duration: None,
            reason: None,
            user_id: None,
            updated_profile: None,
            match_pair: None,
            revoked_key_pair: None,
            encrypted_key: Some(encrypted_key),
            encrypted_content: None,
            timestamp,
            global_tx_id,
        }
    }

    fn decrypt_content(&self, shared_key: &[u8; 32]) -> Option<String> {
        match self.transaction_type {
            TransactionType::Message | TransactionType::PhotoShare => {
                if let Some(encrypted_content) = &self.encrypted_content {
                    let cipher = Aes256Gcm::new(shared_key.into());
                    if encrypted_content.len() < 12 {
                        return None;
                    }
                    let (nonce_bytes, ciphertext) = encrypted_content.split_at(12);
                    let nonce = Nonce::from_slice(nonce_bytes);
                    match cipher.decrypt(nonce, ciphertext) {
                        Ok(plaintext) => String::from_utf8(plaintext).ok(),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
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

    fn update(&self, new_data: RawProfileData, key: &[u8; 32]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = serde_json::to_vec(&new_data)
            .expect("Failed to serialize updated profile data");
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("Encryption failed");

        let mut encrypted_data = nonce_bytes.to_vec();
        encrypted_data.extend(ciphertext);
        encrypted_data
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
        let mut symmetric_key: [u8; 32] = [0u8; 32];
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
    bio_keywords: Option<Vec<String>>,
    min_score: Option<u32>,
    recent_matches: Option<bool>,
}

impl ProfileFilter {
    fn new(
        location: Option<String>,
        min_age: Option<u32>,
        max_age: Option<u32>,
        interests: Option<Vec<String>>,
        bio_keywords: Option<Vec<String>>,
        min_score: Option<u32>,
        recent_matches: Option<bool>,
    ) -> Self {
        ProfileFilter {
            location,
            min_age,
            max_age,
            interests,
            bio_keywords,
            min_score,
            recent_matches,
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
    messages: Vec<Transaction>,
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
            messages: Vec::new(),
            profile,
            relevant_profiles: Vec::new(),
        }
    }

    fn calculate_interaction_score(&self, target_id: &str) -> u32 {
        self.interactions
            .iter()
            .filter(|i| i.target_id == target_id || i.user_id == target_id)
            .map(|i| i.score)
            .sum()
    }

    fn fetch_relevant_profiles(
        &mut self,
        filter: &ProfileFilter,
        mock_profile_db: &[Profile],
        shared_keys: &mut HashMap<(String, String), [u8; 32]>,
        fetcher_id: &str,
        ledger: &GlobalLedger,
    ) -> Vec<String> {
        self.relevant_profiles.clear();
        let mut inaccessible_profiles = Vec::new();
        let mut profiles_with_scores: Vec<(Profile, u32)> = Vec::new();

        let recent_matches: Vec<(String, String)> = if filter.recent_matches.unwrap_or(false) {
            ledger
                .get_chain()
                .iter()
                .flat_map(|block| &block.transactions)
                .filter_map(|tx| {
                    if let TransactionType::Match = tx.transaction_type {
                        tx.match_pair.clone()
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let revoked_keys: Vec<(String, String)> = ledger
            .get_chain()
            .iter()
            .flat_map(|block| &block.transactions)
            .filter_map(|tx| {
                if let TransactionType::KeyRevocation = tx.transaction_type {
                    tx.revoked_key_pair.clone()
                } else {
                    None
                }
            })
            .collect();

        let blocked_users: Vec<(String, String)> = ledger
            .get_chain()
            .iter()
            .flat_map(|block| &block.transactions)
            .filter_map(|tx| {
                if let TransactionType::BlockUser = tx.transaction_type {
                    Some((tx.sender_id.clone(), tx.receiver_id.clone()))
                } else {
                    None
                }
            })
            .collect();

        let reported_users: HashMap<String, usize> = {
            let mut reports = HashMap::new();
            for block in ledger.get_chain() {
                for tx in &block.transactions {
                    if let TransactionType::ReportUser = tx.transaction_type {
                        *reports.entry(tx.receiver_id.clone()).or_insert(0) += 1;
                    }
                }
            }
            reports
        };

        const REPORT_THRESHOLD: usize = 2;

        for profile in mock_profile_db {
            if profile.is_deleted || profile.user_id == fetcher_id {
                continue;
            }

            if blocked_users.contains(&(fetcher_id.to_string(), profile.user_id.clone())) ||
               blocked_users.contains(&(profile.user_id.clone(), fetcher_id.to_string())) {
                continue;
            }

            if reported_users.get(&profile.user_id).unwrap_or(&0) >= &REPORT_THRESHOLD {
                continue;
            }

            let key_pair = (fetcher_id.to_string(), profile.user_id.clone());
            let reverse_key_pair = (profile.user_id.clone(), fetcher_id.to_string());
            match shared_keys.get(&key_pair) {
                Some(decryption_key) => {
                    if revoked_keys.contains(&reverse_key_pair) {
                        inaccessible_profiles.push(profile.user_id.clone());
                        continue;
                    }

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

                        if let Some(keywords) = &filter.bio_keywords {
                            let bio_lower = raw_data.bio.to_lowercase();
                            let any_keyword_present = keywords.iter()
                                .any(|kw| bio_lower.contains(&kw.to_lowercase()));
                            if !any_keyword_present {
                                matches = false;
                            }
                        }

                        let score = self.calculate_interaction_score(&profile.user_id);
                        if let Some(min_score) = filter.min_score {
                            if score < min_score {
                                matches = false;
                            }
                        }

                        if filter.recent_matches.unwrap_or(false) {
                            let is_recent_match = recent_matches.iter()
                                .any(|(id1, id2)| (id1 == fetcher_id && id2 == &profile.user_id) || (id2 == fetcher_id && id1 == &profile.user_id));
                            if !is_recent_match {
                                matches = false;
                            }
                        }

                        if matches {
                            profiles_with_scores.push((profile.clone(), score));
                        }
                    }
                }
                None => {
                    inaccessible_profiles.push(profile.user_id.clone());
                }
            }
        }

        if filter.min_score.is_some() {
            profiles_with_scores.sort_by(|a, b| b.1.cmp(&a.1));
        }

        self.relevant_profiles = profiles_with_scores.into_iter().map(|(p, _)| p).collect();
        inaccessible_profiles
    }

    fn delete_profile(&mut self, ledger: &mut GlobalLedger, mock_profile_db: &mut Vec<Profile>, timestamp: String, global_tx_id: String) {
        self.profile.is_deleted = true;
        if let Some(profile) = mock_profile_db.iter_mut().find(|p| p.user_id == self.user_id) {
            profile.is_deleted = true;
        }
        let deletion_tx = Transaction::new_profile_deletion(
            self.user_id.clone(),
            timestamp,
            global_tx_id,
        );
        ledger.add_block(vec![deletion_tx]);
    }

    fn update_profile(&mut self, ledger: &mut GlobalLedger, mock_profile_db: &mut Vec<Profile>, new_data: RawProfileData, key: &[u8; 32], timestamp: String, global_tx_id: String) {
        let updated_encrypted_data = self.profile.update(new_data, key);
        let update_tx = Transaction::new_profile_update(
            self.user_id.clone(),
            updated_encrypted_data.clone(),
            timestamp,
            global_tx_id,
        );
        self.profile.encrypted_data = updated_encrypted_data.clone();
        if let Some(profile) = mock_profile_db.iter_mut().find(|p| p.user_id == self.user_id) {
            profile.encrypted_data = updated_encrypted_data;
        }
        ledger.add_block(vec![update_tx]);
    }

    fn revoke_key(
        &mut self,
        ledger: &mut GlobalLedger,
        target_id: String,
        shared_keys: &mut HashMap<(String, String), [u8; 32]>,
        timestamp: String,
        global_tx_id: String,
    ) {
        let reverse_key_pair = (target_id.clone(), self.user_id.clone());
        shared_keys.remove(&reverse_key_pair);
        let revocation_tx = Transaction::new_key_revocation(
            self.user_id.clone(),
            target_id,
            timestamp,
            global_tx_id,
        );
        ledger.add_block(vec![revocation_tx]);
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
    miner_name: String,
}

impl GlobalBlock {
    fn new(transactions: Vec<Transaction>, previous_hash: String, miner: &Miner, difficulty: usize) -> Self {
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
            miner_name: miner.name.clone(),
        };
        miner.mine_block(&mut block, difficulty);
        block
    }

    fn compute_hash(&self) -> String {
        let mut hasher = Sha3_256::default();
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
        let genesis_miner = &miners[0];
        let genesis_block = GlobalBlock::new(
            vec![Transaction::new_peace_transfer(
                "system".to_string(),
                "genesis".to_string(),
                0.0,
                "2025-03-04".to_string(),
                "genesis_tx".to_string(),
            )],
            "0".to_string(),
            genesis_miner,
            initial_difficulty,
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
        
        let miner = self.miners.choose(&mut rand::thread_rng()).expect("At least one miner should exist");
        let miner_name = miner.name.clone();
        
        let start = Instant::now();
        let block = GlobalBlock::new(transactions, previous_hash, miner, self.difficulty as usize);
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

    let alice_keys = key_pairs.remove("alice").expect("Alice's key pair should exist");
    let alice_symmetric_key = alice_keys.symmetric_key;
    let alice_public_key = alice_keys.public_key;
    let bob_keys = key_pairs.remove("bob").expect("Bob's key pair should exist");
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
    shared_symmetric_keys.insert(("bob".to_string(), "bob".to_string()), bob_symmetric_key);

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
    let mut alice_shard = UserShard::new(
        "alice".to_string(),
        5.0,
        vec![tx.clone()],
        Vec::new(),
        alice_profile,
    );

    let start = Instant::now();
    let miner_name = ledger.add_block(vec![tx]);
    let duration = start.elapsed();
    println!("Block 1 mined by {} in {:?}", miner_name, duration);

    let basic_filter = ProfileFilter::new(
        Some("CA".to_string()),
        Some(25),
        Some(30),
        Some(vec!["hiking".to_string(), "photography".to_string()]),
        None,
        None,
        None,
    );

    println!("Fetching profiles before updates (basic filter):");
    let inaccessible = alice_shard.fetch_relevant_profiles(&basic_filter, &mock_profile_db, &mut shared_symmetric_keys, "alice", &ledger);
    for profile in &alice_shard.relevant_profiles {
        if let Some(key) = shared_symmetric_keys.get(&("alice".to_string(), profile.user_id.clone())) {
            if let Some(raw_data) = profile.decrypt(key) {
                println!("User {}: {:?}", profile.user_id, raw_data);
            }
        }
    }
    println!("Inaccessible profiles (missing keys): {:?}", inaccessible);

    println!("\nSimulating Alice updating her profile...");
    let updated_alice_data = RawProfileData {
        name: "Alice".to_string(),
        age: 28,
        bio: "Loves hiking, coffee, and now yoga".to_string(),
        interests: vec!["hiking".to_string(), "photography".to_string(), "yoga".to_string()],
        location: "CA".to_string(),
    };
    let start = Instant::now();
    alice_shard.update_profile(&mut ledger, &mut mock_profile_db, updated_alice_data, &alice_symmetric_key, "2025-03-05".to_string(), "update_alice".to_string());
    let duration = start.elapsed();
    let miner_name = ledger.get_chain().last().unwrap().miner_name.clone();
    println!("Block 2 mined by {} in {:?}", miner_name, duration);

    println!("\nSimulating a match between Alice and Bob...");
    let start = Instant::now();
    let match_tx = Transaction::new_match(
        "alice".to_string(),
        "bob".to_string(),
        "2025-03-06".to_string(),
        "match_alice_bob".to_string(),
    );
    let miner_name = ledger.add_block(vec![match_tx]);
    let duration = start.elapsed();
    println!("Block 3 mined by {} in {:?}", miner_name, duration);
    alice_shard.interactions.push(Interaction {
        event_type: "match".to_string(),
        user_id: "alice".to_string(),
        target_id: "bob".to_string(),
        score: 5,
    });

    println!("\nSimulating Alice messaging Bob...");
    let start = Instant::now();
    let message_tx1 = Transaction::new_message(
        "alice".to_string(),
        "bob".to_string(),
        "Hey Bob, loved your hiking photo!",
        &bob_symmetric_key,
        "2025-03-06".to_string(),
        "message_alice_bob_1".to_string(),
    );
    let miner_name = ledger.add_block(vec![message_tx1.clone()]);
    let duration = start.elapsed();
    println!("Block 4 mined by {} in {:?}", miner_name, duration);
    if let Some(content) = message_tx1.decrypt_content(&bob_symmetric_key) {
        println!("Decrypted message: {}", content);
    }
    alice_shard.messages.push(message_tx1.clone());
    alice_shard.interactions.push(Interaction {
        event_type: "message".to_string(),
        user_id: "alice".to_string(),
        target_id: "bob".to_string(),
        score: 2,
    });

    println!("\nSimulating Bob replying to Alice...");
    let start = Instant::now();
    let message_tx2 = Transaction::new_message(
        "bob".to_string(),
        "alice".to_string(),
        "Thanks Alice, your yoga pic is cool!",
        &alice_symmetric_key,
        "2025-03-06".to_string(),
        "message_bob_alice_1".to_string(),
    );
    let miner_name = ledger.add_block(vec![message_tx2.clone()]);
    let duration = start.elapsed();
    println!("Block 5 mined by {} in {:?}", miner_name, duration);
    if let Some(content) = message_tx2.decrypt_content(&alice_symmetric_key) {
        println!("Decrypted message: {}", content);
    }
    alice_shard.messages.push(message_tx2.clone());
    alice_shard.interactions.push(Interaction {
        event_type: "message".to_string(),
        user_id: "bob".to_string(),
        target_id: "alice".to_string(),
        score: 2,
    });

    println!("\nSimulating Alice sharing a photo with Bob...");
    let start = Instant::now();
    let photo_tx = Transaction::new_photo_share(
        "alice".to_string(),
        "bob".to_string(),
        "base64:yoga.jpg",
        &bob_symmetric_key,
        "2025-03-06".to_string(),
        "photo_alice_bob".to_string(),
    );
    let miner_name = ledger.add_block(vec![photo_tx.clone()]);
    let duration = start.elapsed();
    println!("Block 6 mined by {} in {:?}", miner_name, duration);
    if let Some(content) = photo_tx.decrypt_content(&bob_symmetric_key) {
        println!("Decrypted photo: {}", content);
    }
    alice_shard.messages.push(photo_tx.clone());
    alice_shard.interactions.push(Interaction {
        event_type: "photo_share".to_string(),
        user_id: "alice".to_string(),
        target_id: "bob".to_string(),
        score: 3,
    });

    println!("\nSimulating Charlie deleting their profile...");
    let mut charlie_shard = UserShard::new(
        "charlie".to_string(),
        0.0,
        Vec::new(),
        Vec::new(),
        mock_profile_db.iter()
            .find(|p| p.user_id == "charlie")
            .expect("Charlie's profile should exist")
            .clone(),
    );
    let start = Instant::now();
    charlie_shard.delete_profile(&mut ledger, &mut mock_profile_db, "2025-03-07".to_string(), "delete_charlie".to_string());
    let duration = start.elapsed();
    let miner_name = ledger.get_chain().last().unwrap().miner_name.clone();
    println!("Block 7 mined by {} in {:?}", miner_name, duration);

    println!("\nSimulating Alice revoking her key shared with Bob...");
    let start = Instant::now();
    alice_shard.revoke_key(&mut ledger, "bob".to_string(), &mut shared_symmetric_keys, "2025-03-08".to_string(), "revoke_alice_bob".to_string());
    let duration = start.elapsed();
    let miner_name = ledger.get_chain().last().unwrap().miner_name.clone();
    println!("Block 8 mined by {} in {:?}", miner_name, duration);

    println!("\nSimulating Bob blocking Charlie...");
    let start = Instant::now();
    let block_tx = Transaction::new_block_user(
        "bob".to_string(),
        "charlie".to_string(),
        "2025-03-09".to_string(),
        "block_bob_charlie".to_string(),
    );
    let miner_name = ledger.add_block(vec![block_tx]);
    let duration = start.elapsed();
    println!("Block 9 mined by {} in {:?}", miner_name, duration);

    println!("\nSimulating Bob video calling Alice...");
    let start = Instant::now();
    let video_call_tx = Transaction::new_video_call(
        "bob".to_string(),
        "alice".to_string(),
        600,
        "2025-03-10".to_string(),
        "videocall_bob_alice".to_string(),
    );
    let miner_name = ledger.add_block(vec![video_call_tx]);
    let duration = start.elapsed();
    println!("Block 10 mined by {} in {:?}", miner_name, duration);
    alice_shard.interactions.push(Interaction {
        event_type: "videocall".to_string(),
        user_id: "bob".to_string(),
        target_id: "alice".to_string(),
        score: 4,
    });

    println!("\nSimulating Alice reporting Charlie...");
    let start = Instant::now();
    let report_tx1 = Transaction::new_report_user(
        "alice".to_string(),
        "charlie".to_string(),
        "spam".to_string(),
        "2025-03-11".to_string(),
        "report_alice_charlie".to_string(),
    );
    let miner_name = ledger.add_block(vec![report_tx1]);
    let duration = start.elapsed();
    println!("Block 11 mined by {} in {:?}", miner_name, duration);

    println!("\nSimulating Bob reporting Charlie...");
    let start = Instant::now();
    let report_tx2 = Transaction::new_report_user(
        "bob".to_string(),
        "charlie".to_string(),
        "harassment".to_string(),
        "2025-03-12".to_string(),
        "report_bob_charlie".to_string(),
    );
    let miner_name = ledger.add_block(vec![report_tx2]);
    let duration = start.elapsed();
    println!("Block 12 mined by {} in {:?}", miner_name, duration);

    println!("\nSimulating Alice re-sharing her key with Bob...");
    let start = Instant::now();
    let cipher = Aes256Gcm::new(&shared_secret_alice_bob.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_key = cipher.encrypt(nonce, alice_symmetric_key.as_ref())
        .expect("Failed to encrypt symmetric key for re-sharing");
    let mut encrypted_key_with_nonce = nonce_bytes.to_vec();
    encrypted_key_with_nonce.extend(encrypted_key);
    let key_share_tx = Transaction::new_key_share(
        "alice".to_string(),
        "bob".to_string(),
        encrypted_key_with_nonce.clone(),
        "2025-03-13".to_string(),
        "keyshare_alice_bob".to_string(),
    );
    let miner_name = ledger.add_block(vec![key_share_tx]);
    let duration = start.elapsed();
    println!("Block 13 mined by {} in {:?}", miner_name, duration);
    shared_symmetric_keys.insert(("bob".to_string(), "alice".to_string()), alice_symmetric_key);
    ledger.chain.iter_mut().for_each(|block| {
        block.transactions.retain(|tx| {
            !matches!(tx.transaction_type, TransactionType::KeyRevocation)
                || tx.revoked_key_pair != Some(("alice".to_string(), "bob".to_string()))
        });
    });

    println!("\nSimulating Alice messaging Bob again...");
    let start = Instant::now();
    let message_tx3 = Transaction::new_message(
        "alice".to_string(),
        "bob".to_string(),
        "Let’s hike sometime!",
        &bob_symmetric_key,
        "2025-03-13".to_string(),
        "message_alice_bob_2".to_string(),
    );
    let miner_name = ledger.add_block(vec![message_tx3.clone()]);
    let duration = start.elapsed();
    println!("Block 14 mined by {} in {:?}", miner_name, duration);
    if let Some(content) = message_tx3.decrypt_content(&bob_symmetric_key) {
        println!("Decrypted message: {}", content);
    }
    alice_shard.messages.push(message_tx3.clone());
    alice_shard.interactions.push(Interaction {
        event_type: "message".to_string(),
        user_id: "alice".to_string(),
        target_id: "bob".to_string(),
        score: 2,
    });

    println!("\nSimulating Bob replying to Alice again...");
    let start = Instant::now();
    let message_tx4 = Transaction::new_message(
        "bob".to_string(),
        "alice".to_string(),
        "Sweet, how about Saturday?",
        &alice_symmetric_key,
        "2025-03-13".to_string(),
        "message_bob_alice_2".to_string(),
    );
    let miner_name = ledger.add_block(vec![message_tx4.clone()]);
    let duration = start.elapsed();
    println!("Block 15 mined by {} in {:?}", miner_name, duration);
    if let Some(content) = message_tx4.decrypt_content(&alice_symmetric_key) {
        println!("Decrypted message: {}", content);
    }
    alice_shard.messages.push(message_tx4.clone());
    alice_shard.interactions.push(Interaction {
        event_type: "message".to_string(),
        user_id: "bob".to_string(),
        target_id: "alice".to_string(),
        score: 2,
    });

    // Initialize bob_shard here with all interactions
    println!("\nBob fetching profiles after interactions (basic filter):");
    let mut bob_shard = UserShard::new(
        "bob".to_string(),
        0.0,
        Vec::new(),
        vec![
            Interaction {
                event_type: "match".to_string(),
                user_id: "alice".to_string(),
                target_id: "bob".to_string(),
                score: 5,
            },
            Interaction {
                event_type: "message".to_string(),
                user_id: "alice".to_string(),
                target_id: "bob".to_string(),
                score: 2,
            },
            Interaction {
                event_type: "message".to_string(),
                user_id: "bob".to_string(),
                target_id: "alice".to_string(),
                score: 2,
            },
            Interaction {
                event_type: "photo_share".to_string(),
                user_id: "alice".to_string(),
                target_id: "bob".to_string(),
                score: 3,
            },
            Interaction {
                event_type: "videocall".to_string(),
                user_id: "bob".to_string(),
                target_id: "alice".to_string(),
                score: 4,
            },
            Interaction {
                event_type: "message".to_string(),
                user_id: "alice".to_string(),
                target_id: "bob".to_string(),
                score: 2,
            },
            Interaction {
                event_type: "message".to_string(),
                user_id: "bob".to_string(),
                target_id: "alice".to_string(),
                score: 2,
            },
        ],
        mock_profile_db.iter()
            .find(|p| p.user_id == "bob")
            .expect("Bob's profile should exist")
            .clone(),
    );
    bob_shard.messages.push(message_tx1.clone());
    bob_shard.messages.push(message_tx2.clone());
    bob_shard.messages.push(photo_tx.clone());
    bob_shard.messages.push(message_tx3.clone());
    bob_shard.messages.push(message_tx4.clone());
    let inaccessible = bob_shard.fetch_relevant_profiles(&basic_filter, &mock_profile_db, &mut shared_symmetric_keys, "bob", &ledger);
    for profile in &bob_shard.relevant_profiles {
        if let Some(key) = shared_symmetric_keys.get(&("bob".to_string(), profile.user_id.clone())) {
            if let Some(raw_data) = profile.decrypt(key) {
                println!("User {}: {:?}", profile.user_id, raw_data);
            }
        }
    }
    println!("Inaccessible profiles (missing keys): {:?}", inaccessible);
    println!("Chat history for Bob:");
    for msg in &bob_shard.messages {
        if let Some(key) = shared_symmetric_keys.get(&(msg.sender_id.clone(), msg.receiver_id.clone())) {
            if let Some(content) = msg.decrypt_content(key) {
                match msg.transaction_type {
                    TransactionType::PhotoShare => println!("{}: {} -> {}: [Photo: {}]", msg.timestamp, msg.sender_id, msg.receiver_id, content),
                    _ => println!("{}: {} -> {}: {}", msg.timestamp, msg.sender_id, msg.receiver_id, content),
                }
            }
        }
    }

    let user_ids: Vec<String> = vec!["alice".to_string(), "bob".to_string(), "charlie".to_string(), "diana".to_string()];
    for i in 16..=TOTAL_BLOCKS {
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
                format!("2025-03-{:02}", i - 3),
                format!("tx{:03}_{}", i, j),
            ));
        }
        let miner_name = ledger.add_block(transactions);
        let duration = start.elapsed();
        println!("Block {} mined by {} in {:?}", i, miner_name, duration);
        println!("Current difficulty: {:.2}", ledger.get_difficulty());
    }

    println!("\nFetching profiles after updates, deletion, key revocation, block, video call, reports, and key re-sharing (basic filter):");
    let inaccessible = alice_shard.fetch_relevant_profiles(&basic_filter, &mock_profile_db, &mut shared_symmetric_keys, "alice", &ledger);
    for profile in &alice_shard.relevant_profiles {
        if let Some(key) = shared_symmetric_keys.get(&("alice".to_string(), profile.user_id.clone())) {
            if let Some(raw_data) = profile.decrypt(key) {
                println!("User {}: {:?}", profile.user_id, raw_data);
            }
        }
    }
    println!("Inaccessible profiles (missing keys): {:?}", inaccessible);
    println!("Chat history for Alice:");
    for msg in &alice_shard.messages {
        if let Some(key) = shared_symmetric_keys.get(&(msg.sender_id.clone(), msg.receiver_id.clone())) {
            if let Some(content) = msg.decrypt_content(key) {
                match msg.transaction_type {
                    TransactionType::PhotoShare => println!("{}: {} -> {}: [Photo: {}]", msg.timestamp, msg.sender_id, msg.receiver_id, content),
                    _ => println!("{}: {} -> {}: {}", msg.timestamp, msg.sender_id, msg.receiver_id, content),
                }
            }
        }
    }

    let enhanced_filter = ProfileFilter::new(
        Some("CA".to_string()),
        None,
        None,
        None,
        Some(vec!["hiking".to_string(), "yoga".to_string()]),
        Some(14),
        Some(true),
    );

    println!("\nFetching profiles with enhanced filter (bio keywords, min score, recent matches):");
    let inaccessible = alice_shard.fetch_relevant_profiles(&enhanced_filter, &mock_profile_db, &mut shared_symmetric_keys, "alice", &ledger);
    for profile in &alice_shard.relevant_profiles {
        if let Some(key) = shared_symmetric_keys.get(&("alice".to_string(), profile.user_id.clone())) {
            if let Some(raw_data) = profile.decrypt(key) {
                let score = alice_shard.calculate_interaction_score(&profile.user_id);
                println!("User {} (Score: {}): {:?}", profile.user_id, score, raw_data);
            }
        }
    }
    println!("Inaccessible profiles (missing keys): {:?}", inaccessible);

    println!("\nBob fetching profiles after key re-sharing (basic filter):");
    let inaccessible = bob_shard.fetch_relevant_profiles(&basic_filter, &mock_profile_db, &mut shared_symmetric_keys, "bob", &ledger);
    for profile in &bob_shard.relevant_profiles {
        if let Some(key) = shared_symmetric_keys.get(&("bob".to_string(), profile.user_id.clone())) {
            if let Some(raw_data) = profile.decrypt(key) {
                println!("User {}: {:?}", profile.user_id, raw_data);
            }
        }
    }
    println!("Inaccessible profiles (missing keys): {:?}", inaccessible);
    println!("Chat history for Bob (again):");
    for msg in &bob_shard.messages {
        if let Some(key) = shared_symmetric_keys.get(&(msg.sender_id.clone(), msg.receiver_id.clone())) {
            if let Some(content) = msg.decrypt_content(key) {
                match msg.transaction_type {
                    TransactionType::PhotoShare => println!("{}: {} -> {}: [Photo: {}]", msg.timestamp, msg.sender_id, msg.receiver_id, content),
                    _ => println!("{}: {} -> {}: {}", msg.timestamp, msg.sender_id, msg.receiver_id, content),
                }
            }
        }
    }

    println!("\nCuneos Global Ledger Chain:");
    for (i, block) in ledger.get_chain().iter().enumerate() {
        println!("Block {}: Hash = {}", i, block.hash);
        println!("  Previous Hash: {}", block.previous_hash);
        println!("  Timestamp: {}", block.timestamp);
        println!("  Transactions: {:?}", block.transactions);
        for tx in &block.transactions {
            match tx.transaction_type {
                TransactionType::Message => {
                    if let Some(key) = shared_symmetric_keys.get(&(tx.sender_id.clone(), tx.receiver_id.clone())) {
                        if let Some(content) = tx.decrypt_content(key) {
                            println!("  Decrypted Message ({} -> {}): {}", tx.sender_id, tx.receiver_id, content);
                        }
                    }
                }
                TransactionType::PhotoShare => {
                    if let Some(key) = shared_symmetric_keys.get(&(tx.sender_id.clone(), tx.receiver_id.clone())) {
                        if let Some(content) = tx.decrypt_content(key) {
                            println!("  Decrypted Photo ({} -> {}): {}", tx.sender_id, tx.receiver_id, content);
                        }
                    }
                }
                _ => {}
            }
        }
        println!("  Nonce: {}", block.nonce);
        println!("  Mined by: {}", block.miner_name);
    }

    println!("\nMiner Statistics:");
    let total_blocks = ledger.chain.len() as f64;
    let mut miner_wins: HashMap<String, usize> = HashMap::new();
    let mut miner_times: HashMap<String, Vec<f64>> = HashMap::new();

    for (i, block) in ledger.chain.iter().enumerate().skip(1) {
        *miner_wins.entry(block.miner_name.clone()).or_insert(0) += 1;
        miner_times
            .entry(block.miner_name.clone())
            .or_insert_with(Vec::new)
            .push(ledger.mining_durations[i - 1]);
    }

    let default_times: Vec<f64> = Vec::new();
    for miner in &ledger.miners {
        let wins = miner_wins.get(&miner.name).unwrap_or(&0);
        let win_rate = (*wins as f64 / total_blocks) * 100.0;
        let times = miner_times.get(&miner.name).unwrap_or(&default_times);
        let avg_time = if times.is_empty() {
            0.0
        } else {
            times.iter().sum::<f64>() / times.len() as f64
        };
        println!(
            "{}: Wins = {}, Win Rate = {:.2}%, Avg Mining Time = {:.3}s",
            miner.name, wins, win_rate, avg_time
        );
    }
}