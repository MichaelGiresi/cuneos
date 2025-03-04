use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};



// Transaction: Tracks Peace movements
#[derive(Serialize, Deserialize, Debug)]
struct Transaction {
    sender_id: String,
    receiver_id: String,
    amount: f64,
    timestamp: String,
    global_tx_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Interaction {
    event_type: String,
    user_id: String,
    target_id: String,
    score: u32,
}

// Profile: User's dating profile
#[derive(Serialize, Deserialize, Debug)]
struct Profile {
    user_id: String,
    encrypted_data: Vec<u8>,
    is_deleted: bool,
}

// UserShard: Precise shard for one user
#[derive(Serialize, Deserialize, Debug)]
struct UserShard {
    user_id: String, // User id
    balance: f64, //Current Peace Coins
    transactions: Vec<Transaction>, //User's txs only
    interactions: Vec<Interaction>, // User's events only
    profile: Profile, // User's profile
    relevant_profiles: Vec<Profile>, //Filtered Matches
}

// GlobalBlock: Global ledger block (full notes)
#[derive(Serialize, Deserialize, Debug)]
struct GlobalBlock {
    transactions: Vec<Transaction>,
    previous_hash: String, //Links to prior block
    nonce: u64, // For proof-of-work
    hash: String, // Block hash
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
        let mut hasher = Sha3_256::new();
        let tx_bytes = serde_json::to_string(&self.transactions).unwrap().into_bytes();
        hasher.update(&tx_bytes);
        hasher.update(self.previous_hash.as_bytes());
        hex::encode(hasher.finalize())
    }
}

fn main() {
    // Test a UserShard
    let profile = Profile {
        user_id: "user1".to_string(),
        encrypted_data: b"encrypted_profile".to_vec(),
        is_deleted: false,
    };
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

    // Test a GlobalBlock
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

