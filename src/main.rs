use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest as Sha2Digest};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use serde::{Serialize, Deserialize};
use warp::Filter;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use x25519_dalek::{PublicKey, EphemeralSecret};
use hex;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Block {
    index: u64,
    timestamp: u64,
    data: String,
    previous_hash: String,
    hash: String,
    nonce: u64,
    profile: Option<Profile>,
    transaction: Option<Transaction>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Profile {
    account_number: u32,
    first_name: String,
    last_name: String,
    age: u32,
    height: u32,
    gender: String,
    location: String,
    interests: Vec<String>,
    address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Transaction {
    sender: String,
    recipient: String,
    amount: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Miner {
    id: u32,
    // Add fields as needed
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Blockchain {
    chain: Vec<Block>,
    difficulty: usize,
    peace_balances: HashMap<String, u64>,
    total_peace: u64,
    miners: Vec<Miner>, // Added for miner selection
}

impl Block {
    fn new(index: u64, data: String, previous_hash: String, difficulty: usize, profile: Option<Profile>, transaction: Option<Transaction>) -> Block {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut block = Block {
            index,
            timestamp,
            data,
            previous_hash,
            hash: String::new(),
            nonce: 0,
            profile,
            transaction,
        };
        block.hash = block.calculate_hash();
        block.mine_block(difficulty);
        block
    }

    fn calculate_hash(&self) -> String {
        let input = format!(
            "{}{}{}{}{}{}",
            self.index,
            self.timestamp,
            self.data,
            self.previous_hash,
            self.nonce,
            self.transaction.as_ref().map_or("".to_string(), |t| format!("{}{}{}", t.sender, t.recipient, t.amount))
        );
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        hex::encode(result) // Use hex encoding
    }

    fn mine_block(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);
        while &self.hash[..difficulty] != target {
            self.nonce += 1;
            self.hash = self.calculate_hash();
        }
    }
}

impl Blockchain {
    fn new() -> Blockchain {
        let mut blockchain = Blockchain {
            chain: Vec::new(),
            difficulty: 1,
            peace_balances: HashMap::new(),
            total_peace: 0,
            miners: vec![Miner { id: 1 }], // Placeholder miner
        };
        let genesis_profile = Some(Profile {
            account_number: 1,
            first_name: String::from("Genesis"),
            last_name: String::from("User"),
            age: 25,
            height: 170,
            gender: String::from("Non-binary"),
            location: String::from("Internet"),
            interests: vec![String::from("blockchain"), String::from("coding")],
            address: "genesis".to_string(),
        });
        let genesis_block = Block::new(0, "Genesis Block".to_string(), "0".to_string(), 1, genesis_profile, None);
        blockchain.chain.push(genesis_block);
        blockchain.peace_balances.insert("user1".to_string(), 1_000_000);
        blockchain.total_peace = 1_000_000;
        blockchain
    }

    fn add_block(&mut self, data: String, profile: Option<Profile>, transaction: Option<Transaction>) {
        let previous_block = self.chain.last().unwrap();
        let new_block = Block::new(previous_block.index + 1, data, previous_block.hash.clone(), self.difficulty, profile, transaction.clone());
        if let Some(tx) = transaction {
            if self.total_peace + tx.amount <= 21_000_000 {
                if let Some(sender_balance) = self.peace_balances.get_mut(&tx.sender) {
                    if *sender_balance >= tx.amount {
                        *sender_balance -= tx.amount;
                        *self.peace_balances.entry(tx.recipient.clone()).or_insert(0) += tx.amount;
                    }
                }
            }
        }
        self.chain.push(new_block);
    }

    fn delete_profile(&mut self, index: usize) -> String {
        if index < self.chain.len() {
            self.chain[index].profile = None;
            format!("Profile deleted from block {}", index)
        } else {
            format!("Block index {} does not exist", index)
        }
    }

    fn save_to_file(&self, filename: &str) -> io::Result<()> {
        let file = File::create(filename)?;
        serde_json::to_writer(file, self)?;
        Ok(())
    }

    fn load_from_file(filename: &str) -> io::Result<Self> {
        let mut file = File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let blockchain: Blockchain = serde_json::from_str(&contents)?;
        Ok(blockchain)
    }

    fn get_balance(&self, address: &str) -> u64 {
        *self.peace_balances.get(address).unwrap_or(&0)
    }

    // Placeholder decryption function for your encryption logic
    fn decrypt_data(&self, ciphertext: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        let nonce = Nonce::from_slice(&ciphertext[..12]); // Assuming first 12 bytes are nonce
        let payload = Payload {
            msg: &ciphertext[12..],
            aad: b"", // Additional authenticated data, adjust as needed
        };
        cipher.decrypt(nonce, payload).ok()
    }
}

impl fmt::Display for Blockchain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for block in &self.chain {
            writeln!(f, "Block {}:", block.index)?;
            writeln!(f, "  Timestamp: {}", block.timestamp)?;
            writeln!(f, "  Data: {}", block.data)?;
            writeln!(f, "  Previous Hash: {}", block.previous_hash)?;
            writeln!(f, "  Hash: {}", block.hash)?;
            writeln!(f, "  Nonce: {}", block.nonce)?;
            if let Some(profile) = &block.profile {
                writeln!(f, "  Profile: {} {} (Age: {}, Height: {}cm, Address: {})", 
                    profile.first_name, profile.last_name, profile.age, profile.height, profile.address)?;
                writeln!(f, "  Peace Balance: {}", self.get_balance(&profile.address))?;
            } else {
                writeln!(f, "  Profile: [Deleted]")?;
            }
            if let Some(tx) = &block.transaction {
                writeln!(f, "  Transaction: {} sent {} Peace to {}", tx.sender, tx.amount, tx.recipient)?;
            }
            writeln!(f, "-------------------")?;
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct AddUserRequest {
    first_name: String,
    last_name: String,
    age: u32,
    height: u32,
}

#[derive(Deserialize, Debug)]
struct DeleteProfileRequest {
    index: usize,
}

#[derive(Deserialize, Debug)]
struct SendPeaceRequest {
    sender: String,
    recipient: String,
    amount: u64,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let filename = "blockchain.json";
    let blockchain = Arc::new(Mutex::new(
        match Blockchain::load_from_file(filename) {
            Ok(loaded) => {
                println!("Loaded existing blockchain from {}", filename);
                loaded
            }
            Err(_) => {
                println!("No existing blockchain found, creating new one...");
                Blockchain::new()
            }
        }
    ));

    let ip = "192.168.1.46"; // Replace with your actual IP
    let index = warp::path::end().map({
        let ip = ip.to_string();
        let blockchain = Arc::clone(&blockchain);
        move || {
            let blockchain = blockchain.lock().unwrap();
            let html = include_str!("index.html")
                .replace("http://localhost:8080", &format!("http://{}:8080", ip))
                .replace("{{USER_BALANCE}}", &blockchain.get_balance("user1").to_string());
            warp::reply::html(html)
        }
    });

    let add_user = warp::path("add")
        .and(warp::post())
        .and(warp::body::json())
        .map({
            let blockchain = Arc::clone(&blockchain);
            move |req: AddUserRequest| {
                println!("Received add request: {:?}", req);
                let mut blockchain = blockchain.lock().unwrap();
                let address = format!("user{}", blockchain.chain.len() + 1);
                let profile = Some(Profile {
                    account_number: blockchain.chain.len() as u32 + 1,
                    first_name: req.first_name,
                    last_name: req.last_name,
                    age: req.age,
                    height: req.height,
                    gender: String::from("Unknown"),
                    location: String::from("Unknown"),
                    interests: vec![String::from("dating")],
                    address,
                });
                blockchain.add_block("User joined".to_string(), profile, None);
                blockchain.save_to_file(filename).unwrap();
                "User added successfully!"
            }
        });

    let delete_profile = warp::path("delete")
        .and(warp::post())
        .and(warp::body::json())
        .map({
            let blockchain = Arc::clone(&blockchain);
            move |req: DeleteProfileRequest| {
                println!("Received delete request for index: {}", req.index);
                let mut blockchain = blockchain.lock().unwrap();
                let result = blockchain.delete_profile(req.index);
                blockchain.save_to_file(filename).unwrap();
                result
            }
        });

    let show_blockchain = warp::path("blockchain")
        .and(warp::get())
        .map({
            let blockchain = Arc::clone(&blockchain);
            move || {
                println!("Received blockchain request");
                let blockchain = blockchain.lock().unwrap();
                format!("{}", blockchain)
            }
        });

    let send_peace = warp::path("send_peace")
        .and(warp::post())
        .and(warp::body::json())
        .map({
            let blockchain = Arc::clone(&blockchain);
            move |req: SendPeaceRequest| {
                println!("Received send peace request: {:?}", req);
                let mut blockchain = blockchain.lock().unwrap();
                blockchain.add_block("Peace transaction".to_string(), None, Some(Transaction {
                    sender: req.sender.clone(),
                    recipient: req.recipient.clone(),
                    amount: req.amount,
                }));
                blockchain.save_to_file(filename).unwrap();
                format!("Sent {} Peace from {} to {}", req.amount, req.sender, req.recipient)
            }
        });

    let routes = index
        .or(add_user)
        .or(delete_profile)
        .or(show_blockchain)
        .or(send_peace)
        .with(warp::cors().allow_any_origin());

    println!("Server running at http://0.0.0.0:8080 (use your local IP on other devices)");
    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
    Ok(())
}