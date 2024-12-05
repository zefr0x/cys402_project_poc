use bincode::{Decode, Encode};
use fhe::{bfv::{Ciphertext, PublicKey}, mbfv::{DecryptionShare, PublicKeyShare}};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};

const DIFFICULTY_PREFIX: &str = "0";

fn calculate_hash(
    id: u64,
    timestamp: u128,
    previous_hash: &str,
    data: &BlockData,
    nonce: u64,
) -> Vec<u8> {
    let data = serde_json::json!({
        "id": id,
        "previous_hash": previous_hash,
        "data": data,
        "timestamp": timestamp,
        "nonce": nonce
    });
    md5::compute(data.to_string().as_bytes()).to_vec()
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode,PartialEq)]
#[repr(u8)]
pub enum BlockData {
    Genesis = 0,
    PublicKeyShare(#[bincode(with_serde)] PublicKeyShare) = 1,
    PublicKey(#[bincode(with_serde)] PublicKey) = 2,
    CipherShare(#[bincode(with_serde)] Ciphertext) = 3,
    DecreptionShare(#[bincode(with_serde)] DecryptionShare) = 4,
    Other(String) = 5,
}

impl ToString for BlockData {
    fn to_string(&self) -> String {
        match self {
            Self::Genesis => "Genesis".to_owned(),
            Self::PublicKeyShare(_) => "PublicKeyShare(...)".to_owned(),
            Self::PublicKey(_) => "PublicKey(...)".to_owned(),
            Self::CipherShare(_) => "CipherShare(...)".to_owned(),
            Self::DecreptionShare(_) => "DecreptionShare(...)".to_owned(),
            Self::Other(s) => s.to_owned(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct Block {
    pub id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: u128,
    pub data: BlockData,
    pub nonce: u64,
}

fn mine_block(id: u64, timestamp: u128, previous_hash: &str, data: &BlockData) -> (u64, String) {
    info!("mining block...");
    let mut nonce = 0;

    loop {
        let hash = calculate_hash(id, timestamp, previous_hash, data, nonce);
        let binary_hash = hash_to_binary_representation(&hash);
        if binary_hash.starts_with(DIFFICULTY_PREFIX) {
            info!(
                "mined! nonce: {}, hash: {}, binary hash: {}",
                nonce,
                hex::encode(&hash),
                binary_hash
            );
            return (nonce, hex::encode(hash));
        }
        nonce += 1;
    }
}

impl Block {
    pub fn new(id: u64, previous_hash: String, data: BlockData) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (nonce, hash) = mine_block(id, now, &previous_hash, &data);
        Self {
            id,
            hash,
            timestamp: now,
            previous_hash,
            data,
            nonce,
        }
    }
}

fn hash_to_binary_representation(hash: &[u8]) -> String {
    let mut res: String = String::default();
    for c in hash {
        res.push_str(&format!("{:b}", c));
    }
    res
}

pub struct LocalChain {
    pub blocks: Vec<Block>,
}

impl LocalChain {
    pub fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    pub fn genesis(&mut self) {
        let genesis_block = Block {
            id: 0,
            timestamp: 1733239982214461380,
            previous_hash: String::from("genesis"),
            data: BlockData::Genesis,
            nonce: 20,
            hash: "0025952822c1cf0de553d6d9a6f133ad".to_string(),
        };

        // dbg!(mine_block(genesis_block.id, genesis_block.timestamp, &genesis_block.previous_hash, &genesis_block.data));

        self.blocks.push(genesis_block);
    }

    // FIX: Race condition when two nodes mine the exact same block.
    fn is_block_valid(&self, block: &Block, previous_block: &Block) -> bool {
        if block.previous_hash != previous_block.hash {
            warn!("block with id: {} has wrong previous hash", block.id);
            return false;
        } else if !hash_to_binary_representation(
            &hex::decode(&block.hash).unwrap(),
        )
        .starts_with(DIFFICULTY_PREFIX)
        {
            warn!("block with id: {} has invalid difficulty", block.id);
            return false;
        } else if block.id != previous_block.id + 1 {
            warn!(
                "block with id: {} is not the next block after the latest: {}",
                block.id, previous_block.id
            );
            return false;
        } else if hex::encode(calculate_hash(
            block.id,
            block.timestamp,
            &block.previous_hash,
            &block.data,
            block.nonce,
        )) != block.hash
        {
            warn!("block with id: {} has invalid hash", block.id);
            return false;
        }
        true
    }

    fn is_chain_valid(&self, chain: &[Block]) -> bool {
        for i in 0..chain.len() {
            if i == 0 {
                continue;
            }
            let first = chain.get(i - 1).unwrap();
            let second = chain.get(i).unwrap();
            if !self.is_block_valid(second, first) {
                return false;
            }
        }
        true
    }

    // FIX: We always choose the longest valid chain, only depending on the length.
    pub fn choose_chain(&mut self, local: Vec<Block>, remote: Vec<Block>) -> Vec<Block> {
        let is_local_valid = self.is_chain_valid(&local);
        let is_remote_valid = self.is_chain_valid(&remote);

        if is_local_valid && is_remote_valid {
            if local.len() >= remote.len() {
                local
            } else {
                remote
            }
        } else if is_remote_valid && !is_local_valid {
            warn!("Local chain is invalid");
            remote
        } else if !is_remote_valid && is_local_valid {
            warn!("Remote chain is invalid");
            local
        } else {
            panic!("local and remote chains are both invalid");
        }
    }
}
