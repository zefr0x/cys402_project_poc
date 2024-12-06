use bincode::{Decode, Encode};
use fhe::{
    bfv::{Ciphertext, PublicKey},
    mbfv::{CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use log::{info, warn};
use serde::{Deserialize, Serialize};

const DIFFICULTY_PREFIX: &str = "0";

pub fn calculate_hash(
    id: u64,
    timestamp: u128,
    previous_hash: &str,
    peer_id: &str,
    data: &BlockData,
    nonce: u64,
) -> Vec<u8> {
    let data = serde_json::json!({
        "id": id,
        "previous_hash": previous_hash,
        "peer_id": peer_id,
        "data": data,
        "timestamp": timestamp,
        "nonce": nonce
    });
    md5::compute(data.to_string().as_bytes()).to_vec()
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode, PartialEq)]
#[repr(u8)]
pub enum BlockData {
    Genesis = 0,
    CommonPoly(#[bincode(with_serde)] CommonRandomPoly) = 1,
    PublicKeyShare(#[bincode(with_serde)] PublicKeyShare) = 2,
    GlobalKey(#[bincode(with_serde)] PublicKey) = 3,
    CipherShare(#[bincode(with_serde)] Ciphertext) = 4,
    Tally(#[bincode(with_serde)] Ciphertext) = 5,
    DecreptionShare(#[bincode(with_serde)] DecryptionShare) = 6,
    Other(String) = 7,
}

impl std::fmt::Display for BlockData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Genesis => "Genesis".to_owned(),
                Self::CommonPoly(_) => "CommonPoly(...)".to_owned(),
                Self::PublicKeyShare(_) => "PublicKeyShare(...)".to_owned(),
                Self::GlobalKey(_) => "GlobalKey(...)".to_owned(),
                Self::CipherShare(_) => "CipherShare(...)".to_owned(),
                Self::Tally(_) => "Tally(...)".to_owned(),
                Self::DecreptionShare(_) => "DecreptionShare(...)".to_owned(),
                Self::Other(s) => s.to_owned(),
            }
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct Block {
    pub id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub peer_id: String,
    pub timestamp: u128,
    pub data: BlockData,
    pub nonce: u64,
}

fn mine_block(
    id: u64,
    timestamp: u128,
    previous_hash: &str,
    peer_id: &str,
    data: &BlockData,
) -> (u64, String) {
    info!("mining block...");
    let mut nonce = 0;

    loop {
        let hash = calculate_hash(id, timestamp, previous_hash, peer_id, data, nonce);
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
    pub fn new(id: u64, previous_hash: String, peer_id: &str, data: BlockData) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (nonce, hash) = mine_block(id, now, &previous_hash, peer_id, &data);
        Self {
            id,
            hash,
            peer_id: peer_id.to_owned(),
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
            peer_id: "".to_owned(),
            data: BlockData::Genesis,
            nonce: 1182,
            hash: "0046149ca6817e7af76a04d2d03358e5".to_string(),
        };

        // dbg!(mine_block(
        //     genesis_block.id,
        //     genesis_block.timestamp,
        //     &genesis_block.previous_hash,
        //     &genesis_block.peer_id,
        //     &genesis_block.data
        // ));

        self.blocks.push(genesis_block);
    }

    // FIX: Race condition when two nodes mine the exact same block.
    fn is_block_valid(&self, block: &Block, previous_block: &Block) -> bool {
        if block.previous_hash != previous_block.hash {
            warn!("block with id: {} has wrong previous hash", block.id);
            return false;
        } else if !hash_to_binary_representation(&hex::decode(&block.hash).unwrap())
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
            &block.peer_id,
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
