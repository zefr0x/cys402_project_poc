use bincode::{Decode, Encode};
use libp2p::{
    floodsub::{Floodsub, Topic},
    mdns,
    swarm::{NetworkBehaviour, Swarm},
    PeerId,
};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::hash_set::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ChainResponse {
    #[bincode(with_serde)]
    pub sender: PeerId,
    #[bincode(with_serde)]
    pub receiver: PeerId,
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
pub struct LocalChainRequest {
    #[bincode(with_serde)]
    pub from_peer_id: PeerId,
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
pub struct NewBlockAnnounce {
    #[bincode(with_serde)]
    pub block_id: u64,
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
pub struct BlockRequest {
    #[bincode(with_serde)]
    pub from_peer_id: PeerId,
    pub block_id: u64,
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
pub struct BlockResponse {
    #[bincode(with_serde)]
    pub sender: PeerId,
    #[bincode(with_serde)]
    pub receiver: PeerId,
    pub block_id: u64,
}

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub floodsub: Floodsub,
    pub stream: libp2p_stream::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub fn get_list_peers(swarm: &Swarm<AppBehaviour>) -> Vec<PeerId> {
    info!("Discovered Peers:");
    let nodes = swarm.behaviour().mdns.discovered_nodes();
    let mut unique_peers = HashSet::new();
    for peer in nodes {
        unique_peers.insert(peer);
    }

    unique_peers
        .iter()
        .map(|x| x.to_owned().to_owned())
        .collect()
}

pub fn handle_print_peers(swarm: &Swarm<AppBehaviour>) {
    let peers = get_list_peers(swarm);
    peers.iter().for_each(|p| println!("{}", p));
}

pub fn handle_print_chain(app: &crate::bc::LocalChain) {
    for block in &app.blocks {
        println!(
            "id: {}\nhash: {}\nparent-hash: {}\ntimestamp: {}\nnonce: {}\ndata: {}\n---",
            block.id,
            block.hash,
            block.previous_hash,
            block.timestamp,
            block.nonce,
            block.data.to_string()
        );
    }
}

pub fn handle_create_block(
    data: crate::bc::BlockData,
    swarm: &mut Swarm<AppBehaviour>,
    app: &mut crate::bc::LocalChain,
    block_topic: Topic,
) {
    let behaviour = swarm.behaviour_mut();
    let latest_block = app.blocks.last().unwrap();
    let block = crate::bc::Block::new(latest_block.id + 1, latest_block.hash.clone(), data);

    let announce = NewBlockAnnounce { block_id: block.id };

    app.blocks.push(block);
    info!("announce new block");

    let bin = bincode::encode_to_vec(&announce, bincode::config::standard()).unwrap();
    let compressed = zstd::encode_all(bin.as_slice(), 19).unwrap();

    behaviour
        .floodsub
        .publish(block_topic, compressed.as_slice().to_owned());
}
