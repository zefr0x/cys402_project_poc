pub fn hash(data: &impl bincode::Encode) -> Vec<u8> {
    let bin = bincode::encode_to_vec(data, bincode::config::standard()).unwrap();

    md5::compute(bin).to_vec()
}

pub fn handle_print_peers(swarm: &libp2p::swarm::Swarm<crate::p2p::AppBehaviour>) {
    let peers = crate::p2p::get_peers_list(swarm);
    peers.iter().for_each(|p| println!("{}", p));
}

pub fn handle_print_chain(app: &crate::bc::LocalChain) {
    for block in &app.blocks {
        println!(
            "id: {}\nhash: {}\nparent-hash: {}\ntimestamp: {}\npeer_id: {}\nnonce: {}\ndata: {}\ndata_hash: {}\n---",
            block.id,
            block.hash,
            block.previous_hash,
            block.timestamp,
            block.peer_id,
            block.nonce,
            block.data,
            hex::encode(crate::utils::hash(&block.data)),
        );
    }
}
