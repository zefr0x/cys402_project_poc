mod bc;
mod cli;
mod p2p;
mod utils;

use std::sync::Arc;

use bc::BlockData;
use fhe::{
    bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use libp2p::{
    bytes::Buf,
    floodsub::{Floodsub, FloodsubEvent},
    futures::{AsyncReadExt, AsyncWriteExt, StreamExt},
    mdns,
    multiaddr::Protocol,
    noise,
    swarm::SwarmEvent,
    tcp, yamux, PeerId, StreamProtocol, SwarmBuilder,
};
use log::{error, info, warn};
use rand::{rngs::OsRng, thread_rng};
use tokio::{io::AsyncBufReadExt, sync::mpsc};

use p2p::{AppBehaviourEvent, BlockRequest, BlockResponse, ChainResponse, LocalChainRequest};

const DEGREE: usize = 8;
const PLAINTEXT_MODULUS: u64 = 4096;
const MODULI: &[u64; 3] = &[0xffffee001, 0xffffc4001, 0x1ffffe0001];

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    // CLI Hnadling
    let matches = cli::build().get_matches();

    let port = matches.get_one::<u16>("port").unwrap();
    let vote_with = matches.get_one::<bool>("vote-with").unwrap();

    // Blockchain init
    let mut app = bc::LocalChain::new();

    // Homomorphic
    let params = BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(PLAINTEXT_MODULUS)
        .set_moduli(MODULI)
        .build_arc()
        .unwrap();

    let secret_key = SecretKey::random(&params, &mut OsRng);

    // Networking
    let (chian_stream_response_sender, mut chain_stream_response_rcv) =
        mpsc::unbounded_channel::<ChainResponse>();
    let (block_stream_response_sender, mut block_stream_response_rcv) =
        mpsc::unbounded_channel::<BlockResponse>();
    let (init_sender, mut init_rcv) = mpsc::unbounded_channel();

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_quic()
        .with_behaviour(|key| {
            let peer_id = PeerId::from(key.public());

            info!("Peer Id: {}", peer_id);

            p2p::AppBehaviour {
                floodsub: Floodsub::new(peer_id),
                stream: libp2p_stream::Behaviour::default(),
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id).unwrap(),
            }
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    const CHAIN_STREAM_PROTOCOL: StreamProtocol = StreamProtocol::new("/chains");
    const BLOCK_STREAM_PROTOCOL: StreamProtocol = StreamProtocol::new("/blocks");

    let mut incoming_chain_streams = swarm
        .behaviour()
        .stream
        .new_control()
        .accept(CHAIN_STREAM_PROTOCOL)
        .unwrap();
    let mut incoming_block_streams = swarm
        .behaviour()
        .stream
        .new_control()
        .accept(BLOCK_STREAM_PROTOCOL)
        .unwrap();

    let chain_topic = libp2p::floodsub::Topic::new("chains");
    let block_topic = libp2p::floodsub::Topic::new("blocks");

    swarm
        .behaviour_mut()
        .floodsub
        .subscribe(chain_topic.clone());
    swarm
        .behaviour_mut()
        .floodsub
        .subscribe(block_topic.clone());

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    swarm
        .listen_on(
            format!("/ip4/0.0.0.0/udp/{}/quic-v1", port)
                .parse()
                .unwrap(),
        )
        .unwrap();

    let local_peer_id = *swarm.local_peer_id();

    tokio::spawn({
        let init_sender = init_sender.clone();
        async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            info!("sending init event");
            init_sender.send(true).unwrap();
        }
    });

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        tokio::select! {
            init = init_rcv.recv() => {
                if init.is_some() {
                    let peers = p2p::get_peers_list(&swarm);
                    app.genesis();

                    info!("connected nodes: {}", peers.len());
                    if peers.is_empty() {
                        let crp = CommonRandomPoly::new(&params, &mut thread_rng()).unwrap();
                        p2p::handle_create_block(bc::BlockData::CommonPoly(crp.clone()), &mut swarm, &mut app, block_topic.clone());
                        if let Some(crp) = app
                            .blocks
                            .iter()
                            .filter_map(|b| {
                                if let BlockData::CommonPoly(s) = &b.data {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            }).last() {
                                let public_key_share =
                                    PublicKeyShare::new(&secret_key, crp.clone(), &mut thread_rng()).unwrap();
                                p2p::handle_create_block(bc::BlockData::PublicKeyShare(public_key_share.clone()), &mut swarm, &mut app, block_topic.clone());
                            } else {
                                error!("There is no common polynomial in the blockchain.")
                            }
                    }
                    else {
                        let req = p2p::LocalChainRequest {
                            from_peer_id: *peers
                                .iter()
                                .last()
                                .unwrap()
                        };
                        // TODO: Ask multiple nodes, not just one, and select the best.

                        let bin = bincode::encode_to_vec(&req, bincode::config::standard()).unwrap();
                        let compressed = zstd::encode_all(bin.as_slice(), 19).unwrap();

                        info!("Sending chain request to {}", req.from_peer_id);
                        swarm
                            .behaviour_mut()
                            .floodsub
                            .publish(chain_topic.clone(), compressed.as_slice().to_owned());
                    }
                }
            }
            Ok(Some(line)) = stdin.next_line() => {
                match line.as_str() {
                    "lsp" => utils::handle_print_peers(&swarm),
                    cmd if cmd.starts_with("ls") => utils::handle_print_chain(&app),
                    cmd if cmd.starts_with("vote") => {
                        if let Ok(global_key) = app
                            .blocks
                            .iter()
                            .filter_map(|b| {
                                if let BlockData::PublicKeyShare(s) = &b.data {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            }).aggregate::<PublicKey>()
                        {
                            let data_bin = bincode::encode_to_vec(BlockData::GlobalKey(global_key.clone()), bincode::config::standard()).unwrap();
                            let data_hash = md5::compute(&data_bin);
                            info!("Global key hash: {}", hex::encode(data_hash.to_vec()));

                            let pt = if *vote_with {
                                Plaintext::try_encode(&[1_u64], Encoding::poly(), &params).unwrap()
                            } else {
                                Plaintext::try_encode(&[0_u64], Encoding::poly(), &params).unwrap()
                            };
                            let ct = global_key.try_encrypt(&pt, &mut thread_rng()).unwrap();

                            p2p::handle_create_block(bc::BlockData::CipherShare(ct), &mut swarm,  &mut app, block_topic.clone());
                        } else {
                            error!("There are no public key shares in the blockchain.");
                        };
                    },
                    cmd if cmd.starts_with("decrypt") => {
                        let ciphers: Vec<Ciphertext> = app.blocks
                            .iter()
                            .filter_map(|b| {
                                if let BlockData::CipherShare(s) = &b.data {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                        }).collect();

                        if !ciphers.is_empty() {
                            let mut sum = Ciphertext::zero(&params);

                            for cipher in &ciphers {
                                sum += cipher;
                            }

                            info!("Global key hash: {}", hex::encode(utils::hash(&BlockData::Tally(sum.clone()))));

                            let tally = Arc::new(sum);

                            let sh = DecryptionShare::new(&secret_key, &tally, &mut thread_rng()).unwrap();

                            p2p::handle_create_block(bc::BlockData::DecreptionShare(sh), &mut swarm,  &mut app, block_topic.clone());
                        } else {
                            warn!("There are no votes in the blockchain!");
                        }
                    }
                    cmd if cmd.starts_with("result") => {
                        let deciper_shares: Vec<DecryptionShare> = app.blocks
                            .iter()
                            .filter_map(|b| {
                                if let BlockData::DecreptionShare(s) = &b.data {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                        }).collect();
                        let number_of_shares = deciper_shares.len();

                        if number_of_shares != 0 {
                            let pt: Plaintext = deciper_shares.into_iter().aggregate().unwrap();

                            let tally_vec = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
                            let tally_result = tally_vec[0];

                            println!("Result: {} out of {} are with", tally_result, number_of_shares);
                        } else {
                            warn!("There are no decreption shares on the blockchain!");
                        }
                    }
                    cmd if cmd.starts_with("write") => {
                        p2p::handle_create_block(bc::BlockData::Other(cmd.to_owned()), &mut swarm, &mut app, block_topic.clone())
                    }
                _ => error!("unknown command"),
                }
            }
            response = chain_stream_response_rcv.recv()=>{
                let response = response.unwrap();
                let bin = bincode::encode_to_vec(&response, bincode::config::standard()).unwrap();
                let compressed = zstd::encode_all(bin.as_slice(), 19).unwrap();

                swarm
                    .behaviour_mut()
                    .floodsub
                    .publish(chain_topic.clone(), compressed.as_slice().to_owned());

                let bin = bincode::encode_to_vec(&app.blocks, bincode::config::standard()).unwrap();
                info!("Chain size: {} byte", bin.len());
                let compressed = zstd::encode_all(bin.as_slice(), 19).unwrap();
                info!("Compressed chain size: {} byte", compressed.len());

                let mut control = swarm.behaviour().stream.new_control();

                tokio::spawn(async move {

                    loop {
                        info!("Waiting for stream");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                        if let Ok(mut stream) = control.open_stream(response.receiver, CHAIN_STREAM_PROTOCOL).await {
                            info!("Stream opened");

                            stream.write_all(&compressed).await.unwrap();

                            stream.close().await.unwrap();

                            info!("Finish writing, stream closed");
                            break;
                        };
                    }
                });
            },
            response = block_stream_response_rcv.recv()=>{
                let response = response.unwrap();
                let bin = bincode::encode_to_vec(&response, bincode::config::standard()).unwrap();
                let compressed = zstd::encode_all(bin.as_slice(), 19).unwrap();

                swarm
                    .behaviour_mut()
                    .floodsub
                    .publish(chain_topic.clone(), compressed.as_slice().to_owned());

                let bin = bincode::encode_to_vec(app.blocks.get(response.block_id as usize).unwrap(), bincode::config::standard()).unwrap();
                info!("Block size: {} byte", bin.len());
                let compressed = zstd::encode_all(bin.as_slice(), 19).unwrap();
                info!("Compressed block size: {} byte", compressed.len());

                let mut control = swarm.behaviour().stream.new_control();

                tokio::spawn(async move {

                    loop {
                        info!("Waiting for stream");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                        if let Ok(mut stream) = control.open_stream(response.receiver, BLOCK_STREAM_PROTOCOL).await {
                            info!("Stream opened");

                            stream.write_all(&compressed).await.unwrap();

                            stream.close().await.unwrap();

                            info!("Finish writing, stream closed");
                            break;
                        };
                    }
                });
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                     info!(
                    "Local node is listening on {:?}",
                    address.with(Protocol::P2p(local_peer_id))
                );
                }
                SwarmEvent::ConnectionEstablished {
                endpoint, ..
                } => {
                    info!("Connected to {}", endpoint.get_remote_address());
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Discovered(
                    discovered_list,
                ))) => {
                    for (peer, _addr) in discovered_list {
                        swarm
                            .behaviour_mut()
                            .floodsub
                            .add_node_to_partial_view(peer);
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Expired(expired_list))) => {
                    for (peer, _addr) in expired_list {
                        if !swarm.behaviour().mdns.has_node(&peer) {
                            swarm
                                .behaviour_mut()
                                .floodsub
                                .remove_node_from_partial_view(&peer);
                        }
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Floodsub(FloodsubEvent::Message(msg))) => {
                    if let Ok(data) = zstd::decode_all(msg.data.reader()){
                    if let Ok(block_response) =
                        bincode::decode_from_slice(&data, bincode::config::standard())
                    {
                        let block_response: p2p::BlockResponse = block_response.0;
                        info!("received new block response from {}", msg.source.to_string());

                        if block_response.receiver == local_peer_id {
                            info!("Block response from {}:", msg.source);

                            while let Some((peer, mut stream)) = incoming_block_streams.next().await {
                                info!("Waiting for stream");
                                if peer == block_response.sender {
                                    info!("Reading block stream");
                                    let mut buf = Vec::new();

                                    let read = stream.read_to_end(&mut buf).await.unwrap();
                                    info!("{read}");

                                    let mut new_chain = app.blocks.clone();
                                    new_chain.push(bincode::decode_from_slice(&zstd::decode_all(buf.as_slice()).unwrap(), bincode::config::standard()).unwrap().0);

                                    app.blocks = app.choose_chain(app.blocks.clone(), new_chain);

                                    info!("Finish reading, stream closed");
                                    break;
                                }

                            }
                        }
                    } else if let Ok(resp) = bincode::decode_from_slice(&data, bincode::config::standard()) {
                        let resp: ChainResponse = resp.0;
                        if resp.receiver == local_peer_id {
                            info!("Chain response from {}", msg.source);

                            while let Some((peer, mut stream)) = incoming_chain_streams.next().await {
                                info!("Waiting for stream");
                                if peer == resp.sender {
                                    info!("Reading chain stream");
                                    let mut buf = Vec::new();

                                    let read = stream.read_to_end(&mut buf).await.unwrap();
                                    info!("{read}");

                                    app.blocks = app.choose_chain(app.blocks.clone(), bincode::decode_from_slice(&zstd::decode_all(buf.as_slice()).unwrap(), bincode::config::standard()).unwrap().0);

                                    info!("Finish reading, stream closed");
                                    break;
                                }

                            }


                        if let Some(crp) = app
                            .blocks
                            .iter()
                            .filter_map(|b| {
                                if let BlockData::CommonPoly(s) = &b.data {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            }).last() {
                                let public_key_share =
                                    PublicKeyShare::new(&secret_key, crp.clone(), &mut thread_rng()).unwrap();
                                p2p::handle_create_block(bc::BlockData::PublicKeyShare(public_key_share.clone()), &mut swarm, &mut app, block_topic.clone());
                            } else {
                                error!("There is no common polynomial in the blockchain.")
                            }
                        }
                    } else if let Ok(block_request) =
                        bincode::decode_from_slice(&data, bincode::config::standard())
                    {
                        let block_request: p2p::BlockRequest = block_request.0;
                        info!("received new block request from {}", msg.source.to_string());

                        let peer_id = block_request.from_peer_id;

                        if local_peer_id == peer_id {
                            if let Err(e) = block_stream_response_sender.send(BlockResponse {
                                sender: local_peer_id,
                                receiver: msg.source,
                                block_id: block_request.block_id,
                            }) {
                                error!("error sending response via channel, {}", e);
                            }
                        }
                    } else if let Ok(resp) = bincode::decode_from_slice(&data, bincode::config::standard())
                    {
                        let resp: LocalChainRequest = resp.0;
                        info!("sending local chain to {}", msg.source.to_string());
                        let peer_id = resp.from_peer_id;


                        if local_peer_id == peer_id {
                            if let Err(e) = chian_stream_response_sender.send(ChainResponse {
                                sender: local_peer_id,
                                receiver: msg.source,
                            }) {
                                error!("error sending response via channel, {}", e);
                            }
                        }
                    } else if let Ok(block_announce) =
                        bincode::decode_from_slice(&data, bincode::config::standard())
                    {
                        let block_announce: p2p::NewBlockAnnounce = block_announce.0;
                        info!("received new block announcement from {}", msg.source.to_string());

                        let request = BlockRequest { from_peer_id: msg.source, block_id: block_announce.block_id};

                        let bin = bincode::encode_to_vec(&request, bincode::config::standard()).unwrap();
                        let compressed = zstd::encode_all(bin.as_slice(), 19).unwrap();

                        swarm
                            .behaviour_mut()
                            .floodsub
                            .publish(block_topic.clone(), compressed.as_slice().to_owned());
                    }
                    }
                }
                _ => {}
            }
        }
    }
}
