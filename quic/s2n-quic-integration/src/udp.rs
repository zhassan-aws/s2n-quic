use crate::packet::Packet;
use bach::graph::duplex::Duplex;
use core::future::Future;
use futures::{future::FutureExt, select};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;

pub struct Socket {
    interface: Option<IpAddr>,
    buf_size: usize,
}

impl Default for Socket {
    fn default() -> Self {
        Self {
            interface: None,
            buf_size: 1024,
        }
    }
}

impl Socket {
    pub async fn bind(
        &self,
        duplex: Duplex<Packet, Packet>,
    ) -> (SocketAddr, impl Future<Output = ()>) {
        let buf_size = self.buf_size;
        let ip = self.interface.unwrap_or_else(|| Ipv6Addr::LOCALHOST.into());

        let mut socket = UdpSocket::bind((ip, 0))
            .await
            .expect("could not bind UDP socket");

        let local_addr = socket.local_addr().expect("could not bind UDP socket");

        let runner = async move {
            loop {
                let mut recv_buf = vec![0u8; buf_size];

                select! {
                    socket_rx_result = socket.recv_from(&mut recv_buf[..]).fuse() => {
                        match socket_rx_result {
                            Ok((len, source)) => {
                                let packet = Packet {
                                    destination_address: local_addr.into(),
                                    source_address: source.into(),
                                    ecn: Default::default(),
                                    ipv6_flow_label: Default::default(),
                                    payload: recv_buf[..len].to_vec(),
                                };
                                duplex.tx.broadcast(packet);
                            }
                            Err(err) => {
                                panic!("socket error: {:?}", err);
                            }
                        }
                    }
                    channel_rx_result = duplex.rx.receive().fuse() => {
                        match channel_rx_result {
                            Some(packet) => {
                                let packet = packet.body;
                                let payload = &packet.payload[..];
                                let addr: SocketAddr = packet.destination_address.into();
                                socket.send_to(payload, addr).await.expect("could not send packet");
                            }
                            None => {
                                // shut down the connection
                                break;
                            }
                        }
                    }
                };
            }
        };

        (local_addr, runner)
    }
}
