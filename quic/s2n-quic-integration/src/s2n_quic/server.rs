use super::io::Duplex;
use crate::{rt::spawn, stream};
use bach::graph::{Node, Spawn};

#[derive(Debug)]
pub struct Server {
    pub streams: stream::Server,
}

impl Node<Duplex> for Server {
    fn run(&self, port: Duplex) -> Spawn {
        let streams = self.streams.clone();

        // TODO add certs

        let mut server = s2n_quic::Server::builder()
            .with_io(port)
            .unwrap()
            .start()
            .unwrap();

        async move {
            while let Some(connection) = server.accept().await {
                let scenario = streams.run(connection);
                spawn(async move {
                    scenario.await.expect("test failed");
                });
            }
        }
        .into()
    }
}
