use crate::{packet::Packet, rt::spawn, stream, udp::Socket};
use bach::graph::{duplex::Duplex, Node, Spawn};

#[derive(Debug)]
pub struct Client {
    pub server_cert: Vec<u8>,
    pub scenario: stream::Client,
}

pub type Port = Duplex<Packet, Packet>;

impl Node<Port> for Client {
    fn run(&self, port: Port) -> Spawn {
        let scenario = self.scenario.clone();
        let server_cert =
            quinn::Certificate::from_der(&self.server_cert).expect("invalid server cert");
        async move {
            let (server_addr, udp) = Socket::default().bind(port).await;

            let udp = async {
                spawn(udp).await?;
                Ok(())
            };

            let mut endpoint = quinn::Endpoint::builder();
            let mut client_config = quinn::ClientConfigBuilder::default();
            client_config.protocols(&[b"s2n-quic-integ"]);
            client_config
                .add_certificate_authority(server_cert)
                .expect("invalid server cert");
            endpoint.default_client_config(client_config.build());

            let (endpoint, _) = endpoint
                .bind(&"[::]:0".parse().unwrap())
                .expect("could not bind client socket");

            let connection = endpoint
                .connect(&server_addr, "localhost")
                .expect("could not connect to server")
                .await
                .expect("could not connect to server");

            let scenario = scenario.run(connection);
            futures::try_join!(scenario, udp).expect("test failed");
        }
        .into()
    }
}
