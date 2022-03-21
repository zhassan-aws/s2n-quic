use netbench::{
    scenario::{self, Scenario},
    Error, Result,
};
use s2n_quic::{provider::StartError, Client, Connection, Server};
use s2n_quic_core::{endpoint::Endpoint, inet::SocketAddress};
use s2n_quic_platform::io::testing::{self, spawn, spawn_primary, Model};
use std::{collections::HashSet, sync::Arc};

mod time;

trait ScenarioExt {
    fn with(&self) -> Config<(), (), fn(Model)>;

    fn run(&self) {
        self.with().run()
    }
}

impl ScenarioExt for Scenario {
    fn with(&self) -> Config<(), (), fn(Model)> {
        Config::new(self)
    }
}

struct Config<'a, S, C, N> {
    server: S,
    client: C,
    scenario: &'a Scenario,
    network: N,
    seed: u64,
}

impl<'a> Config<'a, (), (), fn(Model)> {
    pub fn new(scenario: &'a Scenario) -> Self {
        Self {
            server: (),
            client: (),
            scenario,
            network: |_network| {},
            seed: 123456789,
        }
    }
}

impl<'a, S: ServerConstructor, C: ClientConstructor, N: FnMut(Model)> Config<'a, S, C, N> {
    pub fn network<NewN: FnMut(Model)>(self, network: NewN) -> Config<'a, S, C, NewN> {
        Config {
            server: self.server,
            client: self.client,
            scenario: self.scenario,
            network,
            seed: self.seed,
        }
    }

    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    pub fn run(&mut self) {
        let model = Model::default();
        let seed = self.seed;
        let mut executor = testing::Executor::new(model.clone(), seed);
        let io = executor.io().clone();

        executor.enter(|| {
            let mut addresses = vec![];

            (self.network)(model);

            let server = &mut self.server;
            for (idx, server_scenario) in self.scenario.servers.iter().enumerate() {
                let certificate = &self.scenario.certificates[server_scenario.certificate as usize];
                let private_key = &self.scenario.certificates[server_scenario.private_key as usize];

                let tls = s2n_quic::provider::tls::default::Server::builder()
                    .with_certificate(&certificate.pem, &private_key.pem)
                    .unwrap()
                    .with_application_protocols(vec!["netbench".to_string()])
                    .unwrap()
                    .build()
                    .unwrap();

                let builder = Server::builder()
                    .with_io(Io(io.builder()))
                    .unwrap()
                    .with_event(s2n_quic::provider::event::tracing::Provider::default())
                    .unwrap()
                    .with_tls(tls)
                    .unwrap();

                // TODO set random

                let scenario = server_scenario.clone();
                let mut server = server.start(idx, builder).unwrap();

                addresses.push(server.local_addr().unwrap());

                spawn(async move {
                    while let Some(connection) = server.accept().await {
                        let scenario = scenario.clone();
                        spawn_primary(async move {
                            if let Err(err) = handle_connection(connection, scenario).await {
                                eprintln!("{}", err);
                            }
                        });
                    }

                    panic!("server shut down unexpectedly");
                });

                async fn handle_connection(
                    connection: Connection,
                    scenario: Arc<scenario::Server>,
                ) -> Result<()> {
                    let server_name = connection.server_name()?.ok_or("missing server name")?;
                    let scenario = scenario.on_server_name(&server_name)?;
                    let conn = netbench::Driver::new(
                        scenario,
                        netbench::s2n_quic::Connection::new(connection),
                    );

                    let mut trace = netbench::trace::Disabled::default();
                    // let mut trace = netbench::trace::StdioLogger::new(Default::default());
                    let mut checkpoints = HashSet::new();
                    let mut timer = time::Timer::default();

                    conn.run(&mut trace, &mut checkpoints, &mut timer).await?;

                    Ok(())
                }
            }

            let addresses = Arc::new(netbench::client::AddressMap::new_simple(
                &self.scenario,
                addresses,
            ));

            let client = &mut self.client;

            for (idx, client_scenario) in self.scenario.clients.iter().enumerate() {
                let ca = &self.scenario.certificates
                    [client_scenario.certificate_authorities[0] as usize];

                let tls = s2n_quic::provider::tls::default::Client::builder()
                    .with_certificate(&ca.pem)
                    .unwrap()
                    .with_application_protocols(vec!["netbench".to_string()])
                    .unwrap()
                    .build()
                    .unwrap();

                let builder = Client::builder()
                    .with_io(Io(io.builder()))
                    .unwrap()
                    .with_event(s2n_quic::provider::event::tracing::Provider::default())
                    .unwrap()
                    .with_tls(tls)
                    .unwrap();

                // TODO set random

                let client = client.start(idx, builder).unwrap();

                let scenario = client_scenario.clone();
                let addresses = addresses.clone();
                spawn_primary(async move {
                    if let Err(err) = handle_client(client, scenario, addresses).await {
                        eprintln!("{}", err);
                    }
                });

                async fn handle_client(
                    client: Client,
                    scenario: Arc<scenario::Client>,
                    addresses: Arc<netbench::client::AddressMap>,
                ) -> Result<()> {
                    let client = netbench::Client::new(client, &scenario, &addresses);

                    let mut trace = netbench::trace::Disabled::default();
                    // let mut trace = netbench::trace::StdioLogger::new(Default::default());
                    let mut checkpoints = HashSet::new();
                    let mut timer = time::Timer::default();

                    let mut client = client.run(&mut trace, &mut checkpoints, &mut timer).await?;

                    client.wait_idle().await?;

                    Ok(())
                }
            }
        });

        executor.run();
    }
}

struct Io(testing::Builder);

impl s2n_quic::provider::io::Provider for Io {
    type PathHandle = testing::PathHandle;
    type Error = Error;

    fn start<E: Endpoint<PathHandle = testing::PathHandle>>(
        self,
        endpoint: E,
    ) -> Result<SocketAddress, Error> {
        let (_, addr) = self.0.start(endpoint)?;
        Ok(addr)
    }
}

trait ServerConstructor {
    fn start<P: s2n_quic::server::ServerProviders>(
        &mut self,
        idx: usize,
        builder: s2n_quic::server::Builder<P>,
    ) -> Result<Server, StartError> {
        let _ = idx;
        builder.start()
    }
}

impl ServerConstructor for () {}

trait ClientConstructor {
    fn start<P: s2n_quic::client::ClientProviders>(
        &mut self,
        idx: usize,
        builder: s2n_quic::client::Builder<P>,
    ) -> Result<Client, StartError> {
        let _ = idx;
        builder.start()
    }
}

impl ClientConstructor for () {}

#[test]
fn request_response() {
    use netbench::units::*;
    use testing::time::delay;

    tracing_subscriber::fmt()
        .compact()
        // .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .init();

    Scenario::build_pair(|conn| {
        conn.open_send_stream(
            |local| {
                local.send(1.megabytes());
            },
            |peer| {
                peer.receive(1.megabytes());
            },
        );
    })
    .with()
    .network(|network| {
        spawn(async move {
            network.set_delay(500.millis()).set_jitter(3.millis() / 2);

            loop {
                //network.set_corrupt_rate(1000).set_mtu(1201);
                delay(1.seconds()).await;

                //network.set_corrupt_rate(10).set_mtu(1500);
                //delay(10.millis()).await;
            }
        });
    })
    .run();
}

#[test]
fn fuzzed() {
    use bolero::generator::*;
    use netbench::units::*;
    use testing::time::delay;

    let scenario = Scenario::build_pair(|conn| {
        conn.open_send_stream(
            |local| {
                local.send(1.megabytes());
            },
            |peer| {
                peer.receive(1.megabytes());
            },
        );
    });

    #[derive(Clone, Copy, Debug, TypeGenerator)]
    struct NetworkParams {
        #[generator(1200..1500)]
        mtu: u16,
        #[generator(100..500)]
        delay_ms: u64,
        #[generator(0..10)]
        jitter_ms: u64,
        corrupt_rate: Option<Rate>,

        #[generator(1000u64..10_000)]
        period_ms: u64,
    }

    #[derive(Clone, Copy, Debug, Default, TypeGenerator)]
    struct Rate {
        #[generator(10..100)]
        value: u64,
    }

    impl NetworkParams {
        fn apply(&self, network: &Model) {
            network
                .set_mtu(self.mtu)
                .set_delay(Duration::from_millis(self.delay_ms))
                .set_jitter(Duration::from_millis(self.jitter_ms))
                .set_corrupt_rate(self.corrupt_rate.unwrap_or_default().value);
        }
    }

    bolero::check!()
        .with_type::<(u64, Vec<NetworkParams>)>()
        .for_each(|(seed, params)| {
            scenario
                .with()
                .seed(*seed)
                .network(move |network| {
                    let params = params.clone();
                    spawn(async move {
                        for param in params.iter().cycle() {
                            param.apply(&network);
                            delay(Duration::from_millis(param.period_ms)).await;
                        }
                    });
                })
                .run();

            eprint!(".");
        });
}
