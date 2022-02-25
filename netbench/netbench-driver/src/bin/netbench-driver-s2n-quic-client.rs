use netbench::Result;
use s2n_quic::provider::{io, tls::default::certificate::IntoCertificate};
use std::collections::HashSet;
use structopt::StructOpt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    Client::from_args().run().await.map_err(|e| e.to_string())
}

#[derive(Debug, StructOpt)]
pub struct Client {
    #[structopt(flatten)]
    opts: netbench_driver::Client,

    #[structopt(long)]
    disable_gso: bool,
}

impl Client {
    pub async fn run(&self) -> Result<()> {
        let addresses = self.opts.address_map().await?;
        let scenario = self.opts.scenario();

        let client = self.client()?;
        let client = netbench::Client::new(client, &scenario, &addresses);
        let mut trace = self.opts.trace();
        let mut checkpoints = HashSet::new();
        let mut timer = netbench::timer::Tokio::default();
        let mut client = client.run(&mut trace, &mut checkpoints, &mut timer).await?;

        client.wait_idle().await?;

        Ok(())
    }

    fn client(&self) -> Result<s2n_quic::Client> {
        // TODO support loading multiple CAs in s2n-quic
        let ca = self.opts.certificate_authorities().next().unwrap();
        let ca = ca.pem.as_str().into_certificate()?;

        let tls = s2n_quic::provider::tls::default::Client::builder()
            .with_certificate(ca)?
            // handle larger cert chains
            .with_max_cert_chain_depth(10)?
            .with_application_protocols(
                self.opts.application_protocols.iter().map(String::as_bytes),
            )?
            .with_key_logging()?
            .build()?;

        let mut io_builder =
            io::Default::builder().with_receive_address((self.opts.local_ip, 0u16).into())?;

        if self.disable_gso {
            io_builder = io_builder.with_gso_disabled()?;
        }

        let io = io_builder.build()?;

        let client = s2n_quic::Client::builder()
            .with_io(io)?
            .with_tls(tls)?
            .start()
            .unwrap();

        Ok(client)
    }
}
