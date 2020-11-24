use crate::{
    api,
    rt::{delay, spawn},
    stream::scenario::{self, Scenario},
};
use anyhow::Result;
use bytes::Bytes;
use core::future::Future;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct Instructions {
    pub client: Arc<scenario::Streams>,
    pub server: Arc<scenario::Streams>,
}

impl Instructions {
    pub fn server(&self) -> Server {
        self.into()
    }

    pub fn client(&self) -> Client {
        self.into()
    }
}

impl From<Scenario> for Instructions {
    fn from(scenario: Scenario) -> Self {
        Self {
            client: Arc::new(scenario.client),
            server: Arc::new(scenario.server),
        }
    }
}

impl From<&Scenario> for Instructions {
    fn from(scenario: &Scenario) -> Self {
        Self {
            client: Arc::new(scenario.client.clone()),
            server: Arc::new(scenario.server.clone()),
        }
    }
}

macro_rules! endpoint {
    ($name:ident, $local:ident, $peer:ident) => {
        #[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
        pub struct $name(Endpoint);

        impl $name {
            pub fn run<C: 'static + api::Connection>(
                &self,
                connection: C,
            ) -> impl Future<Output = Result<()>> + 'static {
                self.0.run(connection)
            }
        }

        impl From<&Scenario> for $name {
            fn from(scenario: &Scenario) -> Self {
                let instructions: Instructions = scenario.into();
                instructions.into()
            }
        }

        impl From<Instructions> for $name {
            fn from(scenario: Instructions) -> Self {
                Self(Endpoint {
                    local: scenario.$local,
                    peer: scenario.$peer,
                })
            }
        }

        impl From<&Instructions> for $name {
            fn from(scenario: &Instructions) -> Self {
                Self(Endpoint {
                    local: scenario.$local.clone(),
                    peer: scenario.$peer.clone(),
                })
            }
        }
    };
}

endpoint!(Server, server, client);
endpoint!(Client, client, server);

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
struct Endpoint {
    local: Arc<scenario::Streams>,
    peer: Arc<scenario::Streams>,
}

impl Endpoint {
    fn run<C: 'static + api::Connection>(
        &self,
        connection: C,
    ) -> impl Future<Output = Result<()>> + 'static {
        let (handle, acceptor) = connection.split();
        let local = Self::local(&self.local, handle);
        let peer = Self::peer(&self.peer, acceptor);
        async move {
            // TODO check if we are allowed to have an error in this test
            futures::try_join!(local, peer).map(|_| ())?;
            Ok(())
        }
    }

    fn local<H: 'static + api::Handle>(
        streams: &Arc<scenario::Streams>,
        handle: H,
    ) -> impl Future<Output = Result<()>> + 'static {
        let mut uni_handles = vec![];
        let mut bidi_handles = vec![];

        for (id, scenario) in streams.uni_streams.iter() {
            let mut handle = handle.clone();
            let id = *id;
            let scenario = *scenario;
            uni_handles.push(async move {
                delay(scenario.delay).await;
                let stream = handle.open_send().await?;
                Self::sender(stream, id, scenario.local).await?;
                <Result<(), anyhow::Error>>::Ok(())
            });
        }

        for (id, scenario) in streams.bidi_streams.iter() {
            let mut handle = handle.clone();
            let id = *id;
            let scenario = *scenario;
            bidi_handles.push(async move {
                delay(scenario.delay).await;
                let stream = handle.open_bidi().await?;
                let (sender, receiver) = stream.split();
                let sender = Self::sender(sender, id, scenario.local);
                let receiver = Self::receiver(receiver, Bytes::new(), scenario.peer);
                futures::try_join!(sender, receiver)?;
                <Result<(), anyhow::Error>>::Ok(())
            });
        }

        async {
            let uni = futures::future::try_join_all(uni_handles);
            let bidi = futures::future::try_join_all(bidi_handles);
            futures::try_join!(uni, bidi)?;
            Ok(())
        }
    }

    fn peer<A: api::Acceptor>(
        _streams: &Arc<scenario::Streams>,
        _acceptor: A,
    ) -> impl Future<Output = Result<()>> + 'static {
        // TODO implement me
        async { todo!() }
    }

    async fn sender<S: api::SendStream>(
        mut stream: S,
        id: u64,
        scenario: scenario::Stream,
    ) -> Result<()> {
        // Write the scenario ID
        let id = Bytes::copy_from_slice(&id.to_be_bytes());
        stream.send(id).await?;

        let mut sender = scenario.data;
        let mut chunks = [bytes::Bytes::new()];

        while sender.send(scenario.send_amount, &mut chunks).is_some() {
            // TODO implement resets
            stream
                .send(core::mem::replace(&mut chunks[0], Bytes::new()))
                .await?;
        }

        stream.finish().await?;

        Ok(())
    }

    async fn receiver<S: api::ReceiveStream>(
        mut stream: S,
        prelude: Bytes,
        scenario: scenario::Stream,
    ) -> Result<()> {
        let mut receiver = scenario.data;
        receiver.receive(&[prelude]);

        while let Some(chunk) = stream.receive().await? {
            // TODO implement stop_sending
            receiver.receive(&[chunk]);
        }

        Ok(())
    }
}
