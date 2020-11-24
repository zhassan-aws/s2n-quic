use crate::packet::Packet;
use bach::graph::{
    self,
    channel::{Receiver, Sender},
    duplex, ChannelMap, NodeId, Port, PortMap,
};

pub mod rx;
pub mod tx;

pub struct Duplex {
    pub rx: Receiver<Packet>,
    pub tx: Sender<Packet>,
}

impl Port for Duplex {
    type Handle = Handle;
}

type InnerPort = duplex::Duplex<Packet, Packet>;
type InnerHandle = duplex::Handle<Packet, Packet>;

#[derive(Clone, Copy)]
pub struct Handle(InnerHandle);

impl graph::Handle for Handle {
    type Port = Duplex;

    fn new(channels: &mut ChannelMap) -> Self {
        Self(channels.handle::<InnerPort>())
    }

    fn initialize(&self, instances: &mut PortMap) -> Self::Port {
        let InnerPort { rx, tx } = self.0.initialize(instances);
        Duplex { rx, tx }
    }

    fn node_id(&self) -> NodeId {
        self.0.node_id()
    }
}

impl s2n_quic::provider::io::Provider for Duplex {
    type Rx = rx::Rx;
    type Tx = tx::Tx;
    type Error = core::convert::Infallible;

    fn start(self) -> Result<s2n_quic_core::io::Duplex<Self::Rx, Self::Tx>, Self::Error> {
        let Self { rx, tx } = self;
        let rx = rx::Rx::new(rx);
        let tx = tx::Tx::new(tx);
        Ok(s2n_quic_core::io::Duplex { rx, tx })
    }
}
