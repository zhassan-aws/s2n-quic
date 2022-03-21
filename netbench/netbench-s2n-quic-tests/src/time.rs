use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use s2n_quic_core::time::Timestamp;
use s2n_quic_platform::io::testing::time;

#[derive(Default)]
pub struct Timer(time::Timer);

impl netbench::Timer for Timer {
    fn now(&self) -> Timestamp {
        time::now()
    }

    fn poll(&mut self, target: Timestamp, cx: &mut Context) -> Poll<()> {
        self.0.update(target);
        Pin::new(&mut self.0).poll(cx)
    }
}
