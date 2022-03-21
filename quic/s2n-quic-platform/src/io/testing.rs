// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::select::{self, Select};
use bach::executor::{Handle, JoinHandle};
use core::{pin::Pin, task::Poll, time::Duration};
use s2n_quic_core::{endpoint::Endpoint, inet::SocketAddress};

type Error = Box<dyn 'static + std::error::Error>;
type Result<T = (), E = Error> = core::result::Result<T, E>;

mod model;
pub mod network;
pub mod time;

pub use model::Model;
pub use network::{Network, PathHandle};
pub use time::now;

pub use bach::{
    rand,
    task::{spawn, spawn_primary},
};

pub struct Executor<N: Network> {
    executor: bach::executor::Executor<Env<N>>,
    io: Io,
}

impl<N: Network> Executor<N> {
    pub fn new(network: N, seed: u64) -> Self {
        let mut executor = bach::executor::Executor::new(|handle| Env {
            handle: handle.clone(),
            time: bach::time::Scheduler::new(Duration::from_micros(1)),
            rand: bach::rand::Scope::new(seed),
            buffers: network::Buffers::default(),
            network,
            stalled_iterations: 0,
        });

        let io = Io {
            handle: executor.handle().clone(),
            buffers: executor.environment().buffers.clone(),
        };

        Self { executor, io }
    }

    pub fn io(&self) -> &Io {
        &self.io
    }

    pub fn enter<F: FnOnce() -> O, O>(&mut self, f: F) -> O {
        self.executor.environment().enter(f)
    }

    pub fn run(&mut self) {
        self.executor.block_on_primary();
    }
}

struct Env<N> {
    handle: bach::executor::Handle,
    time: bach::time::Scheduler,
    rand: bach::rand::Scope,
    buffers: network::Buffers,
    network: N,
    stalled_iterations: usize,
}

impl<N> Env<N> {
    fn enter<F: FnOnce() -> O, O>(&self, f: F) -> O {
        self.handle.enter(|| self.time.enter(|| self.rand.enter(f)))
    }
}

impl<N: Network> bach::executor::Environment for Env<N> {
    fn run<Tasks, F>(&mut self, tasks: Tasks) -> Poll<()>
    where
        Tasks: Iterator<Item = F> + Send,
        F: 'static + FnOnce() -> Poll<()> + Send,
    {
        let mut is_ready = true;

        let Self {
            handle,
            time,
            rand,
            buffers,
            network,
            ..
        } = self;

        handle.enter(|| {
            time.enter(|| {
                rand.enter(|| {
                    for task in tasks {
                        is_ready &= task().is_ready();
                    }
                    network.execute(buffers);
                })
            })
        });

        if is_ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn on_macrostep(&mut self, count: usize) {
        // only advance time after a stall
        if count > 0 {
            self.stalled_iterations = 0;
            return;
        }

        self.stalled_iterations += 1;

        if self.stalled_iterations > 100 {
            panic!("stalled test");
        }

        while let Some(time) = self.time.advance() {
            let _ = time;
            if self.time.wake() > 0 {
                break;
            }
        }
    }
}

#[derive(Clone)]
pub struct Io {
    handle: Handle,
    buffers: network::Buffers,
}

impl Io {
    pub fn builder(&self) -> Builder {
        Builder {
            buffers: self.buffers.clone(),
            handle: self.handle.clone(),
            address: None,
        }
    }
}

pub struct Builder {
    buffers: network::Buffers,
    handle: Handle,
    address: Option<SocketAddress>,
}

impl Builder {
    pub fn start<E: Endpoint<PathHandle = network::PathHandle>>(
        self,
        endpoint: E,
    ) -> Result<(JoinHandle<()>, SocketAddress)> {
        let buffers = self.buffers;
        let handle = self.address.unwrap_or_else(|| buffers.generate_addr());

        buffers.register(handle);

        let instance = Instance {
            buffers,
            handle,
            endpoint,
        };
        let join = self.handle.spawn(instance.event_loop());
        Ok((join, handle))
    }
}

struct Instance<E> {
    buffers: network::Buffers,
    handle: SocketAddress,
    endpoint: E,
}

impl<E: Endpoint<PathHandle = network::PathHandle>> Instance<E> {
    async fn event_loop(self) {
        let Self {
            buffers,
            handle,
            mut endpoint,
        } = self;

        let clock = time::Clock::default();
        let mut timer = time::Timer::default();

        loop {
            let io_task = buffers.readiness(handle);

            let empty_task = futures::future::pending::<()>();

            let mut wakeups = endpoint.wakeups(&clock);
            let mut wakeups = Pin::new(&mut wakeups);

            let select::Outcome {
                rx_result,
                tx_result: _,
                timeout_expired: _,
                application_wakeup: _,
            } = if let Ok(res) = Select::new(io_task, empty_task, &mut wakeups, &mut timer).await {
                res
            } else {
                // The endpoint has shut down
                return;
            };

            if let Some(result) = rx_result {
                if result.is_err() {
                    // the endpoint shut down
                    return;
                }

                buffers.rx(handle, |queue| {
                    endpoint.receive(queue, &clock);
                });
            }

            buffers.tx(handle, |queue| {
                endpoint.transmit(queue, &clock);
            });

            if let Some(timestamp) = endpoint.timeout() {
                timer.update(timestamp);
            } else {
                timer.cancel();
            }
        }
    }
}
