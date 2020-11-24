use crate::api;
use bytes::{Buf, Bytes, BytesMut};
use core::task::{Context, Poll};
use futures::{ready, FutureExt, TryStreamExt};
use quinn::{
    Connection, ConnectionError, IncomingBiStreams, IncomingUniStreams, NewConnection, OpenBi,
    OpenUni, ReadError, VarInt, WriteError,
};

impl api::Connection for NewConnection {
    type Acceptor = Acceptor;
    type Handle = Handle;

    fn split(self) -> (Self::Handle, Self::Acceptor) {
        let NewConnection {
            uni_streams,
            bi_streams,
            connection,
            ..
        } = self;
        (
            Handle {
                connection,
                pending_bi: None,
                pending_uni: None,
            },
            Acceptor {
                uni_streams,
                bi_streams,
            },
        )
    }
}

#[derive(Debug)]
pub struct Acceptor {
    uni_streams: IncomingUniStreams,
    bi_streams: IncomingBiStreams,
}

impl api::Acceptor for Acceptor {
    type ReceiveStream = ReceiveStream;
    type BidiStream = BidiStream;
    type Error = ConnectionError;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<Option<Self::BidiStream>, Self::Error>> {
        let (send, receive) = match ready!(self.bi_streams.try_next().poll_unpin(cx))? {
            Some(x) => x,
            None => return Ok(None).into(),
        };

        Ok(Some(BidiStream {
            send,
            receive,
            recv_buf: BytesMut::new(),
        }))
        .into()
    }

    fn poll_accept_receive(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<Option<Self::ReceiveStream>, Self::Error>> {
        let receive = match ready!(self.uni_streams.try_next().poll_unpin(cx))? {
            Some(x) => x,
            None => return Ok(None).into(),
        };

        Ok(Some(ReceiveStream {
            receive,
            recv_buf: BytesMut::new(),
        }))
        .into()
    }
}

pub struct Handle {
    connection: Connection,
    pending_bi: Option<OpenBi>,
    pending_uni: Option<OpenUni>,
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            pending_bi: None,
            pending_uni: None,
        }
    }
}

impl api::Handle for Handle {
    type SendStream = SendStream;
    type BidiStream = BidiStream;
    type Error = ConnectionError;

    fn poll_open_send(&mut self, cx: &mut Context) -> Poll<Result<Self::SendStream, Self::Error>> {
        if self.pending_uni.is_none() {
            self.pending_uni = Some(self.connection.open_uni());
        }

        let send = ready!(self.pending_uni.as_mut().unwrap().poll_unpin(cx))?;

        Ok(Self::SendStream { send }).into()
    }

    fn poll_open_bidi(&mut self, cx: &mut Context) -> Poll<Result<Self::BidiStream, Self::Error>> {
        if self.pending_bi.is_none() {
            self.pending_bi = Some(self.connection.open_bi());
        }

        let (send, receive) = ready!(self.pending_bi.as_mut().unwrap().poll_unpin(cx))?;
        Ok(Self::BidiStream {
            send,
            receive,
            recv_buf: BytesMut::new(),
        })
        .into()
    }
}

#[derive(Debug)]
pub struct SendStream {
    send: quinn::SendStream,
}

#[derive(Debug)]
pub struct ReceiveStream {
    receive: quinn::RecvStream,
    recv_buf: BytesMut,
}

#[derive(Debug)]
pub struct BidiStream {
    send: quinn::SendStream,
    receive: quinn::RecvStream,
    recv_buf: BytesMut,
}

macro_rules! send_stream {
    ($ty:ident) => {
        impl api::SendStream for $ty {
            type Error = WriteError;

            fn poll_send(
                &mut self,
                chunk: &mut Bytes,
                cx: &mut Context,
            ) -> Poll<Result<(), Self::Error>> {
                let len = ready!(self.send.write(chunk.as_ref()).poll_unpin(cx))?;
                chunk.advance(len);
                if !chunk.is_empty() {
                    return Poll::Pending;
                }
                Ok(()).into()
            }

            fn poll_finish(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
                self.send.finish().poll_unpin(cx)
            }

            fn reset(&mut self, code: u64) {
                let _ = self.send.reset(VarInt::from_u64(code).unwrap());
            }
        }
    };
}

send_stream!(SendStream);
send_stream!(BidiStream);

const READ_BUF_SIZE: usize = 1024 * 4;

macro_rules! receive_stream {
    ($ty:ident) => {
        impl api::ReceiveStream for $ty {
            type Error = ReadError;

            fn poll_receive(
                &mut self,
                cx: &mut Context,
            ) -> Poll<Result<Option<Bytes>, Self::Error>> {
                self.recv_buf.resize(READ_BUF_SIZE, 0);

                let result = ready!(self.receive.read(&mut self.recv_buf).poll_unpin(cx))?;

                Ok(match result {
                    Some(n) => {
                        let buf = self.recv_buf.split_to(n).freeze();
                        Some(buf)
                    }
                    None => None,
                })
                .into()
            }

            fn stop_sending(&mut self, code: u64) {
                let _ = self.receive.stop(VarInt::from_u64(code).unwrap());
            }
        }
    };
}

receive_stream!(ReceiveStream);
receive_stream!(BidiStream);

impl api::BidiStream for BidiStream {
    type SendStream = SendStream;
    type ReceiveStream = ReceiveStream;

    fn split(self) -> (Self::SendStream, Self::ReceiveStream) {
        todo!()
    }
}
