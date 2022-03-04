use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use lnk_cryptovec::CryptoVec;
use futures::stream::{Stream, StreamExt};
use std;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;

#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(not(unix))]
use tokio::net::TcpStream;

use super::{revoke_key, Agent, Connection, Error, KeyStore, Lock, Revoker, ServerStream};
use crate::key::Private;

pub struct Revoke {}

impl<K> Revoker<K> for Revoke
where
    K: Send + Sync + 'static,
{
    fn revoke(&self, keys: KeyStore<K>, blob: Vec<u8>, now: SystemTime, duration: Duration) {
        tokio::spawn(async move {
            sleep(duration).await;
            revoke_key(keys, blob, now)
        });
    }
}

#[cfg(unix)]
#[async_trait]
impl ServerStream for UnixStream {
    type Error = std::io::Error;

    async fn serve<K, L, A>(mut listener: L, agent: A) -> Result<(), Self::Error>
    where
        K: Private + Send + Sync + 'static,
        K::Error: std::error::Error + Send + Sync + 'static,
        L: Stream<Item = Result<Self, Self::Error>> + Send + Unpin,
        A: Agent<K> + Send + Sync + 'static,
    {
        let keys = KeyStore(Arc::new(RwLock::new(HashMap::new())));
        let lock = Lock(Arc::new(RwLock::new(CryptoVec::new())));
        while let Some(Ok(stream)) = listener.next().await {
            let mut buf = CryptoVec::new();
            buf.resize(4);
            tokio::spawn(run(
                Connection {
                    lock: lock.clone(),
                    keys: keys.clone(),
                    agent: Some(agent.clone()),
                    revoker: Box::new(Revoke {}),
                    buf: CryptoVec::new(),
                },
                stream,
            ));
        }
        Ok(())
    }
}

#[cfg(not(unix))]
#[async_trait]
impl ServerStream for TcpStream {
    type Error = std::io::Error;

    async fn serve<K, L, A>(_: L, _: A) -> Result<(), Self::Error>
    where
        K: Private + Send + Sync + 'static,
        K::Error: std::error::Error + Send + Sync + 'static,
        L: Stream<Item = Result<Self, Self::Error>> + Send + Unpin,
        A: Agent<K> + Send + Sync + 'static,
    {
        use std::io::{Error, ErrorKind};

        Err(Error::new(
            ErrorKind::Unsupported,
            "non-unix systems are not supported",
        ))
    }
}

async fn run<S, K, A>(mut connection: Connection<K, A>, mut stream: S) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    K: Private + Send + Sync + 'static,
    K::Error: std::error::Error + Send + Sync + 'static,
    A: Agent<K> + Send + 'static,
{
    let mut writebuf = CryptoVec::new();
    loop {
        // Reading the length
        connection.buf.clear();
        connection.buf.resize(4);
        stream.read_exact(&mut connection.buf).await?;
        // Reading the rest of the buffer
        let len = BigEndian::read_u32(&connection.buf) as usize;
        connection.buf.clear();
        connection.buf.resize(len);
        stream.read_exact(&mut connection.buf).await?;
        // respond
        writebuf.clear();
        connection.respond(&mut writebuf).await?;
        stream.write_all(&writebuf).await?;
        stream.flush().await?
    }
}
