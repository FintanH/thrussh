use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use cryptovec::CryptoVec;
use futures::stream::{Stream, StreamExt};
use std;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;

use super::{revoke_key, Agent, Connection, Error, KeyStore, Lock, Revoker, Serve};
use crate::key::Private;

pub struct Revoke {}

impl<K> Revoker<K> for Revoke
where
    K: Send + Sync + 'static,
{
    fn revoke(&self, blob: Vec<u8>, keys: KeyStore<K>, now: SystemTime, duration: Duration) {
        tokio::spawn(async move {
            sleep(duration).await;
            revoke_key(keys, blob, now)
        });
    }
}

#[async_trait]
impl<S> Serve for S
where
    S: AsyncRead + AsyncWrite + Sized + Send + Sync + Unpin + 'static,
{
    type Error = std::io::Error;

    async fn serve<K, L, A>(listener: L, agent: A) -> Result<(), Error>
    where
        K: Private + Send + Sync + 'static,
        K::Error: std::error::Error + Send + Sync + 'static,
        L: Stream<Item = Result<Self, Self::Error>> + Send + Unpin,
        A: Agent<K> + Send + Sync + 'static,
    {
        serve(listener, agent).await
    }
}

pub async fn serve<K, S, L, A>(mut listener: L, agent: A) -> Result<(), Error>
where
    K: Private + Send + Sync + 'static,
    K::Error: std::error::Error + Send + Sync + 'static,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    L: Stream<Item = tokio::io::Result<S>> + Unpin,
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
