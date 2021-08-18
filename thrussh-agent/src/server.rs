use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use cryptovec::CryptoVec;
use futures::future::Future;
use futures::stream::Stream;
use std;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::SystemTime;
use thiserror::Error;
use thrussh_encoding::{Encoding, Position, Reader};

use super::msg;
use super::Constraint;
use crate::key::Private;

#[cfg(feature = "tokio-agent")]
pub mod tokio;

#[cfg(feature = "smol-agent")]
pub mod smol;

struct KeyStore<Key>(Arc<RwLock<HashMap<Vec<u8>, (Arc<Key>, SystemTime, Vec<Constraint>)>>>);

// NOTE: need to implement this since the derived version will require `Key: Clone` which is unecessary.
impl<Key> Clone for KeyStore<Key> {
    fn clone(&self) -> Self {
        KeyStore(self.0.clone())
    }
}

#[derive(Clone)]
struct Lock(Arc<RwLock<CryptoVec>>);

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Encoding(#[from] thrussh_encoding::Error),

    #[error(transparent)]
    Private(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error),
}

pub trait Agent<Key>: Clone + Send + 'static {
    fn confirm(self, _pk: Arc<Key>) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        Box::new(futures::future::ready((self, true)))
    }
}

/// The main entry point for running a server, where `Self` is the type of stream that the server is backed by.
///
/// The backing implementations provided are:
///   * [`thrussh_agent::server::tokio`]
///   * [`thrussh_agent::server::smol`]
#[async_trait]
pub trait ServerStream
where
    Self: Sized + Send + Sync + Unpin + 'static,
{
    type Error;

    async fn serve<K, L, A>(listener: L, agent: A) -> Result<(), Self::Error>
    where
        K: Private + Send + Sync + 'static,
        K::Error: std::error::Error + Send + Sync + 'static,
        L: Stream<Item = Result<Self, Self::Error>> + Send + Unpin,
        A: Agent<K> + Send + Sync + 'static;
}

/// A helper trait for revoking a key in an asynchronous manner.
///
/// The revoking should be done on a spawned thread, however, since we are avoiding
/// committing to a runtime we use this trait to allow for different `spawn` and `sleep` implementations.
///
/// Any implementation should just be of the form:
/// ```rust
/// spawn(async move { sleep(duration); revoke_key(keys, blob, now) });
/// ```
///
/// Where `revoke_key` is the function defined as [`crate::server::revoke_key`].
trait Revoker<K> {
    fn revoke(&self, keys: KeyStore<K>, blob: Vec<u8>, now: SystemTime, duration: Duration);
}

fn revoke_key<K>(keys: KeyStore<K>, blob: Vec<u8>, now: SystemTime) {
    let mut keys = keys.0.write().unwrap();
    let delete = if let Some(&(_, time, _)) = keys.get(&blob) {
        time == now
    } else {
        false
    };
    if delete {
        keys.remove(&blob);
    }
}

impl<K> Agent<K> for () {
    fn confirm(self, _: Arc<K>) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        Box::new(futures::future::ready((self, true)))
    }
}

struct Connection<Key, A: Agent<Key>> {
    lock: Lock,
    keys: KeyStore<Key>,
    agent: Option<A>,
    revoker: Box<dyn Revoker<Key> + Send + Sync + 'static>,
    buf: CryptoVec,
}

impl<K, A> Connection<K, A>
where
    K: Private + Send + Sync + 'static,
    K::Error: std::error::Error + Send + Sync + 'static,
    A: Agent<K> + Send + 'static,
{
    pub async fn respond(&mut self, writebuf: &mut CryptoVec) -> Result<(), Error> {
        let is_locked = {
            if let Ok(password) = self.lock.0.read() {
                !password.is_empty()
            } else {
                true
            }
        };
        writebuf.extend(&[0, 0, 0, 0]);
        let mut r = self.buf.reader(0);
        match r.read_byte() {
            Ok(11) if !is_locked => {
                // request identities
                if let Ok(keys) = self.keys.0.read() {
                    writebuf.push(msg::IDENTITIES_ANSWER);
                    writebuf.push_u32_be(keys.len() as u32);
                    for (k, _) in keys.iter() {
                        writebuf.extend_ssh_string(k);
                        writebuf.extend_ssh_string(b"");
                    }
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(13) if !is_locked => {
                // sign request
                let agent = self.agent.take().unwrap();
                let (agent, signed) = self.try_sign(agent, r, writebuf).await?;
                self.agent = Some(agent);
                if signed {
                    return Ok(());
                } else {
                    writebuf.resize(4);
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(17) if !is_locked => {
                // add identity
                if let Ok(true) = self.add_key(r, false, writebuf).await {
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(18) if !is_locked => {
                // remove identity
                if let Ok(true) = self.remove_identity(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(19) if !is_locked => {
                // remove all identities
                if let Ok(mut keys) = self.keys.0.write() {
                    keys.clear();
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(22) if !is_locked => {
                // lock
                if let Ok(()) = self.lock(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(23) if is_locked => {
                // unlock
                if let Ok(true) = self.unlock(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(25) if !is_locked => {
                // add identity constrained
                if let Ok(true) = self.add_key(r, true, writebuf).await {
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            _ => {
                // Message not understood
                writebuf.push(msg::FAILURE)
            }
        }
        let len = writebuf.len() - 4;
        BigEndian::write_u32(&mut writebuf[0..], len as u32);
        Ok(())
    }

    fn lock(&self, mut r: Position) -> Result<(), Error> {
        let password = r.read_string()?;
        let mut lock = self.lock.0.write().unwrap();
        lock.extend(password);
        Ok(())
    }

    fn unlock(&self, mut r: Position) -> Result<bool, Error> {
        let password = r.read_string()?;
        let mut lock = self.lock.0.write().unwrap();
        if &lock[0..] == password {
            lock.clear();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_identity(&self, mut r: Position) -> Result<bool, Error> {
        if let Ok(mut keys) = self.keys.0.write() {
            if keys.remove(r.read_string()?).is_some() {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn add_key<'a>(
        &self,
        mut r: Position<'a>,
        constrained: bool,
        writebuf: &mut CryptoVec,
    ) -> Result<bool, Error> {
        let (blob, key) = match K::read(&mut r).map_err(|err| Error::Private(Box::new(err)))? {
            Some((blob, key)) => (blob, key),
            None => return Ok(false),
        };
        writebuf.push(msg::SUCCESS);
        let mut w = self.keys.0.write().unwrap();
        let now = SystemTime::now();
        if constrained {
            let n = r.read_u32()?;
            let mut c = Vec::new();
            for _ in 0..n {
                let t = r.read_byte()?;
                if t == msg::CONSTRAIN_LIFETIME {
                    let seconds = r.read_u32()?;
                    c.push(Constraint::KeyLifetime { seconds });
                    let blob = blob.clone();
                    let keys = self.keys.clone();
                    let duration = Duration::from_secs(seconds as u64);
                    self.revoker.revoke(keys, blob, now, duration);
                } else if t == msg::CONSTRAIN_CONFIRM {
                    c.push(Constraint::Confirm)
                } else {
                    return Ok(false);
                }
            }
            w.insert(blob, (Arc::new(key), now, Vec::new()));
        } else {
            w.insert(blob, (Arc::new(key), now, Vec::new()));
        }
        Ok(true)
    }

    async fn try_sign<'a>(
        &self,
        agent: A,
        mut r: Position<'a>,
        writebuf: &mut CryptoVec,
    ) -> Result<(A, bool), Error> {
        let mut needs_confirm = false;
        let key = {
            let blob = r.read_string()?;
            let k = self.keys.0.read().unwrap();
            if let Some(&(ref key, _, ref constraints)) = k.get(blob) {
                if constraints.iter().any(|c| *c == Constraint::Confirm) {
                    needs_confirm = true;
                }
                key.clone()
            } else {
                return Ok((agent, false));
            }
        };
        let agent = if needs_confirm {
            let (agent, ok) = agent.confirm(key.clone()).await;
            if !ok {
                return Ok((agent, false));
            }
            agent
        } else {
            agent
        };
        writebuf.push(msg::SIGN_RESPONSE);
        let data = r.read_string()?;
        key.write_signature(writebuf, data)
            .map_err(|err| Error::Private(Box::new(err)))?;
        let len = writebuf.len();
        BigEndian::write_u32(writebuf, (len - 4) as u32);

        Ok((agent, true))
    }
}
