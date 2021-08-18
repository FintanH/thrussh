use super::msg;
use super::Constraint;
use crate::key::{Private, Public, Signature};
use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use cryptovec::CryptoVec;
use std::fmt;
use thiserror::Error;
use thrussh_encoding::{Encoding, Reader};

#[cfg(feature = "tokio-agent")]
pub mod tokio;

#[derive(Debug, Error)]
pub enum Error {
    /// Agent protocol error
    #[error("Agent protocol error")]
    AgentProtocolError,

    #[error("Agent failure")]
    AgentFailure,

    #[error(
        "Unable to connect to ssh-agent. The environment variable `SSH_AUTH_SOCK` \
    was set, but it points to a nonexistent file or directory."
    )]
    BadAuthSock,

    #[error(transparent)]
    Encoding(#[from] thrussh_encoding::Error),

    #[error("Environment variable `{0}` not found")]
    EnvVar(&'static str),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Private(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Public(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Signature(Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// SSH agent client.
pub struct AgentClient<S> {
    stream: S,
    buf: CryptoVec,
}

// https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.1
impl<S: Unpin> AgentClient<S> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub fn connect(stream: S) -> Self {
        AgentClient {
            stream,
            buf: CryptoVec::new(),
        }
    }
}

#[async_trait]
pub trait ReadResponse: Send + Sync {
    async fn read_response(&mut self, buf: &mut CryptoVec) -> Result<(), Error>;
}

impl<S: ReadResponse + Unpin> AgentClient<S> {
    /// Send a key to the agent, with a (possibly empty) slice of
    /// constraints to apply when using the key to sign.
    pub async fn add_identity<K>(
        &mut self,
        key: &K,
        constraints: &[Constraint],
    ) -> Result<(), Error>
    where
        K: Private,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        self.buf.clear();
        self.buf.resize(4);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_IDENTITY)
        } else {
            self.buf.push(msg::ADD_ID_CONSTRAINED)
        }
        key.write(&mut self.buf)
            .map_err(|err| Error::Private(Box::new(err)))?;
        if !constraints.is_empty() {
            self.buf.push_u32_be(constraints.len() as u32);
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        self.buf.push(msg::CONSTRAIN_LIFETIME);
                        self.buf.push_u32_be(seconds)
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions {
                        ref name,
                        ref details,
                    } => {
                        self.buf.push(msg::CONSTRAIN_EXTENSION);
                        self.buf.extend_ssh_string(name);
                        self.buf.extend_ssh_string(details);
                    }
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.stream.read_response(&mut self.buf).await?;
        Ok(())
    }

    /// Add a smart card to the agent, with a (possibly empty) set of
    /// constraints to apply when signing.
    pub async fn add_smartcard_key(
        &mut self,
        id: &str,
        pin: &[u8],
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_SMARTCARD_KEY)
        } else {
            self.buf.push(msg::ADD_SMARTCARD_KEY_CONSTRAINED)
        }
        self.buf.extend_ssh_string(id.as_bytes());
        self.buf.extend_ssh_string(pin);
        if !constraints.is_empty() {
            self.buf.push_u32_be(constraints.len() as u32);
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        self.buf.push(msg::CONSTRAIN_LIFETIME);
                        self.buf.push_u32_be(seconds)
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions {
                        ref name,
                        ref details,
                    } => {
                        self.buf.push(msg::CONSTRAIN_EXTENSION);
                        self.buf.extend_ssh_string(name);
                        self.buf.extend_ssh_string(details);
                    }
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.stream.read_response(&mut self.buf).await?;
        Ok(())
    }

    /// Lock the agent, making it refuse to sign until unlocked.
    pub async fn lock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::LOCK);
        self.buf.extend_ssh_string(passphrase);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.stream.read_response(&mut self.buf).await?;
        Ok(())
    }

    /// Unlock the agent, allowing it to sign again.
    pub async fn unlock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::UNLOCK);
        self.buf.extend_ssh_string(passphrase);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.stream.read_response(&mut self.buf).await?;
        Ok(())
    }

    /// Ask the agent for a list of the currently registered secret
    /// keys.
    pub async fn request_identities<K>(&mut self) -> Result<Vec<K>, Error>
    where
        K: Public,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REQUEST_IDENTITIES);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);

        self.stream.read_response(&mut self.buf).await?;
        debug!("identities: {:?}", &self.buf[..]);
        let mut keys = Vec::new();
        if self.buf[0] == msg::IDENTITIES_ANSWER {
            let mut r = self.buf.reader(1);
            let n = r.read_u32()?;
            for _ in 0..n {
                let key = r.read_string()?;
                let _ = r.read_string()?;
                let mut r = key.reader(0);
                if let Some(pk) = K::read(&mut r).map_err(|err| Error::Public(Box::new(err)))? {
                    keys.push(pk);
                }
            }
        }

        Ok(keys)
    }

    /// Ask the agent to sign the supplied piece of data.
    pub fn sign_request<K>(
        mut self,
        public: &K,
        mut data: CryptoVec,
    ) -> impl futures::Future<Output = (Self, Result<CryptoVec, Error>)>
    where
        K: Public + fmt::Debug,
    {
        debug!("sign_request: {:?}", data);
        let hash = self.prepare_sign_request(public, &data);
        async move {
            let resp = self.stream.read_response(&mut self.buf).await;
            debug!("resp = {:?}", &self.buf[..]);
            if let Err(e) = resp {
                return (self, Err(e));
            }

            if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
                let resp = self.write_signature(hash, &mut data);
                if let Err(e) = resp {
                    return (self, Err(e));
                }
                (self, Ok(data))
            } else if self.buf[0] == msg::FAILURE {
                (self, Err(Error::AgentFailure.into()))
            } else {
                debug!("self.buf = {:?}", &self.buf[..]);
                (self, Ok(data))
            }
        }
    }

    fn prepare_sign_request<K>(&mut self, public: &K, data: &[u8]) -> u32
    where
        K: Public + fmt::Debug,
    {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::SIGN_REQUEST);
        public.write_blob(&mut self.buf);
        self.buf.extend_ssh_string(data);
        debug!("public = {:?}", public);
        let hash = public.hash();
        self.buf.push_u32_be(hash);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        hash
    }

    fn write_signature(&self, hash: u32, data: &mut CryptoVec) -> Result<(), Error> {
        let mut r = self.buf.reader(1);
        let mut resp = r.read_string()?.reader(0);
        let t = resp.read_string()?;
        if (hash == 2 && t == b"rsa-sha2-256") || (hash == 4 && t == b"rsa-sha2-512") || hash == 0 {
            let sig = resp.read_string()?;
            data.push_u32_be((t.len() + sig.len() + 8) as u32);
            data.extend_ssh_string(t);
            data.extend_ssh_string(sig);
        }
        Ok(())
    }

    /// Ask the agent to sign the supplied piece of data.
    pub fn sign_request_base64<K>(
        mut self,
        public: &K,
        data: &[u8],
    ) -> impl futures::Future<Output = (Self, Result<String, Error>)>
    where
        K: Public + fmt::Debug,
    {
        debug!("sign_request: {:?}", data);
        self.prepare_sign_request(public, &data);
        async move {
            let resp = self.stream.read_response(&mut self.buf).await;
            if let Err(e) = resp {
                return (self, Err(e));
            }

            if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
                let base64 = data_encoding::BASE64_NOPAD.encode(&self.buf[1..]);
                (self, Ok(base64))
            } else {
                (self, Ok(String::new()))
            }
        }
    }

    /// Ask the agent to sign the supplied piece of data, and return a `Signature`.
    pub fn sign_request_signature<K, Sig>(
        mut self,
        public: &K,
        data: &[u8],
    ) -> impl futures::Future<Output = (Self, Result<Sig, Error>)>
    where
        K: Public + fmt::Debug,
        Sig: Signature,
        Sig::Error: std::error::Error + Send + Sync + 'static,
    {
        debug!("sign_request: {:?}", data);
        self.prepare_sign_request(public, data);

        async move {
            if let Err(e) = self.stream.read_response(&mut self.buf).await {
                return (self, Err(e));
            }
            if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
                let sig = Sig::read(&self.buf).map_err(|err| Error::Signature(Box::new(err)));
                (self, sig)
            } else {
                (self, Err(Error::AgentProtocolError.into()))
            }
        }
    }

    /// Ask the agent to remove a key from its memory.
    pub async fn remove_identity<K>(&mut self, public: &K) -> Result<(), Error>
    where
        K: Public,
    {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_IDENTITY);
        public.write_blob(&mut self.buf);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.stream.read_response(&mut self.buf).await?;
        Ok(())
    }

    /// Ask the agent to remove a smartcard from its memory.
    pub async fn remove_smartcard_key(&mut self, id: &str, pin: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_SMARTCARD_KEY);
        self.buf.extend_ssh_string(id.as_bytes());
        self.buf.extend_ssh_string(pin);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.stream.read_response(&mut self.buf).await?;
        Ok(())
    }

    /// Ask the agent to forget all known keys.
    pub async fn remove_all_identities(&mut self) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_ALL_IDENTITIES);
        BigEndian::write_u32(&mut self.buf[0..], 5);
        self.stream.read_response(&mut self.buf).await?;
        Ok(())
    }

    /// Send a custom message to the agent.
    pub async fn extension(&mut self, typ: &[u8], ext: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::EXTENSION);
        self.buf.extend_ssh_string(typ);
        self.buf.extend_ssh_string(ext);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.stream.read_response(&mut self.buf).await?;
        Ok(())
    }

    /// Ask the agent what extensions about supported extensions.
    pub async fn query_extension(&mut self, typ: &[u8], mut ext: CryptoVec) -> Result<bool, Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::EXTENSION);
        self.buf.extend_ssh_string(typ);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.stream.read_response(&mut self.buf).await?;

        let mut r = self.buf.reader(1);
        ext.extend(r.read_string()?);

        Ok(!self.buf.is_empty() && self.buf[0] == msg::SUCCESS)
    }
}