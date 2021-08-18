use std::path::Path;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use cryptovec::CryptoVec;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::unix::UnixStream;

#[cfg(not(unix))]
use smol::net::TcpStream;

use super::{AgentClient, ClientStream, Error};

#[cfg(not(unix))]
#[async_trait]
impl ClientStream for TcpStream {
    async fn connect_uds<P>(path: P) -> Result<AgentClient<Self>, Error> {
        Err(Error::AgentFailure)
    }

    async fn read_response(&mut self, buf: &mut CryptoVec) -> Result<(), Error> {
        Err(Error::AgentFailure)
    }

    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    async fn connect_env() -> Result<Self, Error> {
        Err(Error::AgentFailure)
    }
}

#[cfg(unix)]
#[async_trait]
impl ClientStream for UnixStream {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    async fn connect_uds<P>(path: P) -> Result<AgentClient<Self>, Error>
    where
        P: AsRef<Path> + Send,
    {
        let stream = UnixStream::connect(path).await?;
        Ok(AgentClient {
            stream,
            buf: CryptoVec::new(),
        })
    }

    async fn read_response(&mut self, buf: &mut CryptoVec) -> Result<(), Error> {
        // Writing the message
        self.write_all(&buf).await?;
        self.flush().await?;

        // Reading the length
        buf.clear();
        buf.resize(4);
        self.read_exact(buf).await?;

        // Reading the rest of the buffer
        let len = BigEndian::read_u32(&buf) as usize;
        buf.clear();
        buf.resize(len);
        self.read_exact(buf).await?;

        Ok(())
    }
}
