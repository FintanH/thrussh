use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use cryptovec::CryptoVec;
use tokio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{AgentClient, Error, ReadResponse};

#[cfg(unix)]
impl AgentClient<tokio::net::UnixStream> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_uds<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Ok(AgentClient {
            stream,
            buf: CryptoVec::new(),
        })
    }

    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_env() -> Result<Self, Error> {
        let var = if let Ok(var) = std::env::var("SSH_AUTH_SOCK") {
            var
        } else {
            return Err(Error::EnvVar("SSH_AUTH_SOCK"));
        };
        match Self::connect_uds(var).await {
            Err(Error::Io(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::BadAuthSock)
            }
            owise => owise,
        }
    }
}

#[cfg(not(unix))]
impl AgentClient<tokio::net::TcpStream> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_env() -> Result<Self, Error> {
        Err(Error::AgentFailure)
    }
}

#[async_trait]
impl<S> ReadResponse for S
where
    S: AsyncRead + AsyncReadExt + AsyncWrite + AsyncWriteExt + Send + Sync + Unpin,
{
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
