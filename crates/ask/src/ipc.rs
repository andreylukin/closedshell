use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

pub struct IpcClient {
    socket_path: String,
}

impl IpcClient {
    pub fn from_env() -> anyhow::Result<Self> {
        let socket_path = std::env::var("CLOSEDSHELL_SOCKET").map_err(|_| {
            anyhow::anyhow!("not running inside closedshell (CLOSEDSHELL_SOCKET not set)")
        })?;
        Ok(Self { socket_path })
    }

    pub fn send(&self, request: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| anyhow::anyhow!("cannot connect to closedshell daemon"))?;
        let mut req_str = serde_json::to_string(request)?;
        req_str.push('\n');
        stream.write_all(req_str.as_bytes())?;
        stream.flush()?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        Ok(serde_json::from_str(&response)?)
    }
}
