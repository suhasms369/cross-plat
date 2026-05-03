use thiserror::Error;

#[derive(Error, Debug)]
pub enum MeshError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("Config: {0}")]
    Config(String),

    #[error("Crypto: {0}")]
    Crypto(String),

    #[error("Auth failed: {0}")]
    Auth(String),

    #[error("No route: {0}")]
    NoRoute(String),

    #[error("Serialization: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML: {0}")]
    Toml(String),

    #[error("Peer disconnected: {0}")]
    PeerDisconnected(String),

    #[error("Input: {0}")]
    Input(String),

    #[error("Replay detected: seq {0} ≤ last {1}")]
    Replay(u64, u64),
}

pub type Result<T> = std::result::Result<T, MeshError>;
