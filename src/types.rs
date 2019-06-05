use arrayvec::{ArrayString, ArrayVec};
use sodiumoxide::crypto::secretbox;
use std::sync::Arc;

pub struct Oxy {
    pub connection: mio::net::TcpStream,
    pub config: Config,
    pub key: secretbox::Key,
    pub typedata: TypeData,
    pub poll: mio::Poll,
    pub d: OxyDefault,
}

#[derive(Default)]
pub struct OxyDefault {
    pub done: bool,
    pub portfwd_accepts: ArrayVec<[PortFwdAccept; 10]>,
    pub portfwd_connects: ArrayVec<[PortFwdConnect; 10]>,
    pub portfwd_connect_token_ticker: u16,
    pub portfwd_accept_token_ticker: u16,
    pub portfwd_bind_token_ticker: u16,
    pub outbound_message_ticker: u64,
    pub inbound_message_ticker: u64,
    pub outbound_nonce: Option<secretbox::Nonce>,
    pub inbound_nonce: Option<secretbox::Nonce>,
    pub recv_buffer: jcirclebuffer::CircleBuffer<Vec<u8>>,
    pub message_buffer: jcirclebuffer::CircleBuffer<Vec<u8>>,
}

pub enum TypeData {
    Server(ServerData),
    Client(ClientData),
}

impl TypeData {
    #[allow(dead_code)]
    pub fn server(&self) -> &ServerData {
        match self {
            TypeData::Server(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    pub fn server_mut(&mut self) -> &mut ServerData {
        match self {
            TypeData::Server(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    pub fn client(&self) -> &ClientData {
        match self {
            TypeData::Client(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    pub fn client_mut(&mut self) -> &mut ClientData {
        match self {
            TypeData::Client(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }
}

#[derive(Default)]
pub struct ServerData {
    pub portfwd_binds: ArrayVec<[PortFwdBind; 10]>,
}

pub struct PortFwdBind {
    pub listener: mio::net::TcpListener,
    pub reference: u64,
    pub token: u16,
}

pub struct PortFwdAccept {
    pub connection: mio::net::TcpStream,
    pub reference: u64,
    pub token: u16,
}

pub type PortFwdConnect = PortFwdAccept;

#[derive(Default)]
pub struct ClientData {
    pub readline_rx: Option<std::sync::mpsc::Receiver<String>>,
    pub linefeed_interface: Option<Arc<linefeed::Interface<linefeed::terminal::DefaultTerminal>>>,
    pub remote_portfwd_binds: ArrayVec<[RemotePortFwdBind; 10]>,
    pub local_portfwd_binds: ArrayVec<[LocalPortFwdBind; 10]>,
}

pub struct RemotePortFwdBind {
    pub reference: u64,
    pub lspec: ArrayString<[u8; 256]>,
    pub rspec: std::net::SocketAddr,
}

pub struct LocalPortFwdBind {
    pub listener: mio::net::TcpListener,
    pub rspec: ArrayString<[u8; 256]>,
    pub token: u16,
}

pub enum RecvConnectionResult {
    Full,
    WouldBlock,
    KeepGoing,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Server,
    Client,
}

#[derive(structopt::StructOpt, Clone)]
pub struct Config {
    #[structopt(long = "mode")]
    pub mode: Mode,
    #[structopt(long = "bind-addr")]
    pub bind_addr: Option<std::net::SocketAddr>,
    #[structopt(long = "destination")]
    pub destination: Option<String>,
    #[structopt(long = "password")]
    pub password: Option<String>,
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub enum Message {
    NonceUpdate {
        client_send: [u8; 24],
        client_recv: [u8; 24],
    },
    Reject {
        reference: u64,
        message: ArrayString<[u8; 8192]>,
    },
    Command {
        command: ArrayVec<[u8; 8192]>,
    },
    Output {
        reference: u64,
        output: ArrayVec<[u8; 8192]>,
    },
    PortFwdBind {
        addr: std::net::SocketAddr,
    },
    PortFwdConnect {
        reference: u64,
    },
    PortFwdData {
        reference: u64,
        direction: PortFwdDirection,
        data: ArrayVec<[u8; 8192]>,
    },
    TunnelConnect {
        spec: ArrayString<[u8; 8192]>,
    },
}

#[derive(PartialEq, serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub enum PortFwdDirection {
    RemoteBind,
    LocalBind,
}

impl std::str::FromStr for Mode {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "server" => Ok(Mode::Server),
            "client" => Ok(Mode::Client),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown mode",
            )),
        }
    }
}
