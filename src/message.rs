use arrayvec::{ArrayString, ArrayVec};

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub enum Message {
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
}

#[derive(PartialEq, serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub enum PortFwdDirection {
    RemoteBind,
    LocalBind,
}
