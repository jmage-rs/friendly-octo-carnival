use arrayvec::ArrayVec;

use crate::constants::*;
use crate::types::*;
use crate::util::*;

impl Oxy {
    pub(crate) fn handle_message(&mut self, message: &Message, message_number: u64) {
        match message {
            Message::Command { command } => match &self.config.mode {
                Mode::Server => {
                    let cmd_str = std::str::from_utf8(&command[..]).unwrap();
                    let output = std::process::Command::new("sh")
                        .arg("-c")
                        .arg(cmd_str)
                        .output()
                        .unwrap();
                    let mut message_output = ArrayVec::new();
                    message_output.extend(output.stdout);
                    let message = Message::Output {
                        output: message_output,
                        reference: message_number,
                    };
                    let message = serde_cbor::to_vec(&message).unwrap();
                    write_framed(&mut self.connection, &message, &self.key);
                }
                Mode::Client => {
                    log::warn!("Server tried to get client to execute command.");
                }
            },
            Message::Output {
                output,
                reference: _,
            } => match &self.config.mode {
                Mode::Client => {
                    let mut writer = self
                        .typedata
                        .client()
                        .linefeed_interface
                        .as_ref()
                        .unwrap()
                        .lock_writer_erase()
                        .unwrap();
                    let str_output = std::str::from_utf8(output).unwrap_or("[unprintable output]");
                    writer.write_str(str_output).unwrap();
                    if *output.iter().last().unwrap_or(&0) != b'\n' {
                        writer.write_str("\n").unwrap();
                    }
                }
                Mode::Server => {
                    log::warn!("Client sent server command output");
                }
            },
            Message::PortFwdBind { addr } => match &self.config.mode {
                Mode::Server => {
                    let listener = mio::net::TcpListener::bind(&addr);
                    if listener.is_err() {
                        self.reject(message_number, "failed to bind");
                        return;
                    }
                    let listener = listener.unwrap();
                    let token = self.d.portfwd_bind_token_ticker;
                    let mio_token = mio::Token(CATEGORY_PORTFWD_BIND | usize::from(token));
                    self.poll
                        .register(
                            &listener,
                            mio_token,
                            mio::Ready::readable(),
                            mio::PollOpt::edge(),
                        )
                        .unwrap();
                    self.d.portfwd_bind_token_ticker = token.checked_add(1).unwrap();
                    let result = self
                        .typedata
                        .server_mut()
                        .portfwd_binds
                        .try_push(PortFwdBind {
                            listener,
                            reference: message_number,
                            token: token,
                        });
                    if result.is_err() {
                        self.reject(message_number, "too many binds");
                        return;
                    }
                }
                Mode::Client => {
                    log::warn!("Server sent BindRequest to client.");
                }
            },
            Message::Reject { message, reference } => {
                log::trace!("Recieved rejection for {}: {:?}", reference, message);
            }
            Message::PortFwdConnect { reference } => match &self.config.mode {
                Mode::Client => {
                    let data = self
                        .typedata
                        .client()
                        .remote_portfwd_binds
                        .iter()
                        .filter(|x| x.reference == *reference)
                        .next();
                    if data.is_none() {
                        log::warn!("PortFwdConnect for unknown portfwd.");
                        return;
                    }
                    let data = data.unwrap();
                    let dest = std::net::ToSocketAddrs::to_socket_addrs(data.lspec.as_str());
                    if dest.is_err() {
                        log::warn!("Failed to resolve lspec {:?}", data.lspec);
                        self.reject(message_number, "");
                        return;
                    }
                    let mut dest = dest.unwrap();
                    let dest = dest.next();
                    if dest.is_none() {
                        log::warn!("Resolved lspec to no addresses {:?}", data.lspec);
                        self.reject(message_number, "");
                        return;
                    }
                    if self.d.portfwd_connects.is_full() {
                        log::warn!("Too many portfwd connections");
                        self.reject(message_number, "");
                        return;
                    }
                    let socket = mio::net::TcpStream::connect(&dest.unwrap());
                    if socket.is_err() {
                        log::warn!("Error on portfwd connect: {:?}", socket);
                        self.reject(message_number, "");
                        return;
                    }
                    let socket = socket.unwrap();
                    let token = self.d.portfwd_connect_token_ticker;
                    self.d.portfwd_connect_token_ticker = token.checked_add(1).unwrap();
                    let mio_token = mio::Token(CATEGORY_PORTFWD_CONNECT | usize::from(token));
                    self.poll
                        .register(
                            &socket,
                            mio_token,
                            mio::Ready::readable(),
                            mio::PollOpt::edge(),
                        )
                        .unwrap();
                    self.d.portfwd_connects.push(PortFwdConnect {
                        connection: socket,
                        reference: message_number,
                        token,
                    });
                }
                Mode::Server => {
                    log::warn!("Server sent PortFwdConnect");
                }
            },
            Message::PortFwdData {
                reference,
                direction,
                data,
            } => {
                log::trace!("Searching for reference {}", reference);
                match (&self.config.mode, direction) {
                    (Mode::Server, PortFwdDirection::RemoteBind) => {
                        let connection_data = self
                            .d
                            .portfwd_accepts
                            .iter_mut()
                            .find(|x| x.reference == *reference)
                            .unwrap();
                        std::io::Write::write_all(&mut connection_data.connection, &data).unwrap();
                    }
                    (Mode::Client, PortFwdDirection::RemoteBind) => {
                        let connection_data = self
                            .d
                            .portfwd_connects
                            .iter_mut()
                            .find(|x| x.reference == *reference)
                            .unwrap();
                        std::io::Write::write_all(&mut connection_data.connection, &data).unwrap();
                    }
                    (Mode::Server, PortFwdDirection::LocalBind) => {
                        let connection_data = self
                            .d
                            .portfwd_connects
                            .iter_mut()
                            .find(|x| x.reference == *reference)
                            .unwrap();
                        std::io::Write::write_all(&mut connection_data.connection, &data).unwrap();
                    }
                    (Mode::Client, PortFwdDirection::LocalBind) => {
                        let connection_data = self
                            .d
                            .portfwd_accepts
                            .iter_mut()
                            .find(|x| x.reference == *reference)
                            .unwrap();
                        std::io::Write::write_all(&mut connection_data.connection, &data).unwrap();
                    }
                };
            }
            Message::TunnelConnect { spec } => match &self.config.mode {
                Mode::Server => {
                    let connection = mio::net::TcpStream::connect(
                        &std::net::ToSocketAddrs::to_socket_addrs(spec.as_str())
                            .unwrap()
                            .next()
                            .unwrap(),
                    )
                    .unwrap();
                    let token = self.d.portfwd_connect_token_ticker;
                    self.d.portfwd_connect_token_ticker = token.checked_add(1).unwrap();
                    let mio_token = mio::Token(CATEGORY_PORTFWD_CONNECT | usize::from(token));
                    self.poll
                        .register(
                            &connection,
                            mio_token,
                            mio::Ready::readable(),
                            mio::PollOpt::edge(),
                        )
                        .unwrap();
                    self.d.portfwd_connects.push(PortFwdConnect {
                        connection,
                        reference: message_number,
                        token,
                    });
                }
                Mode::Client => {
                    log::warn!("Server sent TunnelConnect");
                }
            },
        }
    }
}
