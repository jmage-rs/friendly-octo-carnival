pub mod message;

use arrayvec::{ArrayString, ArrayVec};
use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::secretbox;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

use crate::message::{Message, PortFwdDirection};

#[derive(structopt::StructOpt, Clone)]
struct Config {
    #[structopt(long = "mode")]
    mode: Mode,
    #[structopt(long = "bind-addr")]
    bind_addr: Option<std::net::SocketAddr>,
    #[structopt(long = "destination")]
    destination: Option<String>,
    #[structopt(long = "password")]
    password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Server,
    Client,
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

fn fatal<T, E>(result: &Result<T, E>, msg: &str)
where
    E: std::fmt::Debug,
{
    match result {
        Err(err) => {
            log::error!("{}: {:?}", msg, err);
            std::process::exit(1);
        }
        _ => (),
    }
}

fn write_framed(w: &mut impl std::io::Write, message: &[u8], key: &secretbox::Key) {
    let mut framer = MessageFramer::frame(&message);
    while let Some(frame) = framer.next() {
        let mut write_buffer = [0u8; 296];
        let nonce = secretbox::gen_nonce();
        write_buffer[..24].copy_from_slice(&nonce.0);
        write_buffer[24..][..256].copy_from_slice(&frame[..256]);
        let tag = secretbox::seal_detached(&mut write_buffer[24..][..256], &nonce, &key);
        write_buffer[24..][256..].copy_from_slice(&tag.0);
        std::io::Write::write_all(w, &write_buffer).unwrap();
    }
}

const CONNECTION_TOKEN: mio::Token = mio::Token(0);
const READLINE_TOKEN: mio::Token = mio::Token(1);
const CATEGORY_BASE: usize = 0x00000000;
#[deny(overflowing_literals)]
const CATEGORY_PORTFWD_BIND: usize = 0x01000000;
const CATEGORY_PORTFWD_ACCEPT: usize = 0x02000000;
const CATEGORY_PORTFWD_CONNECT: usize = 0x03000000;

struct Oxy {
    connection: mio::net::TcpStream,
    recv_buffer: [u8; 296],
    recv_cursor: usize,
    message_buffer: ArrayVec<[u8; 16384]>,
    config: Config,
    key: secretbox::Key,
    done: bool,
    readline_rx: Option<std::sync::mpsc::Receiver<String>>,
    outbound_message_ticker: u64,
    inbound_message_ticker: u64,
    typedata: TypeData,
    poll: mio::Poll,
}

enum TypeData {
    Server(ServerData),
    Client(ClientData),
}

impl TypeData {
    fn server(&self) -> &ServerData {
        match self {
            TypeData::Server(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    fn server_mut(&mut self) -> &mut ServerData {
        match self {
            TypeData::Server(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    fn client(&self) -> &ClientData {
        match self {
            TypeData::Client(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    fn client_mut(&mut self) -> &mut ClientData {
        match self {
            TypeData::Client(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }
}

#[derive(Default)]
struct ServerData {
    portfwd_binds: ArrayVec<[PortFwdBind; 10]>,
    portfwd_accepts: ArrayVec<[PortFwdAccept; 10]>,
    portfwd_connects: ArrayVec<[PortFwdConnect; 10]>,
    portfwd_connect_token_ticker: u16,
    portfwd_accept_token_ticker: u16,
    portfwd_bind_token_ticker: u16,
}

struct PortFwdBind {
    listener: mio::net::TcpListener,
    reference: u64,
    token: u16,
}

struct PortFwdAccept {
    connection: mio::net::TcpStream,
    reference: u64,
    token: u16,
}

type PortFwdConnect = PortFwdAccept;

#[derive(Default)]
struct ClientData {
    linefeed_interface: Option<Arc<linefeed::Interface<linefeed::terminal::DefaultTerminal>>>,
    remote_portfwd_binds: ArrayVec<[RemotePortFwdBind; 10]>,
    portfwd_connects: ArrayVec<[PortFwdConnect; 10]>,
    portfwd_connect_token_ticker: u16,
}

struct RemotePortFwdBind {
    reference: u64,
    lspec: ArrayString<[u8; 256]>,
    rspec: std::net::SocketAddr,
}

enum RecvConnectionResult {
    Full,
    WouldBlock,
    KeepGoing,
    Disconnected,
}

impl Oxy {
    fn recv_connection_single(&mut self) -> std::io::Result<RecvConnectionResult> {
        debug_assert!(self.recv_buffer[self.recv_cursor..].len() != 0);
        let result = std::io::Read::read(
            &mut self.connection,
            &mut self.recv_buffer[self.recv_cursor..],
        );
        match result {
            Ok(amt) => {
                log::info!("Read {}", amt);
                if amt == 0 {
                    log::info!("Disconnected");
                    return Ok(RecvConnectionResult::Disconnected);
                }
                self.recv_cursor = self.recv_cursor.checked_add(amt).unwrap();
                if self.recv_cursor > 296 {
                    panic!("That shouldn't happen");
                } else if self.recv_cursor == 296 {
                    return Ok(RecvConnectionResult::Full);
                } else {
                    return Ok(RecvConnectionResult::KeepGoing);
                }
            }
            Err(err) => {
                let kind = err.kind();
                if kind == std::io::ErrorKind::WouldBlock {
                    return Ok(RecvConnectionResult::WouldBlock);
                }
                return Err(err);
            }
        }
    }

    fn recv_connection_multi(&mut self) -> std::io::Result<RecvConnectionResult> {
        loop {
            let result = self.recv_connection_single();
            match result {
                Ok(RecvConnectionResult::KeepGoing) => {
                    continue;
                }
                result => {
                    return result;
                }
            }
        }
    }

    fn consume_connection_frame(&mut self) {
        self.decrypt_message_frame();
        self.try_parse_message();
    }

    fn decrypt_message_frame(&mut self) {
        let nonce = secretbox::Nonce::from_slice(&self.recv_buffer[..24]).unwrap();
        let tag = secretbox::Tag::from_slice(&self.recv_buffer[24..][256..]).unwrap();
        secretbox::open_detached(&mut self.recv_buffer[24..][..256], &tag, &nonce, &self.key)
            .unwrap();
        let amt: usize = self.recv_buffer[24].into();

        self.message_buffer
            .extend(self.recv_buffer[24..][1..][..amt].iter().cloned());
        self.recv_cursor = 0;
    }

    fn try_parse_message(&mut self) {
        let mut cursor = std::io::Cursor::new(&self.message_buffer[..]);
        let parse_result = serde_cbor::from_reader::<Message, _>(&mut cursor);
        match parse_result {
            Ok(val) => {
                let consumed: usize = cursor.position().try_into().unwrap();
                self.message_buffer.drain(0..consumed);
                let message_id = self.inbound_message_ticker;
                self.inbound_message_ticker = self.inbound_message_ticker.checked_add(1).unwrap();
                self.handle_message(&val, message_id);
            }
            Err(err) => {
                log::debug!("CBOR parse error: {:?}", err);
            }
        }
    }

    fn handle_message(&mut self, message: &Message, message_number: u64) {
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
                    let token = self.typedata.server().portfwd_bind_token_ticker;
                    let mio_token = mio::Token(CATEGORY_PORTFWD_BIND | usize::from(token));
                    self.poll
                        .register(
                            &listener,
                            mio_token,
                            mio::Ready::readable(),
                            mio::PollOpt::edge(),
                        )
                        .unwrap();
                    self.typedata.server_mut().portfwd_bind_token_ticker =
                        token.checked_add(1).unwrap();
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
                    if self.typedata.client().portfwd_connects.is_full() {
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
                    let token = self.typedata.client().portfwd_connect_token_ticker;
                    self.typedata.client_mut().portfwd_connect_token_ticker =
                        token.checked_add(1).unwrap();
                    let mio_token = mio::Token(CATEGORY_PORTFWD_CONNECT | usize::from(token));
                    self.poll
                        .register(
                            &socket,
                            mio_token,
                            mio::Ready::readable(),
                            mio::PollOpt::edge(),
                        )
                        .unwrap();
                    self.typedata
                        .client_mut()
                        .portfwd_connects
                        .push(PortFwdConnect {
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
                assert!(direction == &PortFwdDirection::RemoteBind);
                assert!(self.config.mode == Mode::Server);
                let connection_data = self
                    .typedata
                    .server_mut()
                    .portfwd_accepts
                    .iter_mut()
                    .filter(|x| x.reference == *reference)
                    .next()
                    .unwrap();
                std::io::Write::write_all(&mut connection_data.connection, &data).unwrap();
            }
        }
    }

    fn reject(&mut self, reference: u64, message: &str) {
        self.send_message(&Message::Reject {
            reference,
            message: ArrayString::from(message).unwrap(),
        });
    }

    fn pump_connection(&mut self) {
        loop {
            match self.recv_connection_multi() {
                Ok(RecvConnectionResult::Full) => {
                    self.consume_connection_frame();
                }
                Ok(RecvConnectionResult::WouldBlock) => {
                    break;
                }
                Ok(RecvConnectionResult::KeepGoing) => {
                    unreachable!();
                }
                Ok(RecvConnectionResult::Disconnected) => {
                    self.done = true;
                    break;
                }
                Err(err) => {
                    log::warn!("Connection read error: {:?}", err);
                    break;
                }
            }
        }
    }

    fn handle_event(&mut self, event: mio::Event) {
        let category = event.token().0 & 0xFF000000;
        match category {
            CATEGORY_BASE => match event.token() {
                CONNECTION_TOKEN => {
                    self.pump_connection();
                }
                READLINE_TOKEN => {
                    while let Ok(input) = self.readline_rx.as_ref().unwrap().try_recv() {
                        if input.chars().nth(0).unwrap_or('\0') != '!' {
                            let mut command = ArrayVec::new();
                            command.extend(input.as_bytes().iter().cloned());
                            let message = Message::Command { command };
                            self.send_message(&message);
                        } else {
                            if input.starts_with("!R ") {
                                let spec = input.split(" ").nth(1);
                                if spec.is_none() {
                                    log::warn!("No spec!");
                                    continue;
                                }
                                let spec = spec.unwrap();
                                let input_lspec = spec.splitn(2, ":").nth(1);
                                if input_lspec.is_none() {
                                    log::warn!("No lspec");
                                    continue;
                                }
                                let input_lspec = input_lspec.unwrap();
                                let rport = spec.split(":").nth(0).unwrap_or("\0").parse();
                                if rport.is_err() {
                                    log::warn!("Invalid port.");
                                }
                                let rport: u16 = rport.unwrap();
                                let rspec = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                                    "127.0.0.1".parse().unwrap(),
                                    rport,
                                ));
                                if self.typedata.client().remote_portfwd_binds.is_full() {
                                    log::warn!("Too many remote binds");
                                    continue;
                                }
                                let message = Message::PortFwdBind { addr: rspec };
                                let reference = self.send_message(&message);
                                let mut lspec = ArrayString::default();
                                lspec.push_str(input_lspec);
                                self.typedata.client_mut().remote_portfwd_binds.push(
                                    RemotePortFwdBind {
                                        rspec,
                                        reference,
                                        lspec,
                                    },
                                );
                            }
                        }
                    }
                }
                _ => {
                    log::warn!("Event for unknown token: {:?}", event);
                }
            },
            CATEGORY_PORTFWD_BIND => {
                let token = u16::try_from(event.token().0 & 0xFFFF).unwrap();
                loop {
                    let portfwd_bind = self
                        .typedata
                        .server_mut()
                        .portfwd_binds
                        .iter_mut()
                        .filter(|x| x.token == token)
                        .next()
                        .unwrap();
                    let reference = portfwd_bind.reference;
                    use std::io::ErrorKind::WouldBlock;
                    let result = portfwd_bind.listener.accept();
                    match result {
                        Ok((peer, addr)) => {
                            log::debug!("Accepting portfwd bind connection from {}", addr);
                            if self.typedata.server().portfwd_accepts.is_full() {
                                log::warn!("Portfwd accepts full");
                                break;
                            }
                            let new_reference = self.send_message(&Message::PortFwdConnect {
                                reference: reference,
                            });
                            let token = self.typedata.server().portfwd_accept_token_ticker;
                            self.typedata.server_mut().portfwd_accept_token_ticker =
                                token.checked_add(1).unwrap();
                            let mio_token =
                                mio::Token(CATEGORY_PORTFWD_ACCEPT | usize::from(token));
                            self.poll
                                .register(
                                    &peer,
                                    mio_token,
                                    mio::Ready::readable(),
                                    mio::PollOpt::edge(),
                                )
                                .unwrap();
                            self.typedata
                                .server_mut()
                                .portfwd_accepts
                                .push(PortFwdAccept {
                                    connection: peer,
                                    reference: new_reference,
                                    token: token,
                                });
                        }
                        Err(ref err) if err.kind() == WouldBlock => {
                            break;
                        }
                        Err(err) => {
                            log::warn!("Unknown error while accepting: {:?}", err);
                            break;
                        }
                    }
                }
            }
            CATEGORY_PORTFWD_CONNECT => {
                let token = u16::try_from(event.token().0 & 0xFFFF).unwrap();
                loop {
                    let data = self
                        .typedata
                        .client_mut()
                        .portfwd_connects
                        .iter_mut()
                        .filter(|x| x.token == token)
                        .next();
                    if data.is_none() {
                        log::warn!("Event for missing portfwd connect {:?}", event);
                        return;
                    }
                    let data = data.unwrap();
                    let mut read_buffer = ArrayVec::new();
                    // This doesn't exist?? : read_buffer.resize(0, read_buffer.capacity());
                    // This is totally eligible to just use unsafe { read_buffer.set_len() }, but...
                    for _ in 0..read_buffer.capacity() {
                        read_buffer.push(0);
                    }
                    let result = std::io::Read::read(&mut data.connection, &mut read_buffer);
                    match result {
                        Ok(amt) => {
                            read_buffer.truncate(amt);
                            let message = Message::PortFwdData {
                                reference: data.reference,
                                direction: PortFwdDirection::RemoteBind,
                                data: read_buffer,
                            };
                            self.send_message(&message);
                        }
                        Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(err) => {
                            log::warn!("Unknown portfwd connect read error: {:?}", err);
                            break;
                        }
                    }
                }
            }
            _ => {
                log::warn!("Unknown event category: {:?}", event);
            }
        }
    }

    fn spawn_readline_thread(&mut self) {
        let interface = linefeed::Interface::new("oxy");
        fatal(&interface, "Failed to create linefeed interface");
        let interface = interface.unwrap();
        let _ = interface.set_prompt("oxy> ");
        let interface = Arc::new(interface);
        self.typedata.client_mut().linefeed_interface = Some(interface.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        self.readline_rx = Some(rx);
        let (registration, set_readiness) = mio::Registration::new2();
        self.poll
            .register(
                &registration,
                READLINE_TOKEN,
                mio::Ready::readable(),
                mio::PollOpt::edge(),
            )
            .unwrap();
        std::thread::spawn(move || {
            let _registration = registration; // If we drop it MIO won't deliver events.
            loop {
                match interface.read_line() {
                    Ok(linefeed::ReadResult::Input(input)) => {
                        tx.send(input).unwrap();
                        set_readiness.set_readiness(mio::Ready::readable()).unwrap();
                    }
                    _ => {
                        std::process::exit(0);
                    }
                };
            }
        });
    }

    fn send_message(&mut self, message: &Message) -> u64 {
        let message_id = self.outbound_message_ticker;
        self.outbound_message_ticker = self.outbound_message_ticker.checked_add(1).unwrap();
        let message = serde_cbor::to_vec(&message).unwrap();
        write_framed(&mut self.connection, &message, &self.key);
        log::debug!("Message sent successfully.");
        message_id
    }

    fn run(&mut self) {
        self.poll
            .register(
                &self.connection,
                CONNECTION_TOKEN,
                mio::Ready::readable(),
                mio::PollOpt::edge(),
            )
            .unwrap();
        let mut events = mio::Events::with_capacity(1024);

        if self.config.mode == Mode::Client {
            self.spawn_readline_thread();
        }

        loop {
            self.poll.poll(&mut events, None).unwrap();
            for event in &events {
                self.handle_event(event);
            }
            events.clear();
            if self.done {
                break;
            }
        }
    }
}

fn main() {
    let result = sodiumoxide::init();
    fatal(&result, "Failed to initialize sodumoxide");
    env_logger::init();
    let args = <Config as structopt::StructOpt>::from_args();
    let salt =
        argon2id13::Salt::from_slice(b"i7'\xe0\xf0\xe6\xc0\xb2\xf9V\x1b\xe4\xc8\xb6\x95\x07")
            .unwrap();
    let mut key_buffer = [0u8; 32];
    let key_bytes = argon2id13::derive_key(
        &mut key_buffer[..],
        args.password
            .as_ref()
            .map(|x| x.as_str())
            .unwrap_or("")
            .as_bytes(),
        &salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .unwrap();
    let key = secretbox::Key::from_slice(key_bytes).unwrap();
    match &args.mode {
        Mode::Server => {
            let listener = std::net::TcpListener::bind(
                args.bind_addr
                    .as_ref()
                    .unwrap_or(&"127.0.0.1:2600".parse().unwrap()),
            );
            fatal(&listener, "Failed to bind");
            let listener = listener.unwrap();
            loop {
                let accept_result = listener.accept();
                if accept_result.is_err() {
                    log::error!("Error during accept(): {}", accept_result.unwrap_err());
                    continue;
                }
                let (connection, addr) = accept_result.unwrap();
                let key2 = key.clone();
                let args2 = args.clone();
                std::thread::spawn(move || {
                    let key = key2;
                    let args = args2;
                    log::info!("Accepted connection from {}", addr);
                    let recv_buffer = [0u8; 296];
                    let recv_cursor: usize = 0;
                    let message_buffer: ArrayVec<[u8; 16384]> = ArrayVec::new();
                    let connection = mio::net::TcpStream::from_stream(connection).unwrap();
                    let mut oxy = Oxy {
                        recv_buffer,
                        recv_cursor,
                        key,
                        message_buffer,
                        connection,
                        config: args,
                        done: false,
                        readline_rx: None,
                        inbound_message_ticker: 0,
                        outbound_message_ticker: 0,
                        typedata: TypeData::Server(Default::default()),
                        poll: mio::Poll::new().unwrap(),
                    };
                    oxy.run();
                });
            }
        }
        Mode::Client => {
            let dest = args
                .destination
                .as_ref()
                .map(|x| x.as_str())
                .unwrap_or("127.0.0.1:2600");
            let connection = std::net::TcpStream::connect(dest);
            fatal(&connection, "Failed to connect");
            let connection = connection.unwrap();
            let connection = mio::net::TcpStream::from_stream(connection).unwrap();
            let mut oxy = Oxy {
                recv_buffer: [0u8; 296],
                recv_cursor: 0,
                key,
                message_buffer: ArrayVec::new(),
                connection,
                config: args,
                done: false,
                readline_rx: None,
                inbound_message_ticker: 0,
                outbound_message_ticker: 0,
                typedata: TypeData::Client(Default::default()),
                poll: mio::Poll::new().unwrap(),
            };
            oxy.run();
        }
    }
}

struct MessageFramer<'a> {
    input: &'a [u8],
    working_buffer: [u8; 272],
    offset: usize,
}

impl MessageFramer<'_> {
    fn frame<'a>(input: &'a [u8]) -> MessageFramer<'a> {
        MessageFramer {
            input,
            working_buffer: [0u8; 272],
            offset: 0,
        }
    }
}

impl<'a> MessageFramer<'a> {
    fn next(&mut self) -> Option<&mut [u8]> {
        let remaining = self.input.len().checked_sub(self.offset).unwrap();
        if remaining == 0 {
            return None;
        }
        let amt = remaining.try_into().unwrap_or(255);
        self.working_buffer[0] = amt;
        let amt: usize = amt.into();
        let end = self.offset + amt;
        log::trace!(
            "MessageFramer: Remaining: {}, offset: {}, amt: {}",
            remaining,
            self.offset,
            amt
        );
        self.working_buffer[1..][..amt].copy_from_slice(&self.input[self.offset..end]);
        self.offset = self.offset.checked_add(amt).unwrap();
        Some(&mut self.working_buffer[..])
    }
}

#[cfg(test)]
#[test]
fn message_framer_basic() {
    let a = b"asdf";
    let mut framer = MessageFramer::frame(a);
    let frame = framer.next().unwrap();
    assert_eq!(4, frame[0]);
    assert_eq!(b"asdf"[..], frame[1..5]);
    assert!(framer.next().is_none());

    let mut a = Vec::new();
    for _ in 0..250 {
        a.extend(b"asdf");
    }
    let mut framer = MessageFramer::frame(&a);
    let frame = framer.next().unwrap();
    assert_eq!(255, frame[0]);
    assert_eq!(b'a', frame[1]);
    let frame = framer.next().unwrap();
    assert_eq!(255, frame[0]);
    assert_eq!(b'f', frame[1]);
    let _ = framer.next().unwrap();
    let frame = framer.next().unwrap();
    assert_eq!(235, frame[0]);
    assert!(framer.next().is_none());
}
