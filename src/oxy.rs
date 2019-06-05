use arrayvec::{ArrayString, ArrayVec};
use sodiumoxide::crypto::secretbox;
use std::convert::TryFrom;
use std::sync::Arc;

use crate::constants::*;
use crate::types::*;
use crate::util::*;

impl Oxy {
    pub fn new(connection: mio::net::TcpStream, config: Config) -> Oxy {
        let key = derive_key(
            config
                .password
                .as_ref()
                .map(|x| x.as_str())
                .unwrap_or("")
                .as_bytes(),
        );
        match &config.mode {
            Mode::Client => Oxy {
                key,
                connection,
                config,
                typedata: TypeData::Client(Default::default()),
                poll: mio::Poll::new().unwrap(),
                d: Default::default(),
            },
            Mode::Server => Oxy {
                key,
                connection,
                config,
                typedata: TypeData::Server(Default::default()),
                poll: mio::Poll::new().unwrap(),
                d: Default::default(),
            },
        }
    }

    pub fn recv_connection_single(&mut self) -> std::io::Result<RecvConnectionResult> {
        let buf = self.d.recv_buffer.get_fillable_area();
        if buf.is_none() {
            return Ok(RecvConnectionResult::Full);
        }
        let buf = buf.unwrap();
        let result = std::io::Read::read(&mut self.connection, buf);
        match result {
            Ok(amt) => {
                log::info!("Read {}", amt);
                if amt == 0 {
                    log::info!("Disconnected");
                    return Ok(RecvConnectionResult::Disconnected);
                }
                self.d.recv_buffer.fill(amt);
                if self.d.recv_buffer.is_full() {
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

    pub fn recv_connection_multi(&mut self) -> std::io::Result<RecvConnectionResult> {
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

    pub fn consume_connection_frame(&mut self) {
        if self.decrypt_message_frame() {
            self.try_parse_message();
        }
    }

    pub fn consume_connection_frames(&mut self) {
        loop {
            let frame_size = if self.d.inbound_nonce.is_some() {
                272
            } else {
                296
            };
            if self.d.recv_buffer.len() < frame_size {
                break;
            }
            self.consume_connection_frame();
        }
    }

    pub fn decrypt_message_frame_explicit(
        frame: &mut [u8],
        message_buffer: &mut jcirclebuffer::CircleBuffer<Vec<u8>>,
        key: &secretbox::Key,
    ) -> bool {
        let nonce = secretbox::Nonce::from_slice(&frame[..24]).unwrap();
        log::trace!("Decrypting using explicit nonce: {:?}", nonce);
        let tag = secretbox::Tag::from_slice(&frame[24..][256..]).unwrap();
        let body = &mut frame[24..][..256];
        secretbox::open_detached(body, &tag, &nonce, key).unwrap();
        let amt: usize = body[0].into();
        message_buffer.extend(&body[1..=amt]);
        amt < 255
    }

    pub fn decrypt_message_frame_implicit(
        frame: &mut [u8],
        message_buffer: &mut jcirclebuffer::CircleBuffer<Vec<u8>>,
        key: &secretbox::Key,
        nonce: &secretbox::Nonce,
    ) -> bool {
        let tag = secretbox::Tag::from_slice(&frame[256..]).unwrap();
        let body = &mut frame[..256];
        log::trace!("Decrypting using implicit nonce: {:?}", nonce);
        secretbox::open_detached(body, &tag, &nonce, key).unwrap();
        let amt: usize = body[0].into();
        message_buffer.extend(&body[1..=amt]);
        amt < 255
    }

    pub fn decrypt_message_frame(&mut self) -> bool {
        if self.d.inbound_nonce.is_none() {
            let mut if_discontiguous_buffer = [0u8; 296];
            let message_buffer = &mut self.d.message_buffer;
            let key = &self.key;
            let result = self
                .d
                .recv_buffer
                .view_provided_mut(&mut if_discontiguous_buffer, |frame| {
                    Self::decrypt_message_frame_explicit(frame, message_buffer, key)
                });
            self.d.recv_buffer.consume(296);
            result
        } else {
            let mut if_discontiguous_buffer = [0u8; 272];
            let message_buffer = &mut self.d.message_buffer;
            let key = &self.key;
            let nonce = self.d.inbound_nonce.unwrap();
            let result = self
                .d
                .recv_buffer
                .view_provided_mut(&mut if_discontiguous_buffer, |frame| {
                    Self::decrypt_message_frame_implicit(frame, message_buffer, key, &nonce)
                });
            self.d.recv_buffer.consume(272);
            self.d
                .inbound_nonce
                .as_mut()
                .unwrap()
                .increment_le_inplace();
            result
        }
    }

    pub fn try_parse_message(&mut self) {
        let parse_result = serde_cbor::from_slice::<Message>(&self.d.message_buffer.view_nocopy());
        self.d.message_buffer.consume(self.d.message_buffer.len());
        match parse_result {
            Ok(val) => {
                let message_id = self.d.inbound_message_ticker;
                self.d.inbound_message_ticker =
                    self.d.inbound_message_ticker.checked_add(1).unwrap();
                self.handle_message(&val, message_id);
            }
            Err(err) => {
                log::debug!("CBOR parse error: {:?}", err);
            }
        }
    }

    pub fn reject(&mut self, reference: u64, message: &str) {
        self.send_message(&Message::Reject {
            reference,
            message: ArrayString::from(message).unwrap(),
        });
    }

    pub fn pump_connection(&mut self) {
        loop {
            match self.recv_connection_multi() {
                Ok(RecvConnectionResult::Full) => {
                    self.consume_connection_frames();
                }
                Ok(RecvConnectionResult::WouldBlock) => {
                    self.consume_connection_frames();
                    break;
                }
                Ok(RecvConnectionResult::KeepGoing) => {
                    unreachable!();
                }
                Ok(RecvConnectionResult::Disconnected) => {
                    self.d.done = true;
                    break;
                }
                Err(err) => {
                    log::warn!("Connection read error: {:?}", err);
                    break;
                }
            }
        }
    }

    pub fn handle_input(&mut self, input: &str) {
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
                    return;
                }
                let spec = spec.unwrap();
                let input_lspec = spec.splitn(2, ":").nth(1);
                if input_lspec.is_none() {
                    log::warn!("No lspec");
                    return;
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
                    return;
                }
                let message = Message::PortFwdBind { addr: rspec };
                let reference = self.send_message(&message);
                let mut lspec = ArrayString::default();
                lspec.push_str(input_lspec);
                self.typedata
                    .client_mut()
                    .remote_portfwd_binds
                    .push(RemotePortFwdBind {
                        rspec,
                        reference,
                        lspec,
                    });
            }
        }
        if input.starts_with("!L ") {
            let spec = input.split(" ").nth(1);
            if spec.is_none() {
                log::warn!("No spec!");
                return;
            }
            let spec = spec.unwrap();
            let bind_port: u16 = spec.splitn(2, ":").nth(0).unwrap().parse().unwrap();
            let listener =
                mio::net::TcpListener::bind(&format!("127.0.0.1:{}", bind_port).parse().unwrap())
                    .unwrap();
            let mut rspec = ArrayString::new();
            rspec.push_str(spec.splitn(2, ":").nth(1).unwrap());
            let token = self.d.portfwd_bind_token_ticker;
            self.d.portfwd_bind_token_ticker = token.checked_add(1).unwrap();
            let mio_token = mio::Token(CATEGORY_PORTFWD_BIND | usize::from(token));
            self.poll
                .register(
                    &listener,
                    mio_token,
                    mio::Ready::readable(),
                    mio::PollOpt::edge(),
                )
                .unwrap();
            self.typedata
                .client_mut()
                .local_portfwd_binds
                .push(LocalPortFwdBind {
                    listener,
                    rspec,
                    token,
                });
        }
    }

    pub fn handle_event(&mut self, event: mio::Event) {
        let category = event.token().0 & 0xFF000000;
        match category {
            CATEGORY_BASE => match event.token() {
                CONNECTION_TOKEN => {
                    self.pump_connection();
                }
                READLINE_TOKEN => {
                    while let Ok(input) = self
                        .typedata
                        .client()
                        .readline_rx
                        .as_ref()
                        .unwrap()
                        .try_recv()
                    {
                        self.handle_input(&input);
                    }
                }
                _ => {
                    log::warn!("Event for unknown token: {:?}", event);
                }
            },
            CATEGORY_PORTFWD_BIND => match &self.config.mode {
                Mode::Server => {
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
                                if self.d.portfwd_accepts.is_full() {
                                    log::warn!("Portfwd accepts full");
                                    break;
                                }
                                let new_reference = self.send_message(&Message::PortFwdConnect {
                                    reference: reference,
                                });
                                let token = self.d.portfwd_accept_token_ticker;
                                self.d.portfwd_accept_token_ticker = token.checked_add(1).unwrap();
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
                                self.d.portfwd_accepts.push(PortFwdAccept {
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
                Mode::Client => {
                    let token = u16::try_from(event.token().0 & 0xFFFF).unwrap();
                    loop {
                        let portfwd_bind = self
                            .typedata
                            .client_mut()
                            .local_portfwd_binds
                            .iter_mut()
                            .find(|x| x.token == token)
                            .unwrap();
                        use std::io::ErrorKind::WouldBlock;
                        let result = portfwd_bind.listener.accept();
                        match result {
                            Ok((peer, addr)) => {
                                log::debug!("Accepting portfwd bind connection from {}", addr);
                                let mut spec = ArrayString::new();
                                spec.push_str(&portfwd_bind.rspec);
                                let reference = self.send_message(&Message::TunnelConnect { spec });
                                let token = self.d.portfwd_accept_token_ticker;
                                self.d.portfwd_accept_token_ticker = token.checked_add(1).unwrap();
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
                                self.d.portfwd_accepts.push(PortFwdAccept {
                                    connection: peer,
                                    reference,
                                    token,
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
            },
            CATEGORY_PORTFWD_ACCEPT | CATEGORY_PORTFWD_CONNECT => {
                let token = u16::try_from(event.token().0 & 0xFFFF).unwrap();
                loop {
                    let data = match category {
                        CATEGORY_PORTFWD_ACCEPT => {
                            self.d.portfwd_accepts.iter_mut().find(|x| x.token == token)
                        }
                        CATEGORY_PORTFWD_CONNECT => self
                            .d
                            .portfwd_connects
                            .iter_mut()
                            .find(|x| x.token == token),
                        _ => unreachable!(),
                    };
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
                            if amt == 0 {
                                self.poll.deregister(&data.connection).unwrap();
                                break;
                            }
                            read_buffer.truncate(amt);
                            let message = Message::PortFwdData {
                                reference: data.reference,
                                direction: match (category, &self.config.mode) {
                                    (CATEGORY_PORTFWD_ACCEPT, Mode::Client) => {
                                        PortFwdDirection::LocalBind
                                    }
                                    (CATEGORY_PORTFWD_CONNECT, Mode::Client) => {
                                        PortFwdDirection::RemoteBind
                                    }
                                    (CATEGORY_PORTFWD_ACCEPT, Mode::Server) => {
                                        PortFwdDirection::RemoteBind
                                    }
                                    (CATEGORY_PORTFWD_CONNECT, Mode::Server) => {
                                        PortFwdDirection::LocalBind
                                    }
                                    _ => unreachable!(),
                                },
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

    pub fn spawn_readline_thread(&mut self) {
        let interface = linefeed::Interface::new("oxy");
        fatal(&interface, "Failed to create linefeed interface");
        let interface = interface.unwrap();
        let _ = interface.set_prompt("oxy> ");
        let interface = Arc::new(interface);
        self.typedata.client_mut().linefeed_interface = Some(interface.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        self.typedata.client_mut().readline_rx = Some(rx);
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

    pub fn send_message(&mut self, message: &Message) -> u64 {
        let message_id = self.d.outbound_message_ticker;
        self.d.outbound_message_ticker = self.d.outbound_message_ticker.checked_add(1).unwrap();
        let message = serde_cbor::to_vec(&message).unwrap();
        if let Some(nonce) = &mut self.d.outbound_nonce {
            write_framed(&mut self.connection, &message, &self.key, nonce);
        } else {
            write_framed_explicit(&mut self.connection, &message, &self.key);
        }
        log::debug!("Message sent successfully.");
        message_id
    }

    pub fn run(&mut self) {
        sodiumoxide::init().unwrap();
        self.poll
            .register(
                &self.connection,
                CONNECTION_TOKEN,
                mio::Ready::readable(),
                mio::PollOpt::edge(),
            )
            .unwrap();
        let mut events = mio::Events::with_capacity(1024);

        match &self.config.mode {
            Mode::Client => {
                self.spawn_readline_thread();
            }
            Mode::Server => {
                let client_send = secretbox::gen_nonce();
                let client_recv = secretbox::gen_nonce();
                let message = Message::NonceUpdate {
                    client_send: client_send.0,
                    client_recv: client_recv.0,
                };
                self.send_message(&message);
                self.d.outbound_nonce = Some(client_recv);
                self.d.inbound_nonce = Some(client_send);
            }
        }

        loop {
            self.poll.poll(&mut events, None).unwrap();
            for event in &events {
                self.handle_event(event);
            }
            events.clear();
            if self.d.done {
                break;
            }
        }
    }
}
