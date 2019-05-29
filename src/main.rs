use arrayvec::ArrayVec;
use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::secretbox;
use std::convert::TryInto;

#[derive(structopt::StructOpt)]
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

#[derive(Debug, Clone, Copy)]
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

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
enum Message {
    Command { command: ArrayVec<[u8; 8192]> },
    Output { output: ArrayVec<[u8; 8192]> },
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
        args.password.as_ref().unwrap().as_bytes(),
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
                let (mut connection, addr) = accept_result.unwrap();
                let key2 = key.clone();
                std::thread::spawn(move || {
                    let key = key2;
                    log::info!("Accepted connection from {}", addr);
                    let mut read_buffer = [0u8; 296];
                    let mut read_cursor: usize = 0;
                    let mut parse_buffer: ArrayVec<[u8; 16384]> = ArrayVec::new();
                    loop {
                        let read_result =
                            std::io::Read::read(&mut connection, &mut read_buffer[read_cursor..]);
                        fatal(&read_result, "Failed to read");
                        let read_amount = read_result.unwrap();
                        if read_amount == 0 {
                            log::info!("Disconnected");
                            break;
                        }
                        log::info!("Read {}", read_amount);
                        read_cursor = read_cursor.checked_add(read_amount).unwrap();
                        if read_cursor != 296 {
                            continue;
                        }
                        read_cursor = 0;

                        let nonce = secretbox::Nonce::from_slice(&read_buffer[..24]).unwrap();
                        let tag = secretbox::Tag::from_slice(&read_buffer[24..][256..]).unwrap();
                        secretbox::open_detached(&mut read_buffer[24..][..256], &tag, &nonce, &key)
                            .unwrap();
                        let amt: usize = read_buffer[24].into();

                        parse_buffer.extend(read_buffer[24..][1..][..amt].iter().cloned());
                        loop {
                            let mut cursor = std::io::Cursor::new(&parse_buffer[..]);
                            let parse_result = serde_cbor::from_reader::<Message, _>(&mut cursor);
                            match parse_result {
                                Ok(val) => {
                                    match val {
                                        Message::Command { command } => {
                                            let cmd_str =
                                                std::str::from_utf8(&command[..]).unwrap();
                                            let output = std::process::Command::new("sh")
                                                .arg("-c")
                                                .arg(cmd_str)
                                                .output()
                                                .unwrap();
                                            let mut message_output = ArrayVec::new();
                                            message_output.extend(output.stdout);
                                            let message = Message::Output {
                                                output: message_output,
                                            };
                                            let message = serde_cbor::to_vec(&message).unwrap();
                                            write_framed(&mut connection, &message, &key);
                                        }
                                        _ => {
                                            log::error!("Invalid message: {:?}", val);
                                            std::process::exit(1);
                                        }
                                    }
                                    let consumed: usize = cursor.position().try_into().unwrap();
                                    parse_buffer.drain(0..consumed);
                                }
                                Err(err) => {
                                    log::debug!("CBOR parse error: {:?}", err);
                                    break;
                                }
                            }
                        }
                    }
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
            let mut connection = connection.unwrap();
            let interface = linefeed::Interface::new("oxy");
            fatal(&interface, "Failed to create linefeed interface");
            let interface = interface.unwrap();
            let _ = interface.set_prompt("oxy> ");
            loop {
                match interface.read_line() {
                    Ok(linefeed::ReadResult::Input(input)) => {
                        let mut command = ArrayVec::new();
                        command.extend(input.as_bytes().iter().cloned());
                        let message = Message::Command { command };
                        let message = serde_cbor::to_vec(&message).unwrap();
                        write_framed(&mut connection, &message, &key);
                        fatal(&result, "Failed to write");
                        log::debug!("Message sent successfully.");
                        let mut parse_buffer: ArrayVec<[u8; 16384]> = ArrayVec::new();
                        let mut read_buffer = [0u8; 296];
                        let mut read_cursor = 0;
                        loop {
                            let len = std::io::Read::read(
                                &mut connection,
                                &mut read_buffer[read_cursor..],
                            )
                            .unwrap();
                            if len == 0 {
                                log::debug!("Ran out of buffer space or connection lost.");
                                break;
                            }
                            read_cursor = read_cursor.checked_add(len).unwrap();
                            if read_cursor < 296 {
                                continue;
                            }
                            read_cursor = 0;
                            let nonce = secretbox::Nonce::from_slice(&read_buffer[..24]).unwrap();
                            let tag =
                                secretbox::Tag::from_slice(&read_buffer[24..][256..]).unwrap();
                            secretbox::open_detached(
                                &mut read_buffer[24..][..256],
                                &tag,
                                &nonce,
                                &key,
                            )
                            .unwrap();
                            let amt: usize = read_buffer[24].into();

                            parse_buffer.extend(read_buffer[24..][1..][..amt].iter().cloned());

                            let response = serde_cbor::from_slice(&parse_buffer);
                            if response.is_ok() {
                                let response = response.unwrap();
                                match response {
                                    Message::Output { output } => {
                                        let stdout = std::io::stdout();
                                        let mut stdout_lock = stdout.lock();
                                        std::io::Write::write_all(&mut stdout_lock, &output)
                                            .unwrap();
                                        std::io::Write::flush(&mut stdout_lock).unwrap();
                                    }
                                    _ => panic!("Invalid response"),
                                }
                                break;
                            }
                        }
                    }
                    _ => {
                        break;
                    }
                }
            }
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
