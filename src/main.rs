use arrayvec::ArrayVec;
use std::convert::TryInto;

#[derive(structopt::StructOpt)]
struct Config {
    #[structopt(long = "mode")]
    mode: Mode,
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

fn main() {
    let result = sodiumoxide::init();
    fatal(&result, "Failed to initialize sodumoxide");
    env_logger::init();
    let args = <Config as structopt::StructOpt>::from_args();
    match &args.mode {
        Mode::Server => {
            let listener = std::net::TcpListener::bind("127.0.0.1:2600");
            fatal(&listener, "Failed to bind");
            let listener = listener.unwrap();
            let accept_result = listener.accept();
            fatal(&accept_result, "Failed to accept");
            let (mut connection, addr) = accept_result.unwrap();
            log::info!("Accepted connection from {}", addr);
            let mut read_buffer = [0u8; 1024];
            let mut parse_buffer: ArrayVec<[u8; 16384]> = ArrayVec::new();
            loop {
                let read_result = std::io::Read::read(&mut connection, &mut read_buffer);
                fatal(&read_result, "Failed to read");
                let read_amount = read_result.unwrap();
                if read_amount == 0 {
                    log::info!("Disconnected");
                    break;
                }
                log::info!("Read {}", read_amount);
                parse_buffer.extend(read_buffer[..read_amount].iter().cloned());
                loop {
                    let mut cursor = std::io::Cursor::new(&parse_buffer[..]);
                    let parse_result = serde_cbor::from_reader::<Message, _>(&mut cursor);
                    match parse_result {
                        Ok(val) => {
                            match val {
                                Message::Command { command } => {
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
                                    };
                                    serde_cbor::to_writer(&mut connection, &message).unwrap();
                                    std::io::Write::flush(&mut connection).unwrap();
                                    log::debug!("Response sent.");
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
        }
        Mode::Client => {
            let connection = std::net::TcpStream::connect("127.0.0.1:2600");
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
                        let result = serde_cbor::to_writer(&mut connection, &message);
                        fatal(&result, "Failed to write");
                        log::debug!("Message sent successfully.");
                        let mut read_len = 0;
                        let mut read_buffer = [0u8; std::mem::size_of::<Message>()];
                        loop {
                            let len =
                                std::io::Read::read(&mut connection, &mut read_buffer[read_len..])
                                    .unwrap();
                            if len == 0 {
                                log::debug!("Ran out of buffer space or connection lost.");
                                break;
                            }
                            read_len = read_len.checked_add(len).unwrap();
                            let response = serde_cbor::from_slice(&read_buffer[..read_len]);
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
