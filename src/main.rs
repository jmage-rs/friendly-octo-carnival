mod constants;
mod handle_message;
mod oxy;
mod types;
mod util;

use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::secretbox;

use crate::types::*;
use crate::util::*;

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
                    let connection = mio::net::TcpStream::from_stream(connection).unwrap();
                    let mut oxy = Oxy {
                        recv_buffer,
                        recv_cursor,
                        key,
                        connection,
                        config: args,
                        typedata: TypeData::Server(Default::default()),
                        poll: mio::Poll::new().unwrap(),
                        d: Default::default(),
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
                connection,
                config: args,
                typedata: TypeData::Client(Default::default()),
                poll: mio::Poll::new().unwrap(),
                d: Default::default(),
            };
            oxy.run();
        }
    }
}
