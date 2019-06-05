mod constants;
mod handle_message;
mod oxy;
#[cfg(test)]
mod tests;
mod types;
mod util;

use crate::types::*;
use crate::util::*;

fn main() {
    let result = sodiumoxide::init();
    fatal(&result, "Failed to initialize sodumoxide");
    env_logger::init();
    let args = <Config as structopt::StructOpt>::from_args();
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
                let args2 = args.clone();
                std::thread::spawn(move || {
                    let args = args2;
                    log::info!("Accepted connection from {}", addr);
                    let connection = mio::net::TcpStream::from_stream(connection).unwrap();
                    let mut oxy = Oxy::new(connection, args);
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
            let mut oxy = Oxy::new(connection, args);
            oxy.run();
        }
    }
}
