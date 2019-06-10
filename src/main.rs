use oxy::types::*;
use oxy::util::fatal;

fn main() {
    let result = sodiumoxide::init();
    fatal(result, "Failed to initialize sodumoxide");
    env_logger::init();
    let args = <Config as structopt::StructOpt>::from_args();
    match &args.mode {
        Mode::Server => {
            let listener = std::net::TcpListener::bind(
                args.bind_addr
                    .as_ref()
                    .unwrap_or(&"127.0.0.1:2600".parse().unwrap()),
            );
            let listener = fatal(listener, "Failed to bind");
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
            let connection = fatal(connection, "Failed to connect");
            let connection = mio::net::TcpStream::from_stream(connection).unwrap();
            let mut oxy = Oxy::new(connection, args);
            oxy.run();
        }
    }
}
