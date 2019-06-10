use crate::types::Oxy;
use std::sync::Arc;
use std::sync::Mutex;

fn create_linked_pair() -> (Oxy, Oxy) {
    let bind = std::net::TcpListener::bind("127.0.0.1:61337").unwrap();
    let server_connection_holder = Arc::new(Mutex::new(None));
    let server_connection_holder2 = server_connection_holder.clone();
    std::thread::spawn(move || {
        let (connection, _) = bind.accept().unwrap();
        println!("Connection recieved");
        *server_connection_holder2.lock().unwrap() = Some(connection);
    });
    let client_connection = std::net::TcpStream::connect("127.0.0.1:61337").unwrap();
    while server_connection_holder.lock().unwrap().is_none() {
        std::thread::yield_now();
    }
    let server_connection = server_connection_holder.lock().unwrap().take().unwrap();
    let client_connection = mio::net::TcpStream::from_stream(client_connection).unwrap();
    let server_connection = mio::net::TcpStream::from_stream(server_connection).unwrap();
    let client_config =
        <crate::types::Config as structopt::StructOpt>::from_iter(&["oxy", "--mode=client"]);
    let server_config =
        <crate::types::Config as structopt::StructOpt>::from_iter(&["oxy", "--mode=server"]);
    let server = Oxy::new(server_connection, server_config);
    let client = Oxy::new(client_connection, client_config);
    (server, client)
}

#[test]
fn basic_test() {
    use crate::types::RemoteControlMessage;
    let (mut server, mut client) = create_linked_pair();
    let client_remote_control = client.take_remote_control();
    let server_remote_control = server.take_remote_control();
    let client_mutex_1 = Arc::new(Mutex::new(()));
    let server_mutex_1 = Arc::new(Mutex::new(()));
    let client_mutex_2 = Arc::clone(&client_mutex_1);
    let server_mutex_2 = Arc::clone(&server_mutex_1);
    std::thread::spawn(move || {
        let _x = client_mutex_2.lock();
        server.run();
    });
    std::thread::spawn(move || {
        let _x = server_mutex_2.lock();
        client.run();
    });
    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut metacommand: arrayvec::ArrayString<[u8; 256]> = Default::default();
    metacommand.push_str("ls");
    client_remote_control
        .tx
        .send(RemoteControlMessage::MetaCommand(metacommand))
        .unwrap();
    client_remote_control
        .setreadiness
        .set_readiness(mio::Ready::readable())
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    server_remote_control
        .tx
        .send(RemoteControlMessage::Callback(Box::new(|x| {
            assert!(x.d.outbound_message_ticker >= 1);
        })))
        .unwrap();
    server_remote_control
        .setreadiness
        .set_readiness(mio::Ready::readable())
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!client_mutex_1.is_poisoned());
    assert!(!server_mutex_1.is_poisoned());
}
