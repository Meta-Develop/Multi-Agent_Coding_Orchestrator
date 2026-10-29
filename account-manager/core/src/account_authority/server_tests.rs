use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::*;
use crate::account_authority::{resolve_socket_path, StoredAccountRegistry};

#[test]
fn disconnected_peer_preserves_authenticated_buffered_request() {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("peer.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let request =
        br#"{"protocolVersion":1,"requestId":"lost-reply","operation":"authority.describe"}"#;
    let mut client = UnixStream::connect(&path).unwrap();
    client
        .write_all(&(request.len() as u32).to_be_bytes())
        .unwrap();
    client.write_all(request).unwrap();
    drop(client);
    let (mut server, _) = listener.accept().unwrap();

    // Exercise SO_PEERCRED on Linux and getpeereid on BSD/Darwin after close;
    // buffered bytes must never substitute for an authenticated requester.
    let peer = super::super::peer::peer_credentials(server.as_raw_fd()).unwrap();
    assert!(super::super::peer::authorize_peer(
        peer,
        super::super::peer::effective_uid()
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    let received = read_request(&mut server, MAX_REQUEST_BYTES, deadline)
        .unwrap_or_else(|_| panic!("authenticated buffered request was discarded"));
    assert_eq!(received, request);
    assert_eq!(
        read_exact_deadline(&mut server, &mut [0; 1], deadline)
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn partial_request_cannot_extend_io_deadline() {
    let (mut server, mut client) = UnixStream::pair().unwrap();
    client.write_all(b"x").unwrap();
    let deadline = Instant::now() + Duration::from_millis(50);
    let mut body = [0; 2];
    assert_eq!(
        read_exact_deadline(&mut server, &mut body, deadline)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(body[0], b'x');
    assert!(Instant::now() >= deadline);
}

#[test]
fn backpressured_response_cannot_extend_io_deadline() {
    let (mut server, _client) = UnixStream::pair().unwrap();
    server.set_nonblocking(true).unwrap();
    loop {
        match server.write(&[0; 8192]) {
            Ok(written) => assert!(written > 0),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("could not fill response buffer: {error}"),
        }
    }
    let deadline = Instant::now() + Duration::from_millis(50);
    assert_eq!(
        write_all_deadline(&mut server, b"x", deadline)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(Instant::now() >= deadline);
}

#[test]
fn connection_limit_refuses_excess_and_recovers_after_disconnect() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = fs::canonicalize(directory.path()).unwrap();
    let context = AuthorityContext::new(StoredAccountRegistry::new(root.join("accounts.json")))
        .without_registry_fallback();
    let listener = listen(
        resolve_socket_path(root.join("authority.sock")).unwrap(),
        AuthorityServerConfig::new(context).unwrap(),
    )
    .unwrap();
    let mut idle = Vec::new();
    for _ in 0..MAX_ACTIVE_CONNECTIONS {
        idle.push(UnixStream::connect(listener.path()).unwrap());
        listener.accept_once().unwrap();
    }
    assert_eq!(
        listener.active_connections.load(Ordering::Acquire),
        MAX_ACTIVE_CONNECTIONS
    );
    let mut excess = UnixStream::connect(listener.path()).unwrap();
    excess
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    listener.accept_once().unwrap();
    assert_eq!(excess.read(&mut [0; 1]).unwrap(), 0);
    assert_eq!(
        listener.active_connections.load(Ordering::Acquire),
        MAX_ACTIVE_CONNECTIONS
    );

    drop(idle);
    let deadline = Instant::now() + Duration::from_secs(3);
    while listener.active_connections.load(Ordering::Acquire) != 0 {
        assert!(
            Instant::now() < deadline,
            "connection permits were not released"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut recovered = UnixStream::connect(listener.path()).unwrap();
    recovered
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let request = serde_json::to_vec(&serde_json::json!({
        "protocolVersion": 1,
        "requestId": "recovered",
        "operation": "authority.describe",
    }))
    .unwrap();
    recovered
        .write_all(&(request.len() as u32).to_be_bytes())
        .unwrap();
    recovered.write_all(&request).unwrap();
    listener.accept_once().unwrap();
    let mut size = [0; 4];
    recovered.read_exact(&mut size).unwrap();
    let mut response = vec![0; u32::from_be_bytes(size) as usize];
    recovered.read_exact(&mut response).unwrap();
    let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(response["requestId"], "recovered");
    assert!(response["result"]["authorityId"].is_string());
}
