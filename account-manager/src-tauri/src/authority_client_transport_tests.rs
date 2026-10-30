use super::*;
use std::cell::Cell;
use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant};

// The peer buffers its reply and closes as soon as the full request arrives.
// Model macOS timeout setters on that closed socket, independently of host OS.
struct ClosingPeer {
    request: Vec<u8>,
    reply: Cursor<Vec<u8>>,
    closed: Cell<bool>,
    read_timeout: Cell<Option<Duration>>,
    write_timeout: Cell<Option<Duration>>,
    other_read_error: Option<io::ErrorKind>,
}

impl ClosingPeer {
    fn new(reply: Vec<u8>) -> Self {
        Self {
            request: Vec::new(),
            reply: Cursor::new(reply),
            closed: Cell::new(false),
            read_timeout: Cell::new(None),
            write_timeout: Cell::new(None),
            other_read_error: None,
        }
    }

    fn set_timeout(
        &self,
        slot: &Cell<Option<Duration>>,
        timeout: Option<Duration>,
    ) -> io::Result<()> {
        if self.closed.get() {
            // Use the Unix EINVAL kind even on Windows, where OS code 22 has
            // a different meaning.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                io::Error::from_raw_os_error(22),
            ));
        }
        slot.set(timeout);
        Ok(())
    }
}

impl AuthorityStream for ClosingPeer {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if self.closed.get() {
            if let Some(kind) = self.other_read_error {
                return Err(io::Error::new(kind, "simulated timeout failure"));
            }
        }
        self.set_timeout(&self.read_timeout, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_timeout(&self.write_timeout, timeout)
    }
}

impl Write for ClosingPeer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(!self.closed.get());
        assert!(self
            .read_timeout
            .get()
            .is_some_and(|value| !value.is_zero()));
        assert!(self
            .write_timeout
            .get()
            .is_some_and(|value| !value.is_zero()));
        self.request.extend_from_slice(bytes);
        if self.request.len() >= 4 {
            let length = u32::from_be_bytes(self.request[..4].try_into().unwrap()) as usize;
            self.closed.set(self.request.len() == 4 + length);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for ClosingPeer {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(self.closed.get());
        self.reply.read(bytes)
    }
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn peer_close_timeout_einval_does_not_discard_framed_reply() {
    for response in [
        json!({"protocolVersion": 1, "requestId": "test", "result": {"selected": false}}),
        json!({"protocolVersion": 1, "requestId": "test", "error": {"code": "busy", "message": "refused"}}),
    ] {
        let body = serde_json::to_vec(&response).unwrap();
        let mut stream = ClosingPeer::new(frame(&body));
        let deadline = Instant::now() + REQUEST_IO_DEADLINE;
        write_framed(&mut stream, b"request", deadline).unwrap();
        assert_eq!(stream.request, frame(b"request"));
        // Both setters would now fail; the already-buffered reply must win.
        for result in [
            stream.set_read_timeout(Some(Duration::from_secs(1))),
            stream.set_write_timeout(Some(Duration::from_secs(1))),
        ] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
        let reply = read_framed(&mut stream, MAX_RESPONSE_BYTES, deadline).unwrap();
        assert_eq!(reply, body);
        let decoded = decode_response(&reply, "test").unwrap();
        if response.get("error").is_some() {
            assert_eq!(decoded.error.unwrap().code, ErrorCode::Busy);
        } else {
            assert_eq!(decoded.result.unwrap(), response["result"]);
        }
    }
}

#[test]
fn peer_close_without_complete_reply_retains_read_failure() {
    for (reply, reason) in [
        (vec![], "read authority response length"),
        (vec![0, 0], "read authority response length"),
        (vec![0, 0, 0, 2, b'{'], "read authority response body"),
    ] {
        let mut stream = ClosingPeer::new(reply);
        let deadline = Instant::now() + REQUEST_IO_DEADLINE;
        write_framed(&mut stream, b"request", deadline).unwrap();
        let error = read_framed(&mut stream, MAX_RESPONSE_BYTES, deadline).unwrap_err();
        assert!(error.to_string().contains(reason), "{error}");
    }
}

#[test]
fn initial_timeout_errors_and_other_refresh_errors_are_not_ignored() {
    let deadline = Instant::now() + REQUEST_IO_DEADLINE;
    let mut stream = ClosingPeer::new(frame(b"reply"));
    stream.closed.set(true);
    let error = write_framed(&mut stream, b"request", deadline).unwrap_err();
    assert!(error.to_string().contains("set authority read timeout"));
    assert!(stream.request.is_empty());

    let mut stream = ClosingPeer::new(frame(b"reply"));
    stream.other_read_error = Some(io::ErrorKind::PermissionDenied);
    write_framed(&mut stream, b"request", deadline).unwrap();
    let error = read_framed(&mut stream, MAX_RESPONSE_BYTES, deadline).unwrap_err();
    assert!(error.to_string().contains("set authority read timeout"));
    assert_eq!(stream.reply.position(), 0);
}

#[test]
fn expired_deadline_refuses_buffered_reply() {
    let mut stream = ClosingPeer::new(frame(b"reply"));
    write_framed(
        &mut stream,
        b"request",
        Instant::now() + REQUEST_IO_DEADLINE,
    )
    .unwrap();
    let error = read_framed(&mut stream, MAX_RESPONSE_BYTES, Instant::now()).unwrap_err();
    assert!(error.to_string().contains("I/O deadline elapsed"));
    assert_eq!(stream.reply.position(), 0);
}
