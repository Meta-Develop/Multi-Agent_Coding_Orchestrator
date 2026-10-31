//! Explicit OpenSSH lifecycle transport. Remote results never grant native authority.
mod client;
mod helper;
mod process;
mod trust;

pub use client::LifecycleSshClient;
pub use helper::maybe_run_helper;
pub use trust::OperatorTrust;

use super::*;
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"MACOLC01";
const MAX_FRAME: u64 = 64 * 1024 * 1024;
const WORK_CHUNK_BYTES: usize = 16 * 1024;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Request {
    Stage(StageTransportRequest),
    Launch(LaunchTransportRequest),
    Status(StatusTransportRequest),
    Wait(WaitTransportRequest),
    Control(ControlTransportRequest),
    Collect(CollectionTransportRequest),
    Cleanup(CleanupTransportRequest),
}

impl Request {
    fn target(&self) -> &SshTargetConfig {
        match self {
            Self::Stage(r) => &r.target,
            Self::Launch(r) => &r.target,
            Self::Status(r) => &r.target,
            Self::Wait(r) => &r.target,
            Self::Control(r) => &r.target,
            Self::Collect(r) => &r.target,
            Self::Cleanup(r) => &r.target,
        }
    }
}

fn check_deadline(deadline: Option<std::time::Instant>) -> Result<()> {
    if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
        bail!("SSH lifecycle operation deadline expired");
    }
    Ok(())
}

struct CappedBuffer {
    bytes: Vec<u8>,
    max: usize,
    deadline: Option<std::time::Instant>,
}

impl Write for CappedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .deadline
            .is_some_and(|d| std::time::Instant::now() >= d)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "serialization deadline expired",
            ));
        }
        if bytes.len() > self.max - self.bytes.len() {
            return Err(std::io::Error::other("lifecycle frame exceeds byte limit"));
        }
        let accepted = bytes.len().min(WORK_CHUNK_BYTES);
        let needed = self.bytes.len() + accepted;
        if needed > self.bytes.capacity() {
            let capacity = needed.max(
                self.bytes
                    .capacity()
                    .saturating_mul(2)
                    .max(1024)
                    .min(self.max),
            );
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(std::io::Error::other)?;
        }
        self.bytes.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_bounded(
    value: &impl Serialize,
    max: u64,
    deadline: Option<std::time::Instant>,
) -> Result<Vec<u8>> {
    let mut writer = CappedBuffer {
        bytes: Vec::new(),
        max: usize::try_from(max.min(MAX_FRAME))?,
        deadline,
    };
    serde_json::to_writer(&mut writer, value)?;
    check_deadline(deadline)?;
    Ok(writer.bytes)
}

fn write_frame(writer: &mut impl Write, value: &impl Serialize, max: u64) -> Result<()> {
    write_frame_until(writer, value, max, None)
}

fn write_frame_until(
    writer: &mut impl Write,
    value: &impl Serialize,
    max: u64,
    deadline: Option<std::time::Instant>,
) -> Result<()> {
    let bytes = serialize_bounded(value, max, deadline)?;
    check_deadline(deadline)?;
    writer.write_all(MAGIC)?;
    writer.write_all(&(bytes.len() as u64).to_be_bytes())?;
    for chunk in bytes.chunks(WORK_CHUNK_BYTES) {
        check_deadline(deadline)?;
        writer.write_all(chunk)?;
    }
    check_deadline(deadline)?;
    writer.flush()?;
    check_deadline(deadline)
}

fn read_frame<T: DeserializeOwned>(reader: &mut impl Read, max: u64) -> Result<T> {
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("invalid lifecycle protocol magic");
    }
    let mut length = [0; 8];
    reader.read_exact(&mut length)?;
    let length = u64::from_be_bytes(length);
    if length > max.min(MAX_FRAME) {
        bail!("lifecycle frame exceeds byte limit");
    }
    let mut bytes = vec![0; usize::try_from(length)?];
    reader.read_exact(&mut bytes)?;
    let mut extra = [0; 1];
    if reader.read(&mut extra)? != 0 {
        bail!("trailing lifecycle frame bytes");
    }
    serde_json::from_slice(&bytes).context("invalid lifecycle payload")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_rejects_oversize_before_reading_payload() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&1025u64.to_be_bytes());
        assert!(read_frame::<serde_json::Value>(&mut bytes.as_slice(), 1024)
            .unwrap_err()
            .to_string()
            .contains("byte limit"));
    }

    #[test]
    fn framing_rejects_wrong_protocol_and_trailing_data() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &serde_json::json!({"candidate":true}), 1024).unwrap();
        assert_eq!(
            read_frame::<serde_json::Value>(&mut bytes.as_slice(), 1024).unwrap()["candidate"],
            true
        );
        bytes.push(b' ');
        assert!(read_frame::<serde_json::Value>(&mut bytes.as_slice(), 1024).is_err());
        bytes[0] = b'!';
        assert!(read_frame::<serde_json::Value>(&mut bytes.as_slice(), 1024).is_err());
    }

    #[test]
    fn wire_scalars_keep_constructor_validation() {
        assert!(serde_json::from_str::<BoundedMillis>("0").is_err());
        assert!(serde_json::from_str::<ProcessSignal>("65").is_err());
        assert!(serde_json::from_str::<BoundedLiteral>(r#""bad\u0000arg""#).is_err());
        assert!(serde_json::from_str::<TypedArgv>("[]").is_err());
    }
}

#[cfg(test)]
mod outgoing_bound_tests {
    use super::*;
    use serde::ser::SerializeSeq;
    use std::cell::Cell;

    struct LongSequence<'a>(&'a Cell<usize>);
    impl Serialize for LongSequence<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut sequence = serializer.serialize_seq(Some(1_000_000))?;
            for _ in 0..1_000_000 {
                self.0.set(self.0.get() + 1);
                sequence.serialize_element(&255u8)?;
            }
            sequence.end()
        }
    }

    #[test]
    fn outgoing_cap_stops_serialization_before_expanding_the_value() {
        let visited = Cell::new(0);
        let mut wire = Vec::new();
        assert!(write_frame(&mut wire, &LongSequence(&visited), 32).is_err());
        assert!(visited.get() < 100);
        assert!(
            wire.is_empty(),
            "do not publish a partial frame on overflow"
        );
    }
}

#[cfg(test)]
mod local_error_tests {
    use super::*;

    #[test]
    fn local_refusal_detail_is_utf8_and_bounded() {
        let error = TransportNotStarted::new("é".repeat(10000));
        let text = error.to_string();
        assert!(text.len() <= 4096 + "SSH transport did not start: ".len());
        assert!(text.ends_with('é'));
    }
}
