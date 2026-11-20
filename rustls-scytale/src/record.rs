//! What the record encrypters of both protocol versions share: where
//! a record goes.
//!
//! rustls hands an encrypter the buffer its records leave in, and the
//! encrypter appends a whole record to it, header and all.

use alloc::vec::Vec;

use rustls::Error;
use rustls::crypto::cipher::{EncodableVersion, encode_record_header};
use rustls::enums::ContentType;

/// The length of a record's header: its type, its version and the
/// length of what follows.
const HEADER_LEN: usize = 5;

/// Starts a record at the end of `out`: its header, for a payload of
/// `len` bytes once it is protected, and room for that payload.
/// Returns where the payload starts, which the caller fills from
/// there on. What `out` already holds is another record's and is
/// left alone.
pub(crate) fn start(
    out: &mut Vec<u8>,
    typ: ContentType,
    version: EncodableVersion,
    len: usize,
) -> Result<usize, Error> {
    let length = u16::try_from(len).map_err(|_| Error::EncryptError)?;
    out.reserve(HEADER_LEN + len);
    out.extend_from_slice(&encode_record_header(typ, version, length));
    Ok(out.len())
}

/// Takes back a record that [`start`] started and that could not be
/// sealed, so that nothing of it goes out, and says so.
pub(crate) fn abandon(out: &mut Vec<u8>, start: usize) -> Error {
    out.truncate(start.saturating_sub(HEADER_LEN));
    Error::EncryptError
}

#[cfg(test)]
mod tests {
    use rustls::enums::ProtocolVersion;

    use super::*;

    #[test]
    fn a_record_follows_what_is_there_and_can_be_taken_back() {
        let mut out = alloc::vec![0xaa, 0xbb];
        let version = EncodableVersion::Legacy(ProtocolVersion::TLSv1_3);
        let at = start(&mut out, ContentType::ApplicationData, version, 3)
            .expect("three bytes fit");
        assert_eq!(at, 2 + HEADER_LEN);
        assert_eq!(out[..2], [0xaa, 0xbb]);
        assert_eq!(out[2], u8::from(ContentType::ApplicationData));
        assert_eq!(out[5..7], [0, 3]);
        out.extend_from_slice(b"abc");
        assert_eq!(abandon(&mut out, at), Error::EncryptError);
        assert_eq!(out, [0xaa, 0xbb]);
    }

    #[test]
    fn a_payload_too_long_for_the_header_is_refused() {
        let mut out = Vec::new();
        let version = EncodableVersion::Legacy(ProtocolVersion::TLSv1_3);
        let typ = ContentType::ApplicationData;
        let result = start(&mut out, typ, version, 1 << 16);
        assert_eq!(result, Err(Error::EncryptError));
        assert!(out.is_empty());
    }
}
