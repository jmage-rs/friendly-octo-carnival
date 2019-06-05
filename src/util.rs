use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::secretbox;
use std::convert::TryInto;

pub fn fatal<T, E>(result: &Result<T, E>, msg: &str)
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

pub fn write_framed_explicit(w: &mut impl std::io::Write, message: &[u8], key: &secretbox::Key) {
    let mut framer = MessageFramer::frame(&message);
    while let Some(frame) = framer.next() {
        let mut write_buffer = [0u8; 296];
        let nonce = secretbox::gen_nonce();
        log::trace!("Sending using explicit nonce: {:?}", nonce);
        write_buffer[..24].copy_from_slice(&nonce.0);
        write_buffer[24..][..256].copy_from_slice(&frame[..256]);
        let tag = secretbox::seal_detached(&mut write_buffer[24..][..256], &nonce, &key);
        write_buffer[24..][256..].copy_from_slice(&tag.0);
        std::io::Write::write_all(w, &write_buffer).unwrap();
    }
}

pub fn write_framed(
    w: &mut impl std::io::Write,
    message: &[u8],
    key: &secretbox::Key,
    nonce: &mut secretbox::Nonce,
) {
    let mut framer = MessageFramer::frame(&message);
    while let Some(frame) = framer.next() {
        let mut write_buffer = [0u8; 272];
        write_buffer[..256].copy_from_slice(&frame[..256]);
        let tag = secretbox::seal_detached(&mut write_buffer[..256], &nonce, &key);
        nonce.increment_le_inplace();
        write_buffer[256..].copy_from_slice(&tag.0);
        std::io::Write::write_all(w, &write_buffer).unwrap();
    }
}

pub fn derive_key(password: &[u8]) -> secretbox::Key {
    let salt =
        argon2id13::Salt::from_slice(b"i7'\xe0\xf0\xe6\xc0\xb2\xf9V\x1b\xe4\xc8\xb6\x95\x07")
            .unwrap();
    let mut key_buffer = [0u8; 32];
    let key_bytes = argon2id13::derive_key(
        &mut key_buffer[..],
        password,
        &salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .unwrap();
    secretbox::Key::from_slice(key_bytes).unwrap()
}

pub struct MessageFramer<'a> {
    input: &'a [u8],
    working_buffer: [u8; 272],
    offset: usize,
    done: bool,
}

impl MessageFramer<'_> {
    pub fn frame<'a>(input: &'a [u8]) -> MessageFramer<'a> {
        MessageFramer {
            input,
            working_buffer: [0u8; 272],
            offset: 0,
            done: false,
        }
    }
}

impl<'a> MessageFramer<'a> {
    fn next(&mut self) -> Option<&mut [u8]> {
        if self.done {
            return None;
        }
        let remaining = self.input.len().checked_sub(self.offset).unwrap();
        let amt = remaining.try_into().unwrap_or(255);
        if amt != 255 {
            self.done = true;
        }
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
    let mut a = Vec::new();
    for _ in 0..255 {
        a.push(b'a');
    }
    assert!(a.len() == 255);
    let mut framer = MessageFramer::frame(&a);
    let frame = framer.next().unwrap();
    assert_eq!(255, frame[0]);
    let frame = framer.next().unwrap();
    assert_eq!(0, frame[0]);
    assert!(framer.next().is_none());
}
