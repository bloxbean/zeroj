//! ZeroJ CFRG BBS draft-10 provider — full BBS algorithm running inside
//! WebAssembly via zkryptium 0.6.1.
//!
//! ABI: see ADR-0019 §7.
//!
//! Memory model: every response is laid out as
//!     [u32 LE total_payload_len | status_byte | payload_bytes]
//! Status byte is 0 for success, 1 for error. On error, payload is a UTF-8
//! error message. Caller reads the 4-byte length, then reads the status +
//! payload, then frees the buffer with `dealloc(ptr, length + 4)`.
//!
//! Single host import: `env.zeroj_host_getrandom(ptr, len) -> i32` (0 = ok).
//! All other operations are self-contained.

use std::{mem, slice};

use elliptic_curve::hash2curve::ExpandMsg;
use zkryptium::{
    bbsplus::{
        ciphersuites::{BbsCiphersuite, Bls12381Sha256, Bls12381Shake256},
        keys::{BBSplusPublicKey, BBSplusSecretKey},
    },
    keys::pair::KeyPair,
    schemes::{
        algorithms::BBSplus,
        generics::{PoKSignature, Signature},
    },
};

// ---------- Host import ---------------------------------------------------

extern "C" {
    fn zeroj_host_getrandom(ptr: *mut u8, len: usize) -> i32;
}

fn host_backed_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    if buf.is_empty() {
        return Ok(());
    }
    let rc = unsafe { zeroj_host_getrandom(buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(getrandom::Error::FAILED_RDRAND)
    }
}
getrandom::register_custom_getrandom!(host_backed_getrandom);

// ---------- Memory primitives ---------------------------------------------

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

#[no_mangle]
pub extern "C" fn zeroj_bbs_version() -> u32 {
    1
}

// ---------- ABI entrypoints ----------------------------------------------

#[no_mangle]
pub extern "C" fn zeroj_bbs_keygen(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, op_keygen)
}

#[no_mangle]
pub extern "C" fn zeroj_bbs_sk_to_pk(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, op_sk_to_pk)
}

#[no_mangle]
pub extern "C" fn zeroj_bbs_sign(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, op_sign)
}

#[no_mangle]
pub extern "C" fn zeroj_bbs_verify(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, op_verify)
}

#[no_mangle]
pub extern "C" fn zeroj_bbs_proof_gen(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, op_proof_gen)
}

#[no_mangle]
pub extern "C" fn zeroj_bbs_proof_verify(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, op_proof_verify)
}

// ---------- Framing -------------------------------------------------------

fn handle<F>(ptr: *const u8, len: usize, op: F) -> *mut u8
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
{
    if ptr.is_null() {
        return respond(Err("request pointer is null".into()));
    }
    let input = unsafe { slice::from_raw_parts(ptr, len) };
    respond(op(input))
}

fn respond(result: Result<Vec<u8>, String>) -> *mut u8 {
    let mut payload = Vec::new();
    match result {
        Ok(bytes) => {
            payload.push(0);
            payload.extend_from_slice(&bytes);
        }
        Err(message) => {
            payload.push(1);
            payload.extend_from_slice(message.as_bytes());
        }
    }
    leak_response(payload)
}

fn leak_response(payload: Vec<u8>) -> *mut u8 {
    let len = payload.len();
    let mut buf = Vec::with_capacity(len + 4);
    buf.extend_from_slice(&(len as u32).to_le_bytes());
    buf.extend_from_slice(&payload);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    ptr
}

// ---------- Ciphersuite dispatch ------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Suite {
    Sha256,
    Shake256,
}

fn read_suite(input: &[u8]) -> Result<(Suite, &[u8]), String> {
    if input.is_empty() {
        return Err("request is empty (expected ciphersuite byte)".into());
    }
    let suite = match input[0] {
        0 => Suite::Sha256,
        1 => Suite::Shake256,
        other => return Err(format!("unknown ciphersuite byte: {other}")),
    };
    Ok((suite, &input[1..]))
}

macro_rules! with_suite {
    ($suite:expr, $body:ident, $input:expr) => {
        match $suite {
            Suite::Sha256 => $body::<Bls12381Sha256>($input),
            Suite::Shake256 => $body::<Bls12381Shake256>($input),
        }
    };
}

// ---------- Request decoder helpers ---------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.off
    }

    fn need(&self, n: usize, label: &str) -> Result<(), String> {
        if self.remaining() < n {
            Err(format!(
                "{label}: need {n} bytes, only {} remaining",
                self.remaining()
            ))
        } else {
            Ok(())
        }
    }

    fn take(&mut self, n: usize, label: &str) -> Result<&'a [u8], String> {
        self.need(n, label)?;
        let out = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(out)
    }

    fn u32_le(&mut self, label: &str) -> Result<u32, String> {
        let bytes = self.take(4, label)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn var_bytes(&mut self, label: &str) -> Result<&'a [u8], String> {
        let len = self.u32_le(&format!("{label} length"))? as usize;
        self.take(len, label)
    }

    fn message_list(&mut self) -> Result<Vec<Vec<u8>>, String> {
        let count = self.u32_le("message count")? as usize;
        if count > 1024 {
            return Err(format!("message count {count} exceeds cap 1024"));
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let msg = self.var_bytes(&format!("message[{i}]"))?;
            out.push(msg.to_vec());
        }
        Ok(out)
    }

    fn index_list(&mut self) -> Result<Vec<usize>, String> {
        let count = self.u32_le("disclosed index count")? as usize;
        if count > 1024 {
            return Err(format!("disclosed index count {count} exceeds cap 1024"));
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let idx = self.u32_le(&format!("disclosed_index[{i}]"))? as usize;
            out.push(idx);
        }
        Ok(out)
    }

    fn expect_eof(&self, label: &str) -> Result<(), String> {
        if self.remaining() != 0 {
            return Err(format!(
                "{label}: {} unexpected trailing bytes",
                self.remaining()
            ));
        }
        Ok(())
    }
}

fn read_sk(bytes: &[u8]) -> Result<BBSplusSecretKey, String> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "secret key must be 32 bytes".to_string())?;
    BBSplusSecretKey::from_bytes(&arr).map_err(err)
}

fn read_pk(bytes: &[u8]) -> Result<BBSplusPublicKey, String> {
    let arr: [u8; 96] = bytes
        .try_into()
        .map_err(|_| "public key must be 96 bytes".to_string())?;
    BBSplusPublicKey::from_bytes(&arr).map_err(err)
}

fn header_opt<'a>(bytes: &'a [u8]) -> Option<&'a [u8]> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

fn messages_opt<'a>(messages: &'a [Vec<u8>]) -> Option<&'a [Vec<u8>]> {
    if messages.is_empty() {
        None
    } else {
        Some(messages)
    }
}

fn indexes_opt<'a>(idx: &'a [usize]) -> Option<&'a [usize]> {
    if idx.is_empty() {
        None
    } else {
        Some(idx)
    }
}

// ---------- KeyGen --------------------------------------------------------

fn op_keygen(input: &[u8]) -> Result<Vec<u8>, String> {
    let (suite, rest) = read_suite(input)?;
    with_suite!(suite, keygen_typed, rest)
}

fn keygen_typed<CS>(input: &[u8]) -> Result<Vec<u8>, String>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let mut c = Cursor::new(input);
    let key_material = c.var_bytes("key_material")?.to_vec();
    let key_info_bytes = c.var_bytes("key_info")?.to_vec();
    c.expect_eof("keygen request")?;
    let key_info = header_opt(&key_info_bytes);
    let kp = KeyPair::<BBSplus<CS>>::generate(&key_material, key_info, None).map_err(err)?;
    Ok(kp.private_key().to_bytes().to_vec())
}

// ---------- SkToPk --------------------------------------------------------

fn op_sk_to_pk(input: &[u8]) -> Result<Vec<u8>, String> {
    let (suite, rest) = read_suite(input)?;
    with_suite!(suite, sk_to_pk_typed, rest)
}

fn sk_to_pk_typed<CS>(input: &[u8]) -> Result<Vec<u8>, String>
where
    CS: BbsCiphersuite,
{
    let mut c = Cursor::new(input);
    let sk = read_sk(c.take(32, "secret key")?)?;
    c.expect_eof("sk_to_pk request")?;
    let pk = sk.public_key();
    Ok(pk.to_bytes().to_vec())
}

// ---------- Sign / Verify -------------------------------------------------

fn op_sign(input: &[u8]) -> Result<Vec<u8>, String> {
    let (suite, rest) = read_suite(input)?;
    with_suite!(suite, sign_typed, rest)
}

fn sign_typed<CS>(input: &[u8]) -> Result<Vec<u8>, String>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let mut c = Cursor::new(input);
    let sk = read_sk(c.take(32, "secret key")?)?;
    let pk = read_pk(c.take(96, "public key")?)?;
    let header = c.var_bytes("header")?.to_vec();
    let messages = c.message_list()?;
    c.expect_eof("sign request")?;
    let sig = Signature::<BBSplus<CS>>::sign(
        messages_opt(&messages),
        &sk,
        &pk,
        header_opt(&header),
    )
    .map_err(err)?;
    Ok(sig.to_bytes().to_vec())
}

fn op_verify(input: &[u8]) -> Result<Vec<u8>, String> {
    let (suite, rest) = read_suite(input)?;
    with_suite!(suite, verify_typed, rest)
}

fn verify_typed<CS>(input: &[u8]) -> Result<Vec<u8>, String>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let mut c = Cursor::new(input);
    let pk = read_pk(c.take(96, "public key")?)?;
    let sig_bytes = c.take(80, "signature")?.to_vec();
    let header = c.var_bytes("header")?.to_vec();
    let messages = c.message_list()?;
    c.expect_eof("verify request")?;
    let sig_arr: &[u8; 80] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature must be 80 bytes".to_string())?;
    let sig = Signature::<BBSplus<CS>>::from_bytes(sig_arr).map_err(err)?;
    let ok = sig
        .verify(&pk, messages_opt(&messages), header_opt(&header))
        .is_ok();
    Ok(vec![if ok { 1 } else { 0 }])
}

// ---------- ProofGen / ProofVerify ----------------------------------------

fn op_proof_gen(input: &[u8]) -> Result<Vec<u8>, String> {
    let (suite, rest) = read_suite(input)?;
    with_suite!(suite, proof_gen_typed, rest)
}

fn proof_gen_typed<CS>(input: &[u8]) -> Result<Vec<u8>, String>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let mut c = Cursor::new(input);
    let pk = read_pk(c.take(96, "public key")?)?;
    let sig_bytes = c.take(80, "signature")?.to_vec();
    let header = c.var_bytes("header")?.to_vec();
    let ph = c.var_bytes("presentation header")?.to_vec();
    let messages = c.message_list()?;
    let disclosed = c.index_list()?;
    c.expect_eof("proof_gen request")?;
    let proof = PoKSignature::<BBSplus<CS>>::proof_gen(
        &pk,
        &sig_bytes,
        header_opt(&header),
        header_opt(&ph),
        messages_opt(&messages),
        indexes_opt(&disclosed),
    )
    .map_err(err)?;
    Ok(proof.to_bytes())
}

fn op_proof_verify(input: &[u8]) -> Result<Vec<u8>, String> {
    let (suite, rest) = read_suite(input)?;
    with_suite!(suite, proof_verify_typed, rest)
}

fn proof_verify_typed<CS>(input: &[u8]) -> Result<Vec<u8>, String>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let mut c = Cursor::new(input);
    let pk = read_pk(c.take(96, "public key")?)?;
    let proof_bytes = c.var_bytes("proof")?.to_vec();
    let header = c.var_bytes("header")?.to_vec();
    let ph = c.var_bytes("presentation header")?.to_vec();
    let disclosed_messages = c.message_list()?;
    let disclosed_indexes = c.index_list()?;
    c.expect_eof("proof_verify request")?;
    let proof = PoKSignature::<BBSplus<CS>>::from_bytes(&proof_bytes).map_err(err)?;
    let ok = proof
        .proof_verify(
            &pk,
            messages_opt(&disclosed_messages),
            indexes_opt(&disclosed_indexes),
            header_opt(&header),
            header_opt(&ph),
        )
        .is_ok();
    Ok(vec![if ok { 1 } else { 0 }])
}

// ---------- Error mapping -------------------------------------------------

fn err<E: core::fmt::Debug>(e: E) -> String {
    format!("{e:?}")
}
