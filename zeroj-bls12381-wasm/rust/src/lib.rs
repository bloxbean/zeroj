use bls12_381::{
    multi_miller_loop, G1Affine, G2Affine, G2Prepared, Gt, Scalar,
};
use std::{mem, slice};

const G1_BYTES: usize = 96;
const G2_BYTES: usize = 192;
const SCALAR_BYTES: usize = 32;

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
pub extern "C" fn zeroj_bls12381_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn zeroj_bls12381_g1_generator() -> *mut u8 {
    respond(Ok(G1Affine::generator().to_uncompressed().to_vec()))
}

#[no_mangle]
pub extern "C" fn zeroj_bls12381_g2_generator() -> *mut u8 {
    respond(Ok(G2Affine::generator().to_uncompressed().to_vec()))
}

#[no_mangle]
pub extern "C" fn zeroj_bls12381_g1_scalar_mul(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, g1_scalar_mul)
}

#[no_mangle]
pub extern "C" fn zeroj_bls12381_g2_scalar_mul(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, g2_scalar_mul)
}

#[no_mangle]
pub extern "C" fn zeroj_bls12381_pairing_check(ptr: *const u8, len: usize) -> *mut u8 {
    handle(ptr, len, pairing_check)
}

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

fn g1_scalar_mul(input: &[u8]) -> Result<Vec<u8>, String> {
    require_len(input, G1_BYTES + SCALAR_BYTES, "G1 scalar multiplication request")?;
    let point = read_g1(&input[..G1_BYTES])?;
    let scalar = read_scalar(&input[G1_BYTES..])?;
    let result = G1Affine::from(&point * &scalar);
    Ok(result.to_uncompressed().to_vec())
}

fn g2_scalar_mul(input: &[u8]) -> Result<Vec<u8>, String> {
    require_len(input, G2_BYTES + SCALAR_BYTES, "G2 scalar multiplication request")?;
    let point = read_g2(&input[..G2_BYTES])?;
    let scalar = read_scalar(&input[G2_BYTES..])?;
    let result = G2Affine::from(&point * &scalar);
    Ok(result.to_uncompressed().to_vec())
}

fn pairing_check(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 4 {
        return Err("pairing check request is too short".into());
    }
    let count = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
    let pair_len = G1_BYTES + G2_BYTES;
    let expected = 4usize
        .checked_add(count.checked_mul(pair_len).ok_or("pairing request is too large")?)
        .ok_or("pairing request is too large")?;
    require_len(input, expected, "pairing check request")?;

    let mut g1_points = Vec::with_capacity(count);
    let mut g2_prepared = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        g1_points.push(read_g1(&input[offset..offset + G1_BYTES])?);
        offset += G1_BYTES;
        let g2 = read_g2(&input[offset..offset + G2_BYTES])?;
        offset += G2_BYTES;
        g2_prepared.push(G2Prepared::from(g2));
    }

    let terms: Vec<_> = g1_points.iter().zip(g2_prepared.iter()).collect();
    let is_identity = multi_miller_loop(&terms).final_exponentiation() == Gt::identity();
    Ok(vec![if is_identity { 1 } else { 0 }])
}

fn read_g1(bytes: &[u8]) -> Result<G1Affine, String> {
    let arr: [u8; G1_BYTES] = bytes.try_into().map_err(|_| "invalid G1 byte length")?;
    let point = G1Affine::from_uncompressed(&arr);
    if bool::from(point.is_some()) {
        Ok(point.unwrap())
    } else {
        Err("invalid G1 point encoding".into())
    }
}

fn read_g2(bytes: &[u8]) -> Result<G2Affine, String> {
    let arr: [u8; G2_BYTES] = bytes.try_into().map_err(|_| "invalid G2 byte length")?;
    let point = G2Affine::from_uncompressed(&arr);
    if bool::from(point.is_some()) {
        Ok(point.unwrap())
    } else {
        Err("invalid G2 point encoding".into())
    }
}

fn read_scalar(bytes: &[u8]) -> Result<Scalar, String> {
    let arr: [u8; SCALAR_BYTES] = bytes.try_into().map_err(|_| "invalid scalar byte length")?;
    let scalar = Scalar::from_bytes(&arr);
    if bool::from(scalar.is_some()) {
        Ok(scalar.unwrap())
    } else {
        Err("invalid BLS12-381 scalar encoding".into())
    }
}

fn require_len(input: &[u8], expected: usize, label: &str) -> Result<(), String> {
    if input.len() != expected {
        return Err(format!("{label} must be {expected} bytes, got {}", input.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_pairing_is_not_identity() {
        let g1 = G1Affine::generator();
        let g2 = G2Prepared::from(G2Affine::generator());
        let terms = vec![(&g1, &g2)];
        assert_ne!(multi_miller_loop(&terms).final_exponentiation(), Gt::identity());
    }

    #[test]
    fn generator_plus_neg_generator_pairing_is_identity() {
        let g1 = G1Affine::generator();
        let neg_g1 = -G1Affine::generator();
        let g2 = G2Prepared::from(G2Affine::generator());
        let terms = vec![(&g1, &g2), (&neg_g1, &g2)];
        assert_eq!(multi_miller_loop(&terms).final_exponentiation(), Gt::identity());
    }
}
