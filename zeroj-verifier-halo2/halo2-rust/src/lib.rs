//! ZeroJ Halo2 FFI wrapper — IPA commitment scheme, Pasta curves.
//!
//! Uses zcash/halo2 v0.3 with NO trusted setup (IPA is transparent).

use std::ffi::CString;
use std::os::raw::c_char;

pub mod circuit;
use circuit::MulCircuit;

use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk,
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use rand_core::OsRng;

const OK: i32 = 0;
const ERR: i32 = 1;

#[no_mangle]
pub extern "C" fn zeroj_halo2_setup_and_prove(
    k: u32, a: u64, b: u64,
    result_out: *mut *mut c_char, error_out: *mut *mut c_char,
) -> i32 {
    let r = std::panic::catch_unwind(|| -> Result<String, String> {
        let a_val = Fp::from(a);
        let b_val = Fp::from(b);
        let c_val = a_val * b_val;

        let params: Params<EqAffine> = Params::new(k);
        let empty = MulCircuit::default();
        let circuit = MulCircuit {
            a: halo2_proofs::circuit::Value::known(a_val),
            b: halo2_proofs::circuit::Value::known(b_val),
        };

        let vk = plonk::keygen_vk(&params, &empty).map_err(|e| format!("keygen_vk: {e}"))?;
        let pk = plonk::keygen_pk(&params, vk.clone(), &empty).map_err(|e| format!("keygen_pk: {e}"))?;

        let public_inputs = vec![c_val];

        // Prove
        let mut transcript = Blake2bWrite::<Vec<u8>, EqAffine, _>::init(vec![]);
        plonk::create_proof(&params, &pk, &[circuit], &[&[&public_inputs]], OsRng, &mut transcript)
            .map_err(|e| format!("prove: {e}"))?;
        let proof_bytes = transcript.finalize();

        // Verify sanity
        let verifier = plonk::SingleVerifier::new(&params);
        let mut vt = Blake2bRead::<&[u8], EqAffine, _>::init(&proof_bytes[..]);
        plonk::verify_proof(&params, pk.get_vk(), verifier, &[&[&public_inputs]], &mut vt)
            .map_err(|e| format!("verify: {e}"))?;

        // Serialize
        let mut params_bytes = vec![];
        params.write(&mut params_bytes).map_err(|e| format!("params write: {e}"))?;

        use base64::Engine;
        let eng = base64::engine::general_purpose::STANDARD;

        let result = serde_json::json!({
            "protocol": "halo2", "curve": "pallas", "commitmentScheme": "IPA",
            "trustedSetup": false, "k": k,
            "proof": eng.encode(&proof_bytes), "proofSize": proof_bytes.len(),
            "params": eng.encode(&params_bytes), "paramsSize": params_bytes.len(),
            "publicInputs": [format!("{}", a * b)],
            "witness": { "a": a, "b": b, "c": a * b },
            "verified": true,
        });
        Ok(serde_json::to_string_pretty(&result).unwrap())
    });

    match r {
        Ok(Ok(json)) => { unsafe { *result_out = CString::new(json).unwrap().into_raw(); } OK }
        Ok(Err(e)) => { unsafe { *error_out = CString::new(e).unwrap_or_default().into_raw(); } ERR }
        Err(_) => { unsafe { *error_out = CString::new("panic").unwrap().into_raw(); } ERR }
    }
}

#[no_mangle]
pub extern "C" fn zeroj_halo2_verify(
    params_ptr: *const u8, params_len: u32,
    _vk_ptr: *const u8, _vk_len: u32,
    proof_ptr: *const u8, proof_len: u32,
    public_inputs_json: *const c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    let r = std::panic::catch_unwind(|| -> Result<(), String> {
        let params_bytes = unsafe { std::slice::from_raw_parts(params_ptr, params_len as usize) };
        let proof_bytes = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len as usize) };
        let pi_json = unsafe { std::ffi::CStr::from_ptr(public_inputs_json) }
            .to_str().map_err(|e| format!("UTF-8: {e}"))?;

        let params: Params<EqAffine> = Params::read(&mut &params_bytes[..])
            .map_err(|e| format!("params read: {e}"))?;

        let empty = MulCircuit::default();
        let vk = plonk::keygen_vk(&params, &empty).map_err(|e| format!("keygen_vk: {e}"))?;

        let pi_values: Vec<String> = serde_json::from_str(pi_json)
            .map_err(|e| format!("PI parse: {e}"))?;
        let public_inputs: Vec<Fp> = pi_values.iter()
            .map(|s| Fp::from(s.parse::<u64>()
                .map_err(|e| format!("invalid public input '{}': {}", s, e)).unwrap()))
            .collect();

        let verifier = plonk::SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<&[u8], EqAffine, _>::init(proof_bytes);
        plonk::verify_proof(&params, &vk, verifier, &[&[&public_inputs]], &mut transcript)
            .map_err(|e| format!("verify: {e}"))?;

        Ok(())
    });

    match r {
        Ok(Ok(())) => OK,
        Ok(Err(e)) => { unsafe { *error_out = CString::new(e).unwrap_or_default().into_raw(); } ERR }
        Err(_) => { unsafe { *error_out = CString::new("panic").unwrap().into_raw(); } ERR }
    }
}

#[no_mangle]
pub extern "C" fn zeroj_halo2_free(ptr: *mut c_char) {
    if !ptr.is_null() { unsafe { drop(CString::from_raw(ptr)); } }
}

#[no_mangle]
pub extern "C" fn zeroj_halo2_version() -> *mut c_char {
    CString::new("halo2-ipa-0.3-zcash").unwrap().into_raw()
}
