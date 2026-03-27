//! Generates Halo2 test vectors for ZeroJ.
//!
//! Usage: cargo run --bin gentestvectors -- --output <dir>

use std::path::PathBuf;

fn main() {
    let output_dir = std::env::args()
        .skip_while(|a| a != "--output")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    std::fs::create_dir_all(&output_dir).expect("Failed to create output dir");

    println!("=== ZeroJ Halo2 Test Vector Generator ===");
    println!("Circuit: Multiplier (a * b = c)");
    println!("Curve:   BN254 (PSE halo2 fork)");
    println!("Output:  {}", output_dir.display());

    // Call the FFI function to generate artifacts
    let mut result_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut error_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();

    let k = 4u32; // 2^4 = 16 rows
    let a = 3u64;
    let b = 11u64;

    let status = unsafe {
        zeroj_halo2::zeroj_halo2_setup_and_prove(
            k, a, b,
            &mut result_ptr,
            &mut error_ptr,
        )
    };

    if status != 0 {
        let error = if !error_ptr.is_null() {
            unsafe { std::ffi::CStr::from_ptr(error_ptr).to_string_lossy().to_string() }
        } else {
            "Unknown error".to_string()
        };
        eprintln!("ERROR: {error}");
        std::process::exit(1);
    }

    let result_json = unsafe {
        std::ffi::CStr::from_ptr(result_ptr).to_string_lossy().to_string()
    };

    // Write the full result JSON
    let result_path = output_dir.join("halo2_result.json");
    std::fs::write(&result_path, &result_json).expect("Failed to write result");
    println!("Written: {}", result_path.display());

    // Parse and write individual files
    let result: serde_json::Value = serde_json::from_str(&result_json).expect("Invalid JSON");

    // public.json
    let public_inputs = result["publicInputs"].as_array().unwrap();
    let public_json = serde_json::to_string_pretty(public_inputs).unwrap();
    let public_path = output_dir.join("public.json");
    std::fs::write(&public_path, &public_json).expect("Failed to write public.json");
    println!("Written: {} (public inputs: {:?})", public_path.display(), public_inputs);

    // metadata.json
    let metadata = serde_json::json!({
        "circuit": "multiplier",
        "proofSystem": "halo2",
        "curve": "pallas",
        "k": k,
        "witnessA": a,
        "witnessB": b,
        "publicC": a * b,
        "halo2Version": "0.3-zcash",
        "commitmentScheme": "IPA",
        "trustedSetup": false,
        "transcript": "Blake2b",
    });
    let metadata_path = output_dir.join("metadata.json");
    std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata).unwrap())
        .expect("Failed to write metadata.json");
    println!("Written: {}", metadata_path.display());

    println!();
    println!("=== Test vectors generated ===");
    println!("Circuit: {} * {} = {} (verified: {})", a, b, a * b, result["verified"]);
    println!("Proof size: {} bytes", result["proofSize"]);
    println!("Params size: {} bytes", result["paramsSize"]);
    println!("VK size: {} bytes", result["vkSize"]);

    // Cleanup
    unsafe {
        if !result_ptr.is_null() { zeroj_halo2::zeroj_halo2_free(result_ptr); }
        if !error_ptr.is_null() { zeroj_halo2::zeroj_halo2_free(error_ptr); }
    }
}

// Link to the library
extern crate zeroj_halo2;
