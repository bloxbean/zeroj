//! ADR-0061 M2 dalek harness (test only).
//!
//! Subcommands:
//!   verify <cases.json>   for each case {id, n, label, commitmentHex, proofHex}, run
//!                         RangeProof::from_bytes + RangeProof::verify_single with
//!                         PedersenGens::default() and BulletproofGens::new(64, 1);
//!                         print a JSON array {id, verdict: "ok" | "<error>"}.
//!   merlin-vectors        run merlin 3.0.0 on the conformance sequences of merlin.py.
//!   gens                  print PedersenGens::default() (B, B_blinding) and the first
//!                         64 G generators of party 0 (public API only).
//!   prove <n> <value> <seedByte>
//!                         prove_single_with_rng with ChaChaRng::from_seed([seedByte; 32]),
//!                         transcript label b"Deserialize-And-Verify Test"; prints JSON.

use std::env;
use std::fs;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde_json::{json, Value};

fn label_static(s: &str) -> &'static [u8] {
    // verify_single needs a &'static label; the case file names one of a fixed set.
    match s {
        "Deserialize-And-Verify Test" => b"Deserialize-And-Verify Test",
        "ZeroJ-M2-dalek-direction-2" => b"ZeroJ-M2-dalek-direction-2",
        _ => panic!("unknown transcript label {}", s),
    }
}

fn cmd_verify(path: &str) {
    let text = fs::read_to_string(path).expect("read cases");
    let cases: Value = serde_json::from_str(&text).expect("parse cases");
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    let mut out = Vec::new();
    for case in cases.as_array().expect("array") {
        let id = case["id"].as_str().unwrap().to_string();
        let n = case["n"].as_u64().unwrap() as usize;
        let label = label_static(case["label"].as_str().unwrap());
        let v_bytes = hex::decode(case["commitmentHex"].as_str().unwrap()).unwrap();
        let p_bytes = hex::decode(case["proofHex"].as_str().unwrap()).unwrap();
        let verdict = if v_bytes.len() != 32 {
            "commitment length".to_string()
        } else {
            let v = CompressedRistretto::from_slice(&v_bytes).unwrap();
            match RangeProof::from_bytes(&p_bytes) {
                Err(e) => format!("from_bytes: {:?}", e),
                Ok(proof) => {
                    let mut t = Transcript::new(label);
                    match proof.verify_single(&bp_gens, &pc_gens, &mut t, &v, n) {
                        Ok(()) => "ok".to_string(),
                        Err(e) => format!("verify_single: {:?}", e),
                    }
                }
            }
        };
        out.push(json!({"id": id, "verdict": verdict}));
    }
    println!("{}", serde_json::to_string_pretty(&Value::Array(out)).unwrap());
}

struct FixedRng([u8; 32], usize);
impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 { rand_core::impls::next_u32_via_fill(self) }
    fn next_u64(&mut self) -> u64 { rand_core::impls::next_u64_via_fill(self) }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() { *b = self.0[self.1 % 32]; self.1 += 1; }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest); Ok(())
    }
}
impl CryptoRng for FixedRng {}

fn cmd_merlin_vectors() {
    let mut out = serde_json::Map::new();
    {
        let mut t = Transcript::new(b"test protocol");
        t.append_message(b"some label", b"some data");
        let mut c = [0u8; 32];
        t.challenge_bytes(b"challenge", &mut c);
        out.insert("equivalence_simple".into(), json!(hex::encode(c)));
    }
    {
        let mut t = Transcript::new(b"test protocol");
        let data = vec![99u8; 1024];
        t.append_message(b"step1", b"some data");
        let mut chals = Vec::new();
        let mut c = [0u8; 32];
        for _ in 0..32 {
            t.challenge_bytes(b"challenge", &mut c);
            chals.push(json!(hex::encode(c)));
            t.append_message(b"bigdata", &data);
            t.append_message(b"challengedata", &c);
        }
        out.insert("equivalence_complex".into(), Value::Array(chals));
    }
    {
        let mut t = Transcript::new(b"test TranscriptRng collisions");
        t.append_message(b"com", b"commitment data 2");
        let mut seed = [0u8; 32];
        for i in 0..32 { seed[i] = i as u8; }
        let mut rng = t
            .build_rng()
            .rekey_with_witness_bytes(b"witness", b"witness data 2")
            .finalize(&mut FixedRng(seed, 0));
        let mut a = [0u8; 64];
        rng.fill_bytes(&mut a);
        let mut b = [0u8; 7];
        rng.fill_bytes(&mut b);
        out.insert("transcript_rng".into(), json!([hex::encode(a), hex::encode(b)]));
    }
    {
        let mut t = Transcript::new(b"zeroj-m2 merlin long");
        t.append_u64(b"n", 64);
        t.append_message(b"empty", b"");
        let mut c = vec![0u8; 500];
        t.challenge_bytes(b"long", &mut c);
        out.insert("long_challenge".into(), json!(hex::encode(c)));
    }
    println!("{}", serde_json::to_string_pretty(&Value::Object(out)).unwrap());
}

fn cmd_gens() {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(64, 1);
    let g: Vec<Value> = bp.share(0).G(64).map(|p| json!(hex::encode(p.compress().as_bytes()))).collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "B": hex::encode(pc.B.compress().as_bytes()),
            "B_blinding": hex::encode(pc.B_blinding.compress().as_bytes()),
            "G": g,
        }))
        .unwrap()
    );
}

fn cmd_prove(n: usize, value: u64, seed_byte: u8) {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(64, 1);
    let mut rng = ChaChaRng::from_seed([seed_byte; 32]);
    let blinding = Scalar::random(&mut rng);
    let mut t = Transcript::new(b"Deserialize-And-Verify Test");
    let (proof, v) = RangeProof::prove_single_with_rng(&bp, &pc, &mut t, value, &blinding, n, &mut rng)
        .expect("prove");
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "n": n, "value": value, "seedByte": seed_byte,
            "commitmentHex": hex::encode(v.as_bytes()),
            "proofHex": hex::encode(proof.to_bytes()),
        }))
        .unwrap()
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("verify") => cmd_verify(&args[2]),
        Some("merlin-vectors") => cmd_merlin_vectors(),
        Some("gens") => cmd_gens(),
        Some("prove") => cmd_prove(
            args[2].parse().unwrap(),
            args[3].parse().unwrap(),
            args[4].parse().unwrap(),
        ),
        _ => {
            eprintln!("usage: zeroj-dalek-harness verify <cases.json> | merlin-vectors | gens | prove <n> <value> <seedByte>");
            std::process::exit(2);
        }
    }
}
