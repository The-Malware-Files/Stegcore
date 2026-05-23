// Fuzz target: extract() given arbitrary bytes labelled as PNG.
//
// Exercises the most adversarial user-facing path: "user runs
// stegcore extract on a file someone else sent them". The file may be
// crafted to confuse the meta-JSON parser, the AEAD decryption path,
// the slot permutation, or the multi-pass extraction logic.
//
// extract() may return Err — that is fine. It must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use stegcore_engine::steg;

const PASSPHRASE: &[u8] = b"fuzz-fixed-passphrase";

fuzz_target!(|data: &[u8]| {
    let mut tmp = match tempfile::Builder::new().suffix(".png").tempfile() {
        Ok(t) => t,
        Err(_) => return,
    };
    if tmp.write_all(data).is_err() || tmp.flush().is_err() {
        return;
    }
    let path = match tmp.into_temp_path().keep() {
        Ok(p) => p,
        Err(_) => return,
    };
    let _ = steg::extract(&path, PASSPHRASE);
    let _ = std::fs::remove_file(&path);
});
