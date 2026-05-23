// Fuzz target: analyse() given arbitrary bytes labelled as WAV.
// Hits the hound WAV decoder + audio analysis pipeline. Audio decoders
// are historically a rich vein for malformed-input bugs.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use stegcore_engine::analysis;

fuzz_target!(|data: &[u8]| {
    let mut tmp = match tempfile::Builder::new().suffix(".wav").tempfile() {
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
    let _ = analysis::analyse(&path);
    let _ = std::fs::remove_file(&path);
});
