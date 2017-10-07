#[macro_use]
extern crate error_chain;
extern crate ring;

use std::str;

use ring::{digest, hmac, rand, pbkdf2};
use ring::rand::SecureRandom;

error_chain! {
    foreign_links {
        Unspecified(ring::error::Unspecified);
        Utf8Error(std::str::Utf8Error);
    }

}

fn run() -> Result<()> {
    let password = "password";

    // ------------------------------------------------------------------------
    // HMAC
    // ------------------------------------------------------------------------
    // Create salted password
    let rng = rand::SystemRandom::new();
    let mut salt_bytes = [0u8; 64];
    rng.fill(&mut salt_bytes)?;
    let salted_password = [&salt_bytes, password.as_bytes()].concat();
    
    // Create signing key for HMAC
    let signing_key = hmac::SigningKey::generate(&digest::SHA512, &rng)?;
    
    // Hash password using HMAC
    let hash = hmac::sign(&signing_key, &salted_password);
    println!("Hash: {:?}", hash);

    // ------------------------------------------------------------------------
    // PBKF2
    // ------------------------------------------------------------------------
    static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA512;
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    const N_ITER: u32 = 100_000;

    let mut salt = [0u8; CREDENTIAL_LEN];
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
    rng.fill(&mut salt)?;

    // Hash password
    pbkdf2::derive(DIGEST_ALG, N_ITER, &salt, password.as_bytes(),
        &mut pbkdf2_hash);
    println!("PBKDF2 hash: {:?}", String::from_utf8_lossy(&pbkdf2_hash));

    // Attempt to verify the hash
    let res = pbkdf2::verify(DIGEST_ALG, N_ITER, &salt, password.as_bytes(),
        &pbkdf2_hash);
    match res {
        Ok(_) => println!("Verified password!"),
        _ => println!("Failed to verfiy password")
    };
    Ok(())
}

quick_main!(run);
