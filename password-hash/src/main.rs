#[macro_use]
extern crate error_chain;
extern crate ring;

use ring::{digest, hmac, rand};
use ring::rand::SecureRandom;

error_chain! {
    foreign_links {
        Unspecified(ring::error::Unspecified);
    }

}

fn run() -> Result<()> {
    // Create password
    let password = "password";

    // Create salt
    let rng = rand::SystemRandom::new();
    let mut salt = [0u8; 64];
    rng.fill(&mut salt)?;
    
    // Create signing key for HMAC
    let signing_key = hmac::SigningKey::generate(&digest::SHA512, salt.as_ref())?;
    
    // Hash password using HMAC
    let hash = hmac::sign(&signing_key, password.as_bytes());
    println!("Hash: {:?}", hash);

    // Verify passowrd and hash
    println!("Hello, world!");
    Ok(())
}

quick_main!(run);
