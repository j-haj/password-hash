#[macro_use]
extern crate error_chain;
extern crate ring;

use std::str;

use ring::{digest, hmac, rand};
use ring::rand::SecureRandom;

error_chain! {
    foreign_links {
        Unspecified(ring::error::Unspecified);
        Utf8Error(std::str::Utf8Error);
    }

}

fn run() -> Result<()> {
    let password = "password";

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

    Ok(())
}

quick_main!(run);
