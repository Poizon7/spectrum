extern crate rand;
use rand::Rng;

use crate::math::{exponential_modulus, gcd};

// Public function to generate key
pub fn generate_key() -> (u128, u128, u128) {
    let primes: [u128; 2] = [
        834546085180674575058629332681,
        107338188804765057603465338413,
    ];
    let p = primes[rand::thread_rng().gen_range(0..primes.len())];
    let mut q;
    loop {
        q = primes[rand::thread_rng().gen_range(0..primes.len())];
        if q != p {
            break;
        }
    }
    let n = p * q;
    let t = (p - 1) * (q - 1);

    let e = 65537;
    let mut x = 0;
    let mut y = 0;
    gcd(e, t as i128, &mut x, &mut y);
    let d = t as i128 + x;
    (n as u128, e as u128, d as u128)
}

// Public function to encrypt/decrypt
pub fn encrypt(m: u128, e: u128, n: u128) -> u128 {
    exponential_modulus(m, e, n)
}

pub fn decrypt(m: u128, d: u128, n: u128) -> u128 {
    exponential_modulus(m, d, n)
}
