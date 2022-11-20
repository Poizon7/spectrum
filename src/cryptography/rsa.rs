#![allow(non_snake_case)]

extern crate rand;
use rand::Rng;

// Math functions to do RSA cryptography
fn gcd(e: i128, t: i128, x: &mut i128, y: &mut i128) -> i128 {
    if e == 0 {
        *x = 0;
        *y = 1;
        return t;
    }
    let mut x1 = 0;
    let mut y1 = 0;
    let gcd = gcd(t % e, e, &mut x1, &mut y1);
    *x = y1 - (t / e) * x1;
    *y = x1;
    return gcd;
}

fn EMod(m: u128, e: u128, n: u128) -> u128 {
    let mut c = 1;
    let mut f = 0;
    while f < e {
        f += 1;
        c = (m * c) % n;
    }
    c
}

// Public function to generate key
pub fn GenerateKey() -> (u128, u128, u128) {
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
pub fn Encrypt(m: u128, e: u128, n: u128) -> u128 {
    EMod(m, e, n)
}

pub fn Decrypt(m: u128, d: u128, n: u128) -> u128 {
    EMod(m, d, n)
}
