extern crate rand;
use rand::Rng;

use crate::math::{exponential_modulus, gcd};

pub struct RSA {
    pub n: u128,
    pub e: u128,
    d: u128
}

impl Default for RSA {
    fn default() -> Self {
        RSA::new()
    }
}

impl RSA {
    pub fn new() -> Self {
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

        let e: u128 = 65537;
        let mut x = 0;
        let mut y = 0;
        gcd(e as i128, t as i128, &mut x, &mut y);
        let d: u128 = (t as i128 + x) as u128;

        RSA {
            n,
            e,
            d
        }
    }

    pub fn from_num(n: u128, e: u128, d: u128) -> Self {
        RSA {
            n,
            e,
            d
        }
    }
}

impl RSA {
    pub fn encrypt(&self, message: Vec<u8>) -> Vec<u128> {
        let mut cipher: Vec<u128> = Vec::new();

        for m in message {
            cipher.push(exponential_modulus(m as u128, self.e, self.n));
        }

        cipher
    }

    pub fn decrypt(&self, cipher: Vec<u128>) -> Vec<u8> {
        let mut message: Vec<u8> = Vec::new();

        for c in cipher {
            message.push(exponential_modulus(c, self.d, self.n) as u8);
        }

        message
    }
}

// impl CryptographicAlgorithm for RSA {
//     fn encrypt(&self, message: &[u8]) -> Vec<u8> {
//         let message = u8_to_u128(message);
//         let temp: Vec<u128> = Vec::new();
//         let cipher: Vec<u8> = Vec::new();
//
//         for m in message {
//             exponential_modulus(m, self.e, self.n);
//         }
//
//         cipher
//     }
//
//     fn decrypt(&self, cipher: &[u8]) -> Vec<u8> {
//         exponential_modulus(m, d, n)
//     }
// }
//
// fn u8_to_u128(bytes: &[u8]) -> Vec<u128> {
//     let mut num: Vec<u128> = Vec::new();
//     let mut temp: Vec<u8> = Vec::new();
//
//     for byte in bytes {
//         if byte != &0 {
//             temp.push(*byte);
//         } else {
//             let n: u128 = 0;
//             let mult = 1;
//
//             for byte in temp {
//                 n += (byte * mult) as u128;
//                 mult *= u8::MAX;
//             }
//
//             num.push(n);
//         }
//     }
//
//     num
// }
