pub mod aes;
pub mod rsa;
pub mod sha;

use crate::format::{hex_to_u8, u8_to_hex};

use std::str;

#[derive(Debug)]
pub enum CryptoError {
    AESError(aes::AESError),
}

pub trait CryptographicAlgorithm {
    fn encrypt(&self, message: &mut [u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, cipher: &mut [u8]) -> Result<Vec<u8>, CryptoError>;
}

pub fn encrypt(
    crypto: &impl CryptographicAlgorithm,
    message: String,
) -> Result<String, CryptoError> {
    let mut message = message.into_bytes();
    println!("{:?}", message);
    let message = message.as_mut_slice();
    let message = crypto.encrypt(message)?;
    println!("{:?}", message);
    Ok(u8_to_hex(message))
}

pub fn decrypt(
    crypto: &impl CryptographicAlgorithm,
    cipher: String,
) -> Result<String, CryptoError> {
    let mut cipher = hex_to_u8(&cipher);
    println!("{:?}", cipher);
    let cipher = cipher.as_mut_slice();
    let cipher = crypto.decrypt(cipher)?;
    println!("{:?}", cipher);
    Ok(str::from_utf8(&cipher).unwrap().to_string())
}

pub fn encrypt_bytes(
    crypto: &impl CryptographicAlgorithm,
    message: &mut [u8],
) -> Result<Vec<u8>, CryptoError> {
    crypto.encrypt(message)
}

pub fn decrypt_bytes(
    crypto: &impl CryptographicAlgorithm,
    cipher: &mut [u8],
) -> Result<Vec<u8>, CryptoError> {
    crypto.decrypt(cipher)
}

pub trait HashingAlgorithm {
    fn hash(&self, message: Vec<u8>) -> Vec<u8>;
}

pub fn hash(hash: &impl HashingAlgorithm, message: String) -> String {
    let mut message = message.as_bytes().to_vec();
    message = hash.hash(message);
    u8_to_hex(message)
}
