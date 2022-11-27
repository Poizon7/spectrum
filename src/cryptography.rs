pub mod aes;
pub mod rsa;
pub mod sha;

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
    let message = message.as_mut_slice();
    let message = crypto.encrypt(message)?;
    Ok(str::from_utf8(&message).unwrap().to_string())
}

pub fn decrypt(
    crypto: &impl CryptographicAlgorithm,
    cipher: String,
) -> Result<String, CryptoError> {
    let mut cipher = cipher.into_bytes();
    let cipher = cipher.as_mut_slice();
    let cipher = crypto.encrypt(cipher)?;
    Ok(str::from_utf8(&cipher).unwrap().to_string())
}

pub fn encrypt_bytes(
    crypto: &impl CryptographicAlgorithm,
    message: &mut [u8],
) -> Result<Vec<u8>, CryptoError> {
    crypto.decrypt(message)
}

pub fn decrypt_bytes(
    crypto: &impl CryptographicAlgorithm,
    cipher: &mut [u8],
) -> Result<Vec<u8>, CryptoError> {
    crypto.decrypt(cipher)
}

pub trait HashingAlgorithm {
    fn hash(&self, message: Vec<u8>) -> String;
}

pub fn hash(crypto: &impl HashingAlgorithm, message: String) -> String {
    let message = message.as_bytes().to_vec();
    crypto.hash(message)
}
