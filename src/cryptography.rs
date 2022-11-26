pub mod aes;
pub mod rsa;

pub enum CryptoError {
    AESError(aes::AESError),
}

pub trait CryptographicAlgorithm {
    fn encrypt(&self, message: &mut [u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, cipher: &mut [u8]) -> Result<Vec<u8>, CryptoError>;
}

pub fn encrypt(
    crypto: &impl CryptographicAlgorithm,
    message: &mut [u8],
) -> Result<Vec<u8>, CryptoError> {
    crypto.encrypt(message)
}

pub fn decrypt(
    crypto: &impl CryptographicAlgorithm,
    cipher: &mut [u8],
) -> Result<Vec<u8>, CryptoError> {
    crypto.decrypt(cipher)
}
