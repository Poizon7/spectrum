extern crate rand;

use rand::Rng;

use crate::cryptography::{CryptoError, CryptographicAlgorithm};
use crate::format::{hex_to_u8, vec_to_matrix16};
use crate::math::finite_field_multiplication;

// Key enums
#[derive(Clone, Debug)]
enum Key {
    Key128bit([u8; 176]),
    Key192bit([u8; 208]),
    Key256bit([u8; 240]),
}

#[derive(Clone, Debug)]
enum InitKey {
    Bit128([u8; 16]),
    Bit192([u8; 24]),
    Bit256([u8; 32]),
}

#[derive(Debug)]
enum KeySize {
    Bit128,
    Bit192,
    Bit256,
}

#[derive(Debug)]
pub enum AESError {
    IncorrectKeySize,
    EmptyKey,
}

#[derive(Debug)]
pub struct AES {
    key_size: KeySize,
    init_key: Option<InitKey>,
    key: Option<Key>,
}

// Key generation
impl AES {
    pub fn new() -> AES {
        let mut aes = AES {
            key_size: KeySize::Bit256,
            init_key: None,
            key: None,
        };
        aes.generate_init_key();
        aes.expand_key();
        aes
    }

    pub fn new_128() -> AES {
        AES {
            key_size: KeySize::Bit128,
            init_key: None,
            key: None,
        }
    }

    pub fn new_192() -> AES {
        AES {
            key_size: KeySize::Bit192,
            init_key: None,
            key: None,
        }
    }

    pub fn new_256() -> AES {
        AES {
            key_size: KeySize::Bit256,
            init_key: None,
            key: None,
        }
    }

    pub fn from_hex(key: &str) -> Result<AES, AESError> {
        let vec: Vec<u8> = hex_to_u8(key);

        let mut aes = AES {
            key_size: KeySize::Bit256,
            init_key: None,
            key: None,
        };
        aes.generate_init_key_from(vec.as_slice())?;
        aes.expand_key();

        Ok(aes)
    }

    pub fn generate_init_key_from(&mut self, bytes: &[u8]) -> Result<(), AESError> {
        match self.key_size {
            /*KeySize::Bit128 => {
                let mut key = [0; 16];
                for i in 0..16 {
                    key[i] = rand::thread_rng().gen();
                }
                self.init_key = Some(InitKey::Bit128(key));
            }
            KeySize::Bit192 => {
                let mut key = [0; 24];
                for i in 0..16 {
                    key[i] = rand::thread_rng().gen();
                }
                self.init_key = Some(InitKey::Bit192(key));
            }*/
            KeySize::Bit256 => {
                if bytes.len() == 32 {
                    let mut key = [0; 32];
                    for i in 0..32 {
                        key[i] = *bytes.get(i).unwrap();
                    }
                    self.init_key = Some(InitKey::Bit256(key));
                    Ok(())
                } else {
                    Err(AESError::IncorrectKeySize)
                }
            }
            _ => Err(AESError::IncorrectKeySize),
        }
    }

    pub fn generate_init_key(&mut self) {
        match self.key_size {
            KeySize::Bit128 => {
                let mut key = [0; 16];
                for i in 0..16 {
                    key[i] = rand::thread_rng().gen();
                }
                self.init_key = Some(InitKey::Bit128(key));
            }
            KeySize::Bit192 => {
                let mut key = [0; 24];
                for i in 0..24 {
                    key[i] = rand::thread_rng().gen();
                }
                self.init_key = Some(InitKey::Bit192(key));
            }
            KeySize::Bit256 => {
                let mut key = [0; 32];
                for i in 0..32 {
                    key[i] = rand::thread_rng().gen();
                }
                self.init_key = Some(InitKey::Bit256(key));
            }
        }
    }

    pub fn generate_key(&mut self) {
        if self.init_key.is_some() {
            self.expand_key();
        } else {
            self.generate_init_key();
            self.expand_key();
        }
    }

    fn expand_key(&mut self) {
        if let Some(init_key) = &self.init_key {
            let mut temp: [u8; 4] = [0, 0, 0, 0];
            let mut c: u8 = match self.key_size {
                KeySize::Bit128 => 16,
                KeySize::Bit192 => 24,
                KeySize::Bit256 => 32,
            };
            let mut i = 1;
            let mut key = match self.key_size {
                KeySize::Bit128 => Key::Key128bit([0; 176]),
                KeySize::Bit192 => Key::Key192bit([0; 208]),
                KeySize::Bit256 => Key::Key256bit([0; 240]),
            };

            match key {
                Key::Key128bit(mut key_128) => {
                    for byte in match init_key {
                        InitKey::Bit128(init_key) => *init_key,
                        _ => panic!("Missmatch between init key and key"),
                    } {
                        key_128[i as usize] = byte;
                    }
                    key = Key::Key128bit(key_128);
                }
                Key::Key192bit(mut key_192) => {
                    for byte in match init_key {
                        InitKey::Bit192(init_key) => *init_key,
                        _ => panic!("Missmatch between init key and key"),
                    } {
                        key_192[i as usize] = byte;
                    }
                    key = Key::Key192bit(key_192);
                }
                Key::Key256bit(mut key_256) => {
                    for (i, byte) in match init_key {
                        InitKey::Bit256(init_key) => (*init_key).iter().enumerate(),
                        _ => panic!("Missmatch between init key and key"),
                    } {
                        key_256[i as usize] = *byte;
                    }
                    key = Key::Key256bit(key_256);
                }
            }

            while c < match self.key_size {
                KeySize::Bit128 => 176,
                KeySize::Bit192 => 208,
                KeySize::Bit256 => 240,
            } {
                match key {
                    Key::Key128bit(key) => {
                        for j in 0..4 {
                            temp[j] = key[(j as u8 + c - 4) as usize];
                        }
                    }
                    Key::Key192bit(key) => {
                        for j in 0..4 {
                            temp[j] = key[(j as u8 + c - 4) as usize];
                        }
                    }
                    Key::Key256bit(key) => {
                        for j in 0..4 {
                            temp[j] = key[(j as u8 + c - 4) as usize];
                        }
                    }
                }

                if c % match self.key_size {
                    KeySize::Bit128 => 16,
                    KeySize::Bit192 => 24,
                    KeySize::Bit256 => 32,
                } == 0
                {
                    AES::schedule_core(&mut temp, i);
                    i += 1;
                }

                if match key {
                    Key::Key256bit(_) => true,
                    _ => false,
                } && c % 32 == 16
                {
                    for mut byte in temp.iter_mut() {
                        AES::sbox(&mut byte);
                    }
                }

                match key {
                    Key::Key128bit(mut key_128) => {
                        for j in 0..4 {
                            key_128[c as usize] = key_128[(c - 16) as usize] ^ temp[j];
                            c += 1;
                        }
                        key = Key::Key128bit(key_128);
                    }
                    Key::Key192bit(mut key_192) => {
                        for j in 0..4 {
                            key_192[c as usize] = key_192[(c - 24) as usize] ^ temp[j];
                            c += 1;
                        }
                        key = Key::Key192bit(key_192);
                    }
                    Key::Key256bit(mut key_256) => {
                        for j in 0..4 {
                            key_256[c as usize] = key_256[(c - 32) as usize] ^ temp[j];
                            c += 1;
                        }
                        key = Key::Key256bit(key_256);
                    }
                }
            }

            self.key = Some(key);
        }
    }

    fn rotate(byte: &mut [u8; 4]) {
        let temp = byte[0];

        for i in 0..3 {
            byte[i] = byte[i + 1];
        }

        byte[3] = temp;
    }

    fn rcon(mut byte: u8) -> u8 {
        let mut c: u8 = 1;

        if byte == 0 {
            return 0;
        }

        while byte != 1 {
            let b = c & 0x80;
            c <<= 1;
            if b == 0x80 {
                c ^= 0x1b;
            }
            byte -= 1;
        }

        return c;
    }

    fn schedule_core(bytes: &mut [u8; 4], i: u8) {
        AES::rotate(bytes);
        for byte in bytes.iter_mut() {
            AES::sbox(byte);
        }
        bytes[0] ^= AES::rcon(i);
    }
}

impl CryptographicAlgorithm for AES {
    fn encrypt(&self, message: &mut [u8]) -> Result<Vec<u8>, CryptoError> {
        match &self.key {
            Some(key) => {
                let message = message.chunks_mut(16);

                let mut cipher = Vec::new();

                for slice in message {
                    let mut vec = slice.to_vec();
                    if slice.len() < 16 {
                        while vec.len() < 16 {
                            vec.push(0);
                        }
                    }

                    let mut matrix = vec_to_matrix16(vec).unwrap();

                    AES::encryption_algorithm(&mut matrix, key);

                    cipher.append(&mut matrix.to_vec());
                }

                Ok(cipher)
            }
            None => Err(CryptoError::AESError(AESError::EmptyKey)),
        }
    }

    fn decrypt(&self, cipher: &mut [u8]) -> Result<Vec<u8>, CryptoError> {
        match &self.key {
            Some(key) => {
                let cipher = cipher.chunks_mut(16);

                let mut message = Vec::new();

                for slice in cipher {
                    let mut vec = slice.to_vec();
                    if slice.len() < 16 {
                        while vec.len() < 16 {
                            vec.push(0);
                        }
                    }

                    let mut matrix = vec_to_matrix16(vec).unwrap();

                    AES::decryption_algorithm(&mut matrix, key);

                    message.append(&mut matrix.to_vec());
                }

                Ok(message)
            }
            None => Err(CryptoError::AESError(AESError::EmptyKey)),
        }
    }
}

// Shared functions
impl AES {
    fn add_key(matrix: &mut [u8; 16], key: &[u8]) {
        for i in 0..16 {
            matrix[i] ^= key[i];
        }
    }
}

// Encryption
impl AES {
    fn sbox(byte: &mut u8) {
        let sbox: [u8; 256] = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
            0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
            0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
            0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
            0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
            0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
            0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
            0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
            0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
            0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
            0xb0, 0x54, 0xbb, 0x16,
        ];

        *byte = sbox[*byte as usize];
    }

    fn shift_rows(matrix: &mut [u8; 16]) {
        let mut temp = [0; 16];

        temp[0] = matrix[0];
        temp[1] = matrix[5];
        temp[2] = matrix[10];
        temp[3] = matrix[15];

        temp[4] = matrix[4];
        temp[5] = matrix[9];
        temp[6] = matrix[14];
        temp[7] = matrix[3];

        temp[8] = matrix[8];
        temp[9] = matrix[13];
        temp[10] = matrix[2];
        temp[11] = matrix[7];

        temp[12] = matrix[12];
        temp[13] = matrix[1];
        temp[14] = matrix[6];
        temp[15] = matrix[11];

        *matrix = temp;

        /*
        let temp = matrix[4];

        for i in 4..7 {
            matrix[i] = matrix[i + 1];
        }

        matrix[7] = temp;

        let temp = matrix[8];
        matrix[8] = matrix[10];
        matrix[10] = temp;

        let temp = matrix[9];
        matrix[9] = matrix[11];
        matrix[11] = temp;

        let temp = matrix[15];

        for i in (12..16).rev() {
            matrix[(i)] = matrix[(i - 1)];
        }

        matrix[12] = temp;*/
    }

    fn mix_columns(matrix: &mut [u8]) {
        for i in 0..4 {
            let c = [
                matrix[i * 4],
                matrix[(i * 4) + 1],
                matrix[(i * 4) + 2],
                matrix[(i * 4) + 3],
            ];

            matrix[i * 4] = finite_field_multiplication(2, c[0])
                ^ finite_field_multiplication(3, c[1])
                ^ finite_field_multiplication(1, c[2])
                ^ finite_field_multiplication(1, c[3]);
            matrix[(i * 4) + 1] = finite_field_multiplication(1, c[0])
                ^ finite_field_multiplication(2, c[1])
                ^ finite_field_multiplication(3, c[2])
                ^ finite_field_multiplication(1, c[3]);
            matrix[(i * 4) + 2] = finite_field_multiplication(1, c[0])
                ^ finite_field_multiplication(1, c[1])
                ^ finite_field_multiplication(2, c[2])
                ^ finite_field_multiplication(3, c[3]);
            matrix[(i * 4) + 3] = finite_field_multiplication(3, c[0])
                ^ finite_field_multiplication(1, c[1])
                ^ finite_field_multiplication(1, c[2])
                ^ finite_field_multiplication(2, c[3]);
        }
    }

    fn encryption_algorithm(matrix: &mut [u8; 16], key: &Key) {
        match key {
            Key::Key128bit(key) => {
                AES::add_key(matrix, &key[0..16]);

                for round in 1..=9 {
                    for byte in matrix.iter_mut() {
                        AES::sbox(byte);
                    }

                    AES::shift_rows(matrix);
                    AES::mix_columns(matrix);
                    AES::add_key(matrix, &key[(round * 16)..((round * 16) + 16)]);
                }

                for byte in matrix.iter_mut() {
                    AES::sbox(byte);
                }

                AES::shift_rows(matrix);
                AES::add_key(matrix, &key[160..176]);
            }
            Key::Key192bit(key) => {
                AES::add_key(matrix, &key[0..16]);

                for round in 1..=11 {
                    for byte in matrix.iter_mut() {
                        AES::sbox(byte);
                    }

                    AES::shift_rows(matrix);
                    AES::mix_columns(matrix);
                    AES::add_key(matrix, &key[(round * 16)..((round * 16) + 16)]);
                }

                for byte in matrix.iter_mut() {
                    AES::sbox(byte);
                }

                AES::shift_rows(matrix);
                AES::add_key(matrix, &key[192..208]);
            }
            Key::Key256bit(key) => {
                AES::add_key(matrix, &key[0..16]);

                for round in 1..=13 {
                    for byte in matrix.iter_mut() {
                        AES::sbox(byte);
                    }

                    AES::shift_rows(matrix);
                    AES::mix_columns(matrix);
                    AES::add_key(matrix, &key[(round * 16)..((round * 16) + 16)]);
                }

                for byte in matrix.iter_mut() {
                    AES::sbox(byte);
                }

                AES::shift_rows(matrix);
                AES::add_key(matrix, &key[224..240]);
            }
        }
    }
}

// Decryption
impl AES {
    fn reverse_sbox(byte: &mut u8) {
        let sbox: [u8; 256] = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
            0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
            0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c,
            0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
            0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68,
            0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
            0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8,
            0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
            0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
            0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
            0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
            0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33,
            0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
            0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
            0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
            0x55, 0x21, 0x0c, 0x7d,
        ];

        *byte = sbox[*byte as usize];
    }

    fn reverse_shift_rows(matrix: &mut [u8; 16]) {
        let mut temp = [0; 16];

        temp[0] = matrix[0];
        temp[5] = matrix[1];
        temp[10] = matrix[2];
        temp[15] = matrix[3];

        temp[4] = matrix[4];
        temp[9] = matrix[5];
        temp[14] = matrix[6];
        temp[3] = matrix[7];

        temp[8] = matrix[8];
        temp[13] = matrix[9];
        temp[2] = matrix[10];
        temp[7] = matrix[11];

        temp[12] = matrix[12];
        temp[1] = matrix[13];
        temp[6] = matrix[14];
        temp[11] = matrix[15];

        *matrix = temp;

        /*
        let temp = matrix[7];

        for i in (4..8).rev() {
            matrix[i] = matrix[i - 1];
        }

        matrix[4] = temp;

        let temp = matrix[10];
        matrix[10] = matrix[8];
        matrix[8] = temp;

        let temp = matrix[11];
        matrix[11] = matrix[9];
        matrix[9] = temp;

        let temp = matrix[12];

        for i in 12..15 {
            matrix[i] = matrix[i + 1];
        }

        matrix[15] = temp;*/
    }

    fn reverse_mix_columns(matrix: &mut [u8; 16]) {
        for i in 0..4 {
            let c = [
                matrix[i * 4],
                matrix[(i * 4) + 1],
                matrix[(i * 4) + 2],
                matrix[(i * 4) + 3],
            ];

            matrix[(i * 4)] = finite_field_multiplication(14, c[0])
                ^ finite_field_multiplication(11, c[1])
                ^ finite_field_multiplication(13, c[2])
                ^ finite_field_multiplication(9, c[3]);
            matrix[(i * 4) + 1] = finite_field_multiplication(9, c[0])
                ^ finite_field_multiplication(14, c[1])
                ^ finite_field_multiplication(11, c[2])
                ^ finite_field_multiplication(13, c[3]);
            matrix[(i * 4) + 2] = finite_field_multiplication(13, c[0])
                ^ finite_field_multiplication(9, c[1])
                ^ finite_field_multiplication(14, c[2])
                ^ finite_field_multiplication(11, c[3]);
            matrix[(i * 4) + 3] = finite_field_multiplication(11, c[0])
                ^ finite_field_multiplication(13, c[1])
                ^ finite_field_multiplication(9, c[2])
                ^ finite_field_multiplication(14, c[3]);
        }
    }

    fn decryption_algorithm(matrix: &mut [u8; 16], key: &Key) {
        match key {
            Key::Key128bit(key) => {
                AES::add_key(matrix, &key[160..176]);
                AES::reverse_shift_rows(matrix);

                for byte in matrix.iter_mut() {
                    AES::reverse_sbox(byte);
                }

                for round in (1..=9).rev() {
                    AES::add_key(matrix, &key[(round * 16)..((round * 16) + 16)]);
                    AES::reverse_mix_columns(matrix);
                    AES::reverse_shift_rows(matrix);

                    for byte in matrix.iter_mut() {
                        AES::reverse_sbox(byte);
                    }
                }

                AES::add_key(matrix, &key[0..16]);
            }
            Key::Key192bit(key) => {
                AES::add_key(matrix, &key[192..208]);
                AES::reverse_shift_rows(matrix);

                for byte in matrix.iter_mut() {
                    AES::reverse_sbox(byte);
                }

                for round in (1..=11).rev() {
                    AES::add_key(matrix, &key[(round * 16)..((round * 16) + 16)]);
                    AES::reverse_mix_columns(matrix);
                    AES::reverse_shift_rows(matrix);

                    for byte in matrix.iter_mut() {
                        AES::reverse_sbox(byte);
                    }
                }

                AES::add_key(matrix, &key[0..16]);
            }
            Key::Key256bit(key) => {
                AES::add_key(matrix, &key[224..240]);
                AES::reverse_shift_rows(matrix);

                for byte in matrix.iter_mut() {
                    AES::reverse_sbox(byte);
                }

                for round in (1..=13).rev() {
                    AES::add_key(matrix, &key[(round * 16)..((round * 16) + 16)]);
                    AES::reverse_mix_columns(matrix);
                    AES::reverse_shift_rows(matrix);

                    for byte in matrix.iter_mut() {
                        AES::reverse_sbox(byte);
                    }
                }

                AES::add_key(matrix, &key[0..16]);
            }
        }
    }
}
