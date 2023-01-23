use crate::cryptography::aes::*;
use crate::format::hex_to_u8;

use rand::Rng;

#[derive(Debug)]
pub struct AES128 {
    pub init_key: [u8; 16],
    key: [u8; 176],
}

impl Default for AES128 {
    fn default() -> Self {
        AES128::new()
    }
}

impl AES128 {
    pub fn new() -> Self {
        let init_key = AES128::generate_init_key();
        let key = AES128::expand_key(init_key);
        AES128 {
            init_key,
            key
        }
    }

    pub fn from_init_key(init_key: [u8; 16]) -> Self {
        let key = AES128::expand_key(init_key);
        AES128 {
            init_key,
            key
        }
    }
    
    pub fn from_hex(hex: &str) -> Result<Self, AESError> {
        let hex: Vec<u8> = hex_to_u8(hex);

        if hex.len() != 16 {return Err(AESError::InccorectSize);}

        let mut init_key = [0; 16];
        for (i, byte) in hex.iter().enumerate() {
            init_key[i] = *byte;
        }

        let key = AES128::expand_key(init_key);

        Ok(AES128 {
                init_key,
                key
        })
    }

    pub fn generate_init_key() -> [u8; 16] {
        let mut key = [0; 16];
        for byte in key.iter_mut() {
            *byte = rand::thread_rng().gen();
        }
        key
    }

    pub fn expand_key(init_key: [u8; 16]) -> [u8; 176] {
        let mut temp: [u8; 4] = [0, 0, 0, 0];
        let mut c: u8 = 16;
        let mut i = 1;

        let mut key = [0; 176];

        for (j, byte) in init_key.iter().enumerate() {
            key[j] = *byte;
        }

        while c < 176 {
            for j in 0..4 {
                temp[j] = key[(j as u8 + c - 4) as usize];
            }

            if c % 16 == 0 {
                schedule_core(&mut temp, i);
                i += 1;
            }

            for byte in temp {
                key[c as usize] = key[(c - 16) as usize] ^ byte;
                c += 1;
            }
        }
        key
    }

    pub fn init_key_is_initialised(&self) -> bool {
        self.init_key != [0; 16]
    }

    pub fn key_is_inistialised(&self) -> bool {
        self.key != [0; 176]
    }

    pub fn encryption_algorithm(&self, matrix: &mut [u8; 16]) {
        add_key(matrix, &self.key[0..16]);

        for round in 1..=9 {
            for byte in matrix.iter_mut() {
                sbox(byte);
            }

            shift_rows(matrix);
            mix_columns(matrix);
            add_key(matrix, &self.key[(round * 16)..((round * 16) + 16)]);
        }

        for byte in matrix.iter_mut() {
            sbox(byte);
        }

        shift_rows(matrix);
        add_key(matrix, &self.key[160..176]);
    }

    pub fn decryption_algorithm(&self, matrix: &mut [u8; 16]) {
        add_key(matrix, &self.key[160..176]);
        reverse_shift_rows(matrix);

        for byte in matrix.iter_mut() {
            reverse_sbox(byte);
        }

        for round in (1..=9).rev() {
            add_key(matrix, &self.key[(round * 16)..((round * 16) + 16)]);
            reverse_mix_columns(matrix);
            reverse_shift_rows(matrix);

            for byte in matrix.iter_mut() {
                reverse_sbox(byte);
            }
        }

        add_key(matrix, &self.key[0..16]);
    }
}
