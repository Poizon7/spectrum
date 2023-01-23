use crate::cryptography::aes::*;

use crate::format::hex_to_u8;

use rand::Rng;

#[derive(Debug)]
pub struct AES256 {
    pub init_key: [u8; 32],
    key: [u8; 240],
}

impl Default for AES256 {
    fn default() -> Self {
        AES256::new()
    }
}

impl AES256 {
    pub fn new() -> Self {
        let init_key = AES256::generate_init_key();
        let key = AES256::expand_key(init_key);
        AES256 {
            init_key,
            key
        }
    }
    
    pub fn from_init_key(init_key: [u8; 32]) -> Self {
        let key = AES256::expand_key(init_key);
        AES256 {
            init_key,
            key
        }
    }

    pub fn from_hex(hex: &str) -> Result<Self, AESError> {
        let hex: Vec<u8> = hex_to_u8(hex);

        if hex.len() != 32 {return Err(AESError::InccorectSize);}

        let mut init_key = [0; 32];
        for (i, byte) in hex.iter().enumerate() {
            init_key[i] = *byte;
        }

        let key = AES256::expand_key(init_key);

        Ok(
            AES256 {
                init_key,
                key
            }
        )
    }

    pub fn generate_init_key() -> [u8; 32] {
        let mut key = [0; 32];
        for byte in key.iter_mut() {
            *byte = rand::thread_rng().gen();
        }
        key
    }

    pub fn expand_key(init_key: [u8; 32]) -> [u8; 240] {
        let mut temp: [u8; 4] = [0, 0, 0, 0];
        let mut c: u8 = 32;
        let mut i = 1;

        let mut key = [0; 240];

        for (j, byte) in init_key.iter().enumerate() {
            key[j] = *byte;
        }

        while c < 240 {
            for j in 0..4 {
                temp[j] = key[(j as u8 + c - 4) as usize];
            }

            if c % 32 == 0 {
                schedule_core(&mut temp, i);
                i += 1;
            }

            if 32 == 16 {
                for byte in temp.iter_mut() {
                    sbox(byte);
                }
            }

            for byte in temp {
                key[c as usize] = key[(c - 32) as usize] ^ byte;
                c += 1;
            }
        }
        key
    }

    pub fn init_key_is_initialised(&self) -> bool {
        self.init_key != [0; 32]
    }

    pub fn key_is_initialised(&self) -> bool {
        self.key != [0; 240]
    }

    pub fn encryption_algorithm(&self, matrix: &mut [u8; 16]) {
        add_key(matrix, &self.key[0..16]);

        for round in 1..=13 {
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
        add_key(matrix, &self.key[224..240]);
    }

    pub fn decryption_algorithm(&self, matrix: &mut [u8; 16]) {
        add_key(matrix, &self.key[224..240]);
        reverse_shift_rows(matrix);

        for byte in matrix.iter_mut() {
            reverse_sbox(byte);
        }

        for round in (1..=13).rev() {
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
