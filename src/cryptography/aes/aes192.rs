use crate::cryptography::aes::*;

use crate::format::hex_to_u8;

use rand::Rng;

#[derive(Debug)]
pub struct AES192 {
    pub init_key: [u8; 24],
    key: [u8; 208],
}

impl Default for AES192 {
    fn default() -> Self {
        AES192::new()
    }
}

impl AES192 {
    pub fn new() -> Self {
        let init_key = AES192::generate_init_key();
        let key = AES192::expand_key(init_key);
        AES192 {
            init_key,
            key
        }
    }
    
    pub fn from_init_key(init_key: [u8; 24]) -> Self {
        let key = AES192::expand_key(init_key);
        AES192 {
            init_key,
            key
        }
    }

    pub fn from_hex(hex: &str) -> Result<Self, AESError> {
        let hex: Vec<u8> = hex_to_u8(hex);

        if hex.len() != 24 {return Err(AESError::InccorectSize);}

        let mut init_key = [0; 24];
        for (i, byte) in hex.iter().enumerate() {
            init_key[i] = *byte;
        }

        let key = AES192::expand_key(init_key);

        Ok(
            AES192 {
                init_key,
                key
            }
        )
    }

    pub fn generate_init_key() -> [u8; 24] {
        let mut key = [0; 24];
        for byte in key.iter_mut() {
            *byte = rand::thread_rng().gen();
        }
        key
    }

    pub fn expand_key(init_key: [u8; 24]) -> [u8; 208] {
        let mut temp: [u8; 4] = [0, 0, 0, 0];
        let mut c: u8 = 24;
        let mut i = 1;

        let mut key = [0; 208];

        for (j, byte) in init_key.iter().enumerate() {
            key[j] = *byte;
        }

        while c < 208 {
            for j in 0..4 {
                temp[j] = key[(j as u8 + c - 4) as usize];
            }

            if c % 24 == 0 {
                schedule_core(&mut temp, i);
                i += 1;
            }

            for byte in temp {
                key[c as usize] = key[(c - 24) as usize] ^ byte;
                c += 1;
            }
        }
        key
    }

    pub fn init_key_is_initialised(&self) -> bool {
        self.init_key != [0; 24]
    }

    pub fn key_is_initialised(&self) -> bool {
        self.key != [0; 208]
    }

    pub fn encryption_algorithm(&self, matrix: &mut [u8; 16]) {
        add_key(matrix, &self.key[0..16]);

        for round in 1..=11 {
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
        add_key(matrix, &self.key[192..208]);
    }

    pub fn decryption_algorithm(&self, matrix: &mut [u8; 16]) {
        add_key(matrix, &self.key[192..208]);
        reverse_shift_rows(matrix);

        for byte in matrix.iter_mut() {
            reverse_sbox(byte);
        }

        for round in (1..=11).rev() {
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
