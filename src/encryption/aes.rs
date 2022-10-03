#![allow(non_snake_case)]

mod key;
mod cypher;

#[derive(Copy, Clone, Debug)]
pub enum Key {
    Key128bit(Key128bit),
    Key192bit(Key192bit),
    Key256bit(Key256bit),
}

#[derive(Clone, Copy, Debug)]
pub enum KeyLength {
    Bit128(Option<[u8; 16]>),
    Bit192(Option<[u8; 24]>),
    Bit256(Option<[u8; 32]>),
}

// Struct for working with 128-bit keys

#[derive(Copy, Clone, Debug)]
pub struct Key128bit {
    pub key: [u8; 176],
}

// Struct for working with 192-bit keys

#[derive(Copy, Clone, Debug)]
pub struct Key192bit {
    pub key: [u8; 208],
}

// Struct for working with 256-bit keys

#[derive(Copy, Clone, Debug)]
pub struct Key256bit {
    pub key: [u8; 240],
}

pub fn GenerateKey(bit: &KeyLength) -> Key {
    match bit {
        KeyLength::Bit128(initKey) => {
            let initKey = match initKey {
                Some(initKey) => *initKey,
                None => key::Generate128InitKey(),
            };
            let key = Key128bit {
                key: key::Expand128Key(initKey),
            };

            Key::Key128bit(key)
        }
        KeyLength::Bit192(initKey) => {
            let initKey = match initKey {
                Some(initKey) => *initKey,
                None => key::Generate192InitKey(),
            };
            let key = Key192bit {
                key: key::Expand192Key(initKey),
            };

            Key::Key192bit(key)
        }
        KeyLength::Bit256(initKey) => {
            let initKey = match initKey {
                Some(initKey) => *initKey,
                None => key::Generate256InitKey(),
            };
            let key = Key256bit {
                key: key::Expand256Key(initKey),
            };

            Key::Key256bit(key)
        }
    }
}

// Control

fn PlainToMatrix(plain: &str) -> [u8; 16] {
    let mut plain = String::from(plain.trim_end());

    while plain.len() < 16 {
        plain.push(' ')
    }

    let plain = plain.as_bytes();

    [
        plain[0], plain[4], plain[8], plain[12], plain[1], plain[5], plain[9], plain[13], plain[2],
        plain[6], plain[10], plain[14], plain[3], plain[7], plain[11], plain[15],
    ]
}

pub fn Encrypt(plain: &mut String, key: &Key) -> Vec<[u8; 16]> {
    let mut matrix: Vec<[u8; 16]> = Vec::new();

    while plain.len() % 16 != 0 {
        plain.push(' ');
    }

    for i in 0..(&plain.len() / 16) {
        matrix.push(PlainToMatrix(&plain[i * 16..(i + 1) * 16]));
        cypher::EncryptionAlgorithm(&mut matrix[i], key);
    }

    let mut message = Vec::new();

    for i in 0..(&plain.len() / 16) {
        message.push(matrix[i]);
    }

    message
}

pub fn Decrypt(mut crypt: Vec<[u8; 16]>, key: &Key) -> String {
    for i in 0..(crypt.len()) {
        cypher::DecryptionAlgorithm(&mut crypt[i], &key);
    }

    let mut message: String = String::new();

    for i in 0..crypt.len() {
        for j in 0..4 {
            for k in 0..4 {
                message += &((crypt[i][k * 4 + j] as char).to_string());
            }
        }
    }

    message
}
