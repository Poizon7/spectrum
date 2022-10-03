#![allow(non_snake_case)]

extern crate rand;
use rand::Rng;

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

// Functions related to the 128-bit key
fn Generate128InitKey() -> [u8; 16] {
    let mut key = [0; 16];
    for i in 0..16 {
        key[i] = rand::thread_rng().gen();
    }
    key
}
fn Expand128Key(initKey: [u8; 16]) -> [u8; 176] {
    let mut temp: [u8; 4] = [0, 0, 0, 0];
    let mut c: u8 = 16;
    let mut i = 1;
    let mut key = [0; 176];

    for byte in initKey {
        key[i as usize] = byte;
    }

    while c < 176 {
        for j in 0..4 {
            temp[j] = key[(j as u8 + c - 4) as usize];
        }

        if c % 16 == 0 {
            ScheduleCore(&mut temp, i);
            i += 1;
        }

        for j in 0..4 {
            key[c as usize] = key[c as usize - 16] ^ temp[j];
            c += 1;
        }
    }
    key
}

// Struct for working with 192-bit keys

#[derive(Copy, Clone, Debug)]
pub struct Key192bit {
    pub key: [u8; 208],
}

// Functions related to the 192-bit key
fn Generate192InitKey() -> [u8; 24] {
    let mut key = [0; 24];
    for i in 0..16 {
        key[i] = rand::thread_rng().gen();
    }
    key
}
fn Expand192Key(initKey: [u8; 24]) -> [u8; 208] {
    let mut temp: [u8; 4] = [0, 0, 0, 0];
    let mut c: u8 = 24;
    let mut i = 1;
    let mut key = [0; 208];

    for byte in initKey {
        key[i as usize] = byte;
    }

    while c < 208 {
        for j in 0..4 {
            temp[j] = key[(j as u8 + c - 4) as usize];
        }

        if c % 24 == 0 {
            ScheduleCore(&mut temp, i);
            i += 1;
        }

        for j in 0..4 {
            key[c as usize] = key[c as usize - 24] ^ temp[j];
            c += 1;
        }
    }
    key
}

// Struct for working with 256-bit keys

#[derive(Copy, Clone, Debug)]
pub struct Key256bit {
    pub key: [u8; 240],
}

// Functions related to the 256-bit key
fn Generate256InitKey() -> [u8; 32] {
    let mut key = [0; 32];
    for i in 0..32 {
        key[i] = rand::thread_rng().gen();
    }
    key
}
fn Expand256Key(initKey: [u8; 32]) -> [u8; 240] {
    let mut temp: [u8; 4] = [0, 0, 0, 0];
    let mut c: u8 = 32;
    let mut i = 1;
    let mut key = [0; 240];

    for byte in initKey {
        key[i as usize] = byte;
    }

    while c < 240 {
        for j in 0..4 {
            temp[j] = key[(j as u8 + c - 4) as usize];
        }

        if c % 32 == 0 {
            ScheduleCore(&mut temp, i);
            i += 1;
        }

        if c % 32 == 16 {
            for j in 0..4 {
                Sbox(temp[j]);
            }
        }

        for j in 0..4 {
            key[c as usize] = key[(c - 16) as usize] ^ temp[j];
            c += 1;
        }

        for j in 0..4 {
            key[c as usize] = key[c as usize - 32] ^ temp[j];
            c += 1;
        }
    }
    key
}

// Functions related to AES keys
fn Rotate(byte: &mut [u8; 4]) {
    let temp = byte[0];

    for i in 0..3 {
        byte[i] = byte[i + 1];
    }

    byte[3] = temp;
}
fn Rcon(mut byte: u8) -> u8 {
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
fn ScheduleCore(byte: &mut [u8; 4], i: u8) {
    Rotate(byte);
    for j in 0..4 {
        Sbox(byte[j]);
    }
    byte[0] ^= Rcon(i);
}
pub fn GenerateKey(bit: &KeyLength) -> Key {
    match bit {
        KeyLength::Bit128(initKey) => {
            let initKey = match initKey {
                Some(initKey) => *initKey,
                None => Generate128InitKey(),
            };
            let key = Key128bit {
                key: Expand128Key(initKey),
            };

            Key::Key128bit(key)
        }
        KeyLength::Bit192(initKey) => {
            let initKey = match initKey {
                Some(initKey) => *initKey,
                None => Generate192InitKey(),
            };
            let key = Key192bit {
                key: Expand192Key(initKey),
            };

            Key::Key192bit(key)
        }
        KeyLength::Bit256(initKey) => {
            let initKey = match initKey {
                Some(initKey) => *initKey,
                None => Generate256InitKey(),
            };
            let key = Key256bit {
                key: Expand256Key(initKey),
            };

            Key::Key256bit(key)
        }
    }
}

// Encrypt

fn Sbox(byte: u8) -> u8 {
    let sbox: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    sbox[byte as usize]
}

fn ShiftRows(matrix: &mut [u8; 16]) {
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

    matrix[12] = temp;
}

fn MixColumns(matrix: &mut [u8; 16]) {
    for i in 0..4 {
        let c = [
            matrix[i * 4],
            matrix[(i * 4) + 1],
            matrix[(i * 4) + 2],
            matrix[(i * 4) + 3],
        ];

        matrix[i * 4] = FFM(2, c[0]) ^ FFM(3, c[1]) ^ FFM(1, c[2]) ^ FFM(1, c[3]);
        matrix[(i * 4) + 1] = FFM(1, c[0]) ^ FFM(2, c[1]) ^ FFM(3, c[2]) ^ FFM(1, c[3]);
        matrix[(i * 4) + 2] = FFM(1, c[0]) ^ FFM(1, c[1]) ^ FFM(2, c[2]) ^ FFM(3, c[3]);
        matrix[(i * 4) + 3] = FFM(3, c[0]) ^ FFM(1, c[1]) ^ FFM(1, c[2]) ^ FFM(2, c[3]);
    }
}

// Decryption

fn ReverseSbox(byte: u8) -> u8 {
    let sbox: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    for j in 0..=255 {
        if byte == sbox[j as usize] {
            return j;
        }
    }

    0
}

fn ReverseShiftRows(matrix: &mut [u8; 16]) {
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

    matrix[15] = temp;
}

fn ReverseMixColumns(matrix: &mut [u8; 16]) {
    for i in 0..4 {
        let c = [
            matrix[i * 4],
            matrix[(i * 4) + 1],
            matrix[(i * 4) + 2],
            matrix[(i * 4) + 3],
        ];

        matrix[(i * 4)] = FFM(14, c[0]) ^ FFM(11, c[1]) ^ FFM(13, c[2]) ^ FFM(9, c[3]);
        matrix[(i * 4) + 1] = FFM(9, c[0]) ^ FFM(14, c[1]) ^ FFM(11, c[2]) ^ FFM(13, c[3]);
        matrix[(i * 4) + 2] = FFM(13, c[0]) ^ FFM(9, c[1]) ^ FFM(14, c[2]) ^ FFM(11, c[3]);
        matrix[(i * 4) + 3] = FFM(11, c[0]) ^ FFM(13, c[1]) ^ FFM(9, c[2]) ^ FFM(14, c[3]);
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

fn AddKey(matrix: &mut [u8; 16], key: &[u8]) {
    for i in 0..16 {
        matrix[(i)] ^= key[i];
    }
}

fn FFM(n1: u8, n2: u8) -> u8 {
    let mut a: u8 = n1;
    let mut b: u8 = n2;
    let mut p: u8 = 0;

    for _i in 0..=8 {
        if (b & 0b00000001) == 1 {
            p ^= a;
        }

        b = b >> 1;

        let carry = if (a & 0b10000000) == 128 { 1 } else { 0 };

        a = a << 1;

        if carry == 1 {
            a ^= 0x1b;
        }
    }

    p
}

fn EncryptionAlgorithm(matrix: &mut [u8; 16], key: &Key) {
    match key {
        Key::Key128bit(key) => {
            AddKey(matrix, &key.key[0..16]);

            for round in 1..=9 {
                for i in 0..16 {
                    matrix[i] = Sbox(matrix[i]);
                }

                ShiftRows(matrix);
                MixColumns(matrix);
                AddKey(matrix, &key.key[(round * 16)..((round * 16) + 16)]);
            }

            for i in 0..16 {
                matrix[i] = Sbox(matrix[i]);
            }

            ShiftRows(matrix);
            AddKey(matrix, &key.key[160..176]);
        }
        Key::Key192bit(key) => {
            AddKey(matrix, &key.key[0..16]);

            for round in 1..=11 {
                for i in 0..16 {
                    matrix[i] = Sbox(matrix[i]);
                }

                ShiftRows(matrix);
                MixColumns(matrix);
                AddKey(matrix, &key.key[(round * 16)..((round * 16) + 16)]);
            }

            for i in 0..16 {
                matrix[i] = Sbox(matrix[i]);
            }

            ShiftRows(matrix);
            AddKey(matrix, &key.key[192..208]);
        }
        Key::Key256bit(key) => {
            AddKey(matrix, &key.key[0..16]);

            for round in 1..=13 {
                for i in 0..16 {
                    matrix[i] = Sbox(matrix[i]);
                }

                ShiftRows(matrix);
                MixColumns(matrix);
                AddKey(matrix, &key.key[(round * 16)..((round * 16) + 16)]);
            }

            for i in 0..16 {
                matrix[i] = Sbox(matrix[i]);
            }

            ShiftRows(matrix);
            AddKey(matrix, &key.key[224..240]);
        }
    }
}

pub fn Encrypt(plain: &mut String, key: &Key) -> Vec<[u8; 16]> {
    let mut matrix: Vec<[u8; 16]> = Vec::new();

    while plain.len() % 16 != 0 {
        plain.push(' ');
    }

    for i in 0..(&plain.len() / 16) {
        matrix.push(PlainToMatrix(&plain[i * 16..(i + 1) * 16]));
        EncryptionAlgorithm(&mut matrix[i], key);
    }

    let mut message = Vec::new();

    for i in 0..(&plain.len() / 16) {
        message.push(matrix[i]);
    }

    message
}

fn DecryptionAlgorithm(matrix: &mut [u8; 16], key: &Key) {
    match key {
        Key::Key128bit(key) => {
            AddKey(matrix, &key.key[160..176]);
            ReverseShiftRows(matrix);

            for i in 0..16 {
                matrix[i] = ReverseSbox(matrix[i]);
            }

            for round in (1..=9).rev() {
                AddKey(matrix, &key.key[(round * 16)..((round * 16) + 16)]);
                ReverseMixColumns(matrix);
                ReverseShiftRows(matrix);

                for i in 0..16 {
                    matrix[i] = ReverseSbox(matrix[i]);
                }
            }

            AddKey(matrix, &key.key[0..16]);
        }
        Key::Key192bit(key) => {
            AddKey(matrix, &key.key[192..208]);
            ReverseShiftRows(matrix);

            for i in 0..16 {
                matrix[i] = ReverseSbox(matrix[i]);
            }

            for round in (1..=11).rev() {
                AddKey(matrix, &key.key[(round * 16)..((round * 16) + 16)]);
                ReverseMixColumns(matrix);
                ReverseShiftRows(matrix);

                for i in 0..16 {
                    matrix[i] = ReverseSbox(matrix[i]);
                }
            }

            AddKey(matrix, &key.key[0..16]);
        }
        Key::Key256bit(key) => {
            AddKey(matrix, &key.key[224..240]);
            ReverseShiftRows(matrix);

            for i in 0..16 {
                matrix[i] = ReverseSbox(matrix[i]);
            }

            for round in (1..=13).rev() {
                AddKey(matrix, &key.key[(round * 16)..((round * 16) + 16)]);
                ReverseMixColumns(matrix);
                ReverseShiftRows(matrix);

                for i in 0..16 {
                    matrix[i] = ReverseSbox(matrix[i]);
                }
            }

            AddKey(matrix, &key.key[0..16]);
        }
    }
}

pub fn Decrypt(mut crypt: Vec<[u8; 16]>, key: &Key) -> String {
    for i in 0..(crypt.len()) {
        DecryptionAlgorithm(&mut crypt[i], &key);
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
