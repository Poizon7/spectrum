#[derive(Debug)]
pub enum FormatError {
    IncorrectVectorSize,
}

pub fn u8_to_hex(vec: Vec<u8>) -> String {
    let mut string = String::new();
    let hex = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
    ];

    for i in vec {
        let j = i / 16;
        string += hex[j as usize];

        let j = i % 16;
        string += hex[j as usize];
    }

    string
}

pub fn hex_to_u8(mut string: &str) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();
    let hex = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut bytes = Vec::new();
    while string.len() >= 2 {
        let byte: &str;
        (byte, string) = string.split_at(2);
        bytes.push(byte);
    }

    for byte in bytes {
        let num = hex
            .iter()
            .position(|x| x == &byte.chars().next().unwrap())
            .unwrap()
            * 16
            + hex
                .iter()
                .position(|x| x == &byte.chars().nth(1).unwrap())
                .unwrap();
        vec.push(num as u8);
    }

    vec
}

pub fn vec_to_array4(vec: Vec<u8>) -> Result<[u8; 4], FormatError> {
    match vec.len() {
        4 => {
            let mut array = [0; 4];

            for (i, byte) in vec.into_iter().enumerate() {
                array[i] = byte;
            }

            Ok(array)
        }
        _ => Err(FormatError::IncorrectVectorSize),
    }
}

pub fn vec_to_array16(vec: Vec<u8>) -> Result<[u8; 16], FormatError> {
    match vec.len() {
        16 => {
            let mut array = [0; 16];

            for (i, byte) in vec.into_iter().enumerate() {
                array[i] = byte;
            }

            Ok(array)
        }
        _ => Err(FormatError::IncorrectVectorSize),
    }
}

pub fn vec_to_array24(vec: Vec<u8>) -> Result<[u8; 24], FormatError> {
    match vec.len() {
        24 => {
            let mut array = [0; 24];

            for (i, byte) in vec.into_iter().enumerate() {
                array[i] = byte;
            }

            Ok(array)
        }
        _ => Err(FormatError::IncorrectVectorSize),
    }
}

pub fn vec_to_array32(vec: Vec<u8>) -> Result<[u8; 32], FormatError> {
    match vec.len() {
        32 => {
            let mut array = [0; 32];

            for (i, byte) in vec.into_iter().enumerate() {
                array[i] = byte;
            }

            Ok(array)
        }
        _ => Err(FormatError::IncorrectVectorSize),
    }
}

pub fn array_to_vec<const N: usize>(array: [u8; N]) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();

    for byte in array {
        vec.push(byte);
    }

    vec
}
