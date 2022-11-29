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
    while string.len() > 2 {
        let byte: &str;
        (byte, string) = string.split_at(2);
        bytes.push(byte);
    }

    bytes.push(string);

    for byte in bytes {
        let num = hex
            .iter()
            .position(|x| x == &byte.chars().nth(0).unwrap())
            .unwrap()
            * 16
            + hex
                .iter()
                .position(|x| x == &byte.chars().nth(0).unwrap())
                .unwrap();
        vec.push(num as u8);
    }

    vec
}
