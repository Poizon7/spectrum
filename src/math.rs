pub fn finite_field_multiplication(n1: u8, n2: u8) -> u8 {
    let mut a: u8 = n1;
    let mut b: u8 = n2;
    let mut p: u8 = 0;

    for _i in 0..=8 {
        if (b & 0b00000001) == 1 {
            p ^= a;
        }

        b >>= 1;

        let carry = ((a & 0b10000000) == 128) as u8;

        a <<= 1;

        if carry == 1 {
            a ^= 0x1b;
        }
    }

    p
}

pub fn gcd(e: i128, t: i128, x: &mut i128, y: &mut i128) -> i128 {
    if e == 0 {
        *x = 0;
        *y = 1;
        return t;
    }
    let mut x1 = 0;
    let mut y1 = 0;
    let gcd = gcd(t % e, e, &mut x1, &mut y1);
    *x = y1 - (t / e) * x1;
    *y = x1;
    gcd
}

pub fn exponential_modulus(m: u128, e: u128, n: u128) -> u128 {
    let mut c = 1;
    let mut f = 0;
    while f < e {
        f += 1;
        c = (m * c) % n;
    }
    c
}

pub fn right_rotate(mut bytes: u32, amount: u8) -> u32 {
    let base: u32 = 2;
    let mut num = (amount > 0) as u32;
    for i in 1..=amount {
        num += base.pow(i as u32);
    }

    let mut part = bytes & num;
    bytes >>= amount;
    part <<= 32 - amount;
    bytes += part;

    bytes
}
