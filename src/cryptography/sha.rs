use crate::cryptography::HashingAlgorithm;
use crate::format::u8_to_hex;
use crate::math::right_rotate;

pub enum SHAType {
    SHA256,
}

pub struct SHA {
    kind: SHAType,
}

impl SHA {
    pub fn new() -> SHA {
        SHA {
            kind: SHAType::SHA256,
        }
    }
}

impl HashingAlgorithm for SHA {
    fn hash(&self, mut message: Vec<u8>) -> String {
        match self.kind {
            SHAType::SHA256 => {
                // Defining variables
                let mut h0: u32 = 0x6a09e667;
                let mut h1: u32 = 0xbb67ae85;
                let mut h2: u32 = 0x3c6ef372;
                let mut h3: u32 = 0xa54ff53a;
                let mut h4: u32 = 0x510e527f;
                let mut h5: u32 = 0x9b05688c;
                let mut h6: u32 = 0x1f83d9ab;
                let mut h7: u32 = 0x5be0cd19;

                let k: [u32; 64] = [
                    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
                    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
                    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
                    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
                ];

                // Pre-processing (Padding):
                let mut num = (message.len() * 8).to_be_bytes();
                let num = num.as_mut_slice();
                let mut num = num.to_vec();

                message.push(128);
                while (message.len() + 8) % 64 != 0 {
                    message.push(0);
                }

                message.append(&mut num);

                // Process the message in successive 512-bit chunks:
                let temp: Vec<Vec<u8>> = message.chunks(4).map(|s| s.into()).collect();
                {
                    let mut w: [u32; 64] = [0; 64];
                    for i in 0..16 {
                        let num = ((temp[i][0] as u32) << 24)
                            + ((temp[i][1] as u32) << 16)
                            + ((temp[i][2] as u32) << 8)
                            + ((temp[i][3] as u32) << 0);
                        w[i] = num;
                    }
                    // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
                    for i in 16..64 {
                        let s0 = right_rotate(w[i - 15], 7)
                            ^ right_rotate(w[i - 15], 18)
                            ^ (w[i - 15] >> 3);

                        let s1 = right_rotate(w[i - 2], 17)
                            ^ right_rotate(w[i - 2], 19)
                            ^ (w[i - 2] >> 10);

                        w[i] = ((w[i - 16] as u64 + s0 as u64 + w[i - 7] as u64 + s1 as u64)
                            & u32::MAX as u64) as u32;
                    }

                    // Initialize working variables to current hash value:
                    let mut a = h0;
                    let mut b = h1;
                    let mut c = h2;
                    let mut d = h3;
                    let mut e = h4;
                    let mut f = h5;
                    let mut g = h6;
                    let mut h = h7;

                    // Compression function main loop:
                    for i in 0..64 {
                        let s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
                        let ch = (e & f) ^ ((!e) & g);
                        let temp1 = ((h as u64 + s1 as u64 + ch as u64 + k[i] as u64 + w[i] as u64)
                            & u32::MAX as u64) as u32;
                        let s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
                        let maj = (a & b) ^ (a & c) ^ (b & c);
                        let temp2 = ((s0 as u64 + maj as u64) & u32::MAX as u64) as u32;

                        h = g;
                        g = f;
                        f = e;
                        e = ((d as u64 + temp1 as u64) & u32::MAX as u64) as u32;
                        d = c;
                        c = b;
                        b = a;
                        a = ((temp1 as u64 + temp2 as u64) & u32::MAX as u64) as u32;
                    }

                    // Add the compressed chunk to the current hash value:
                    h0 = ((h0 as u64 + a as u64) & u32::MAX as u64) as u32;
                    h1 = ((h1 as u64 + b as u64) & u32::MAX as u64) as u32;
                    h2 = ((h2 as u64 + c as u64) & u32::MAX as u64) as u32;
                    h3 = ((h3 as u64 + d as u64) & u32::MAX as u64) as u32;
                    h4 = ((h4 as u64 + e as u64) & u32::MAX as u64) as u32;
                    h5 = ((h5 as u64 + f as u64) & u32::MAX as u64) as u32;
                    h6 = ((h6 as u64 + g as u64) & u32::MAX as u64) as u32;
                    h7 = ((h7 as u64 + h as u64) & u32::MAX as u64) as u32;
                }

                let mut hash = h0.to_be_bytes().to_vec();
                hash.append(&mut h1.to_be_bytes().to_vec());
                hash.append(&mut h2.to_be_bytes().to_vec());
                hash.append(&mut h3.to_be_bytes().to_vec());
                hash.append(&mut h4.to_be_bytes().to_vec());
                hash.append(&mut h5.to_be_bytes().to_vec());
                hash.append(&mut h6.to_be_bytes().to_vec());
                hash.append(&mut h7.to_be_bytes().to_vec());

                // Produce the final hash value (big-endian):
                u8_to_hex(hash)
            }
        }
    }
}
