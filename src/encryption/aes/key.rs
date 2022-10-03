extern crate rand;
use rand::Rng;

// Functions related to the 128-bit key
pub fn Generate128InitKey() -> [u8; 16] {
  let mut key = [0; 16];
  for i in 0..16 {
      key[i] = rand::thread_rng().gen();
  }
  key
}
pub fn Expand128Key(initKey: [u8; 16]) -> [u8; 176] {
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

// Functions related to the 192-bit key
pub fn Generate192InitKey() -> [u8; 24] {
  let mut key = [0; 24];
  for i in 0..16 {
      key[i] = rand::thread_rng().gen();
  }
  key
}
pub fn Expand192Key(initKey: [u8; 24]) -> [u8; 208] {
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

// Functions related to the 256-bit key
pub fn Generate256InitKey() -> [u8; 32] {
  let mut key = [0; 32];
  for i in 0..32 {
      key[i] = rand::thread_rng().gen();
  }
  key
}
pub fn Expand256Key(initKey: [u8; 32]) -> [u8; 240] {
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
              super::cypher::Sbox(temp[j]);
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
      super::cypher::Sbox(byte[j]);
  }
  byte[0] ^= Rcon(i);
}
