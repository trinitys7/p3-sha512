use std::io::Bytes;

use sha2::Digest;

mod air;
mod columns;
mod constants;
mod generation;
mod utils;
mod bits_air;

pub const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    let len: usize = bytes.as_ref().len();
    let mut buf = [0u8; 64];
    let mut seed = SHA256_H;
    // Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
    let pad_len = if len % 64 < 56 {
        56 - len % 64
    } else {
        64 + 56 - len % 64
    };
    let mut tmp = [0u8; 72];
    tmp[0] = 0x80;

    let padding = &mut tmp[0..pad_len + 8];
    padding[pad_len..pad_len + 8].copy_from_slice(&(len << 3).to_be_bytes());

    let mut bytes_with_padding = bytes.as_ref().to_vec();
    bytes_with_padding.extend_from_slice(&padding);

    for i in 0..bytes_with_padding.len() / 64 {
        buf.copy_from_slice(&bytes_with_padding[i * 64..(i + 1) * 64]);
        permute(&mut seed, buf)
    }
    let mut digest = [0u8; 32];
    for i in 0..8 {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&seed[i].to_be_bytes());
    }
    return digest.to_vec();
}

fn permute(mut seed: impl AsMut<[u32]>, bytes: impl AsRef<[u8]>) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let j = i * 4;
        w[i] = (bytes.as_ref()[j] as u32) << 24
            | (bytes.as_ref()[j + 1] as u32) << 16
            | (bytes.as_ref()[j + 2] as u32) << 8
            | (bytes.as_ref()[j + 3] as u32);
    }

    for i in 16..64 {
        let v1 = w[i - 2];
        let t1 = v1.rotate_right(17) ^ v1.rotate_right(19) ^ (v1 >> 10);
        let v2 = w[i - 15];
        let t2 = v2.rotate_right(7) ^ v2.rotate_right(18) ^ (v2 >> 3);
        w[i] = t1
            .wrapping_add(w[i - 7])
            .wrapping_add(t2)
            .wrapping_add(w[i - 16])
    }

    let seed_copy: &mut [u32] = &mut seed.as_mut().to_vec();
    for i in 0..64 {
        let t1 = seed_copy.as_mut()[7]
            .wrapping_add(
                seed_copy.as_mut()[4].rotate_right(6)
                    ^ seed_copy.as_mut()[4].rotate_right(11)
                    ^ seed_copy.as_mut()[4].rotate_right(25),
            )
            .wrapping_add(
                (seed_copy.as_mut()[4] & seed_copy.as_mut()[5])
                    ^ (!seed_copy.as_mut()[4] & seed_copy.as_mut()[6]),
            )
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);

        let t2 = (seed_copy.as_mut()[0].rotate_right(2)
            ^ seed_copy.as_mut()[0].rotate_right(13)
            ^ seed_copy.as_mut()[0].rotate_right(22))
        .wrapping_add(
            (seed_copy.as_mut()[0] & seed_copy.as_mut()[1])
                ^ (seed_copy.as_mut()[0] & seed_copy.as_mut()[2])
                ^ (seed_copy.as_mut()[1] & seed_copy.as_mut()[2]),
        );
        (
            seed_copy.as_mut()[7],
            seed_copy.as_mut()[6],
            seed_copy.as_mut()[5],
            seed_copy.as_mut()[4],
            seed_copy.as_mut()[3],
            seed_copy.as_mut()[2],
            seed_copy.as_mut()[1],
            seed_copy.as_mut()[0],
        ) = (
            seed_copy.as_mut()[6],
            seed_copy.as_mut()[5],
            seed_copy.as_mut()[4],
            seed_copy.as_mut()[3].wrapping_add(t1),
            seed_copy.as_mut()[2],
            seed_copy.as_mut()[1],
            seed_copy.as_mut()[0],
            t1.wrapping_add(t2),
        );
    }
    for (x, y) in seed.as_mut().iter_mut().zip(seed_copy.iter()) {
        *x = x.wrapping_add(*y);
    }
}
fn main() {
    let rand_bytes: [u8; 32] = [
        16, 71, 94, 251, 180, 27, 214, 66, 25, 64, 54, 0, 202, 116, 10, 106, 153, 150, 20, 138,
        173, 67, 225, 187, 28, 143, 224, 140, 200, 218, 171, 166,
    ];
    println!("sha2: {:?}", sha2::Sha256::digest(&rand_bytes));

    println!("sha custom: {:?}", sha256(&rand_bytes));
}
