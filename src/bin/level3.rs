mod aes_limited {
    use aes::{add_round_key, generate_round_keys, mix_columns, shift_rows, sub_bytes, GF256};

    pub fn aes_3r(plain: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let mut state = [GF256::new(0); 16];
        let mut cipher_key = [GF256::new(0); 16];
        for i in 0..16 {
            state[i] = GF256::new(plain[i]);
            cipher_key[i] = GF256::new(key[i]);
        }

        let round_keys = generate_round_keys(&cipher_key);
        // round 0
        add_round_key(&mut state, &round_keys[0]);
        // round 1 ~ 2
        for i in 1..=2 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &round_keys[i]);
        }

        // round 3
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &round_keys[3]);

        let mut res = [0u8; 16];
        for i in 0..16 {
            res[i] = state[i].get_u8();
        }

        res
    }
}

use aes::GF256;

#[rustfmt::skip]
const SBOX: [u8;256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

#[rustfmt::skip]
const INV_SBOX: [u8;256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
];

fn inv_sbox(val: GF256) -> GF256 {
    GF256::new(INV_SBOX[val.get_u8() as usize])
}

fn gfarray2u8array<const T: usize>(gfarray: &[GF256; T]) -> [u8; T] {
    let mut res = [0u8; T];
    for i in 0..T {
        res[i] = gfarray[i].get_u8();
    }
    res
}

fn judge(inv_sboxed: &[GF256], coef: &[GF256]) -> bool {
    let v0 = inv_sboxed[0] / coef[0];
    let v1 = inv_sboxed[1] / coef[1];
    let v2 = inv_sboxed[2] / coef[2];
    let v3 = inv_sboxed[3] / coef[3];

    let between_0_1 = v0 == v1;
    let between_1_2 = v1 == v2;
    let between_2_3 = v2 == v3;

    between_0_1 && between_1_2 && between_2_3
}

fn half_judge_up(inv_sboxed: &[GF256], coef: &[GF256]) -> bool {
    let v0 = inv_sboxed[0] / coef[0];
    let v1 = inv_sboxed[1] / coef[1];

    let between_0_1 = v0 == v1;

    between_0_1
}

#[allow(dead_code)]
fn half_judge_middle(inv_sboxed: &[GF256], coef: &[GF256]) -> bool {
    let v1 = inv_sboxed[1] / coef[1];
    let v2 = inv_sboxed[2] / coef[2];

    let between_1_2 = v1 == v2;

    between_1_2
}

fn half_judge_down(inv_sboxed: &[GF256], coef: &[GF256]) -> bool {
    let v2 = inv_sboxed[2] / coef[2];
    let v3 = inv_sboxed[3] / coef[3];

    let between_2_3 = v2 == v3;

    between_2_3
}

fn partial_key_guess(
    original_cipher: &[GF256; 16],
    diff_ciphers: &[[GF256; 16]],
    indices: &[usize],
    coef: &[GF256],
) -> Vec<[GF256; 4]> {
    let original = [
        original_cipher[indices[0]],
        original_cipher[indices[1]],
        original_cipher[indices[2]],
        original_cipher[indices[3]],
    ];

    let mut cands = Vec::new();

    let mut up_cands = Vec::new();
    let mut down_cands = Vec::new();
    for i in 0_u8..=255 {
        for j in 0_u8..=255 {
            let i = GF256::new(i);
            let j = GF256::new(j);

            let o0 = inv_sbox(original[0] ^ i);
            let o1 = inv_sbox(original[1] ^ j);
            let o2 = inv_sbox(original[2] ^ i);
            let o3 = inv_sbox(original[3] ^ j);

            let mut up_flag = true;
            let mut down_flag = true;
            for diff_cipher in diff_ciphers.iter() {
                let diff = [
                    diff_cipher[indices[0]],
                    diff_cipher[indices[1]],
                    diff_cipher[indices[2]],
                    diff_cipher[indices[3]],
                ];

                let a = o0 ^ inv_sbox(diff[0] ^ i);
                let b = o1 ^ inv_sbox(diff[1] ^ j);
                let c = o2 ^ inv_sbox(diff[2] ^ i);
                let d = o3 ^ inv_sbox(diff[3] ^ j);

                if !half_judge_up(&[a, b, c, d], coef) {
                    up_flag = false;
                }

                if !half_judge_down(&[a, b, c, d], coef) {
                    down_flag = false;
                }

                if !up_flag && !down_flag {
                    break;
                }
            }

            if up_flag {
                up_cands.push((i, j));
            }

            if down_flag {
                down_cands.push((i, j));
            }
        }
    }

    for &(u0, u1) in up_cands.iter() {
        for &(d0, d1) in down_cands.iter() {
            let o0 = inv_sbox(original[0] ^ u0);
            let o1 = inv_sbox(original[1] ^ u1);
            let o2 = inv_sbox(original[2] ^ d0);
            let o3 = inv_sbox(original[3] ^ d1);

            let mut flag = true;
            for diff_cipher in diff_ciphers.iter() {
                let diff = [
                    diff_cipher[indices[0]],
                    diff_cipher[indices[1]],
                    diff_cipher[indices[2]],
                    diff_cipher[indices[3]],
                ];

                let a = o0 ^ inv_sbox(diff[0] ^ u0);
                let b = o1 ^ inv_sbox(diff[1] ^ u1);
                let c = o2 ^ inv_sbox(diff[2] ^ d0);
                let d = o3 ^ inv_sbox(diff[3] ^ d1);

                if !judge(&[a, b, c, d], coef) {
                    flag = false;
                    break;
                }
            }

            if flag {
                cands.push([u0, u1, d0, d1]);
            }
        }
    }

    cands
}

fn kr_sub(
    count: usize,
    select: &mut [usize; 4],
    partial_keys: &[Vec<[GF256; 4]>],
    indices: &[[usize; 4]; 4],
    original_cipher: &[GF256; 16],
    original_plain: &[GF256; 16],
    result: &mut Option<[GF256; 16]>,
) {
    if result.is_some() {
        return;
    }

    if count < 4 {
        for i in 0..partial_keys[count].len() {
            if result.is_some() {
                return;
            }

            select[count] = i;
            kr_sub(
                count + 1,
                select,
                partial_keys,
                indices,
                original_cipher,
                original_plain,
                result,
            );
        }
        return;
    }

    let mut round3_key = [GF256::new(0); 16];
    for (i, partial_key_cand) in partial_keys.iter().enumerate() {
        let partial_key = &partial_key_cand[select[i]];
        for (j, k) in indices[i].iter().enumerate() {
            round3_key[*k] = partial_key[j];
        }
    }

    let key = inv_generate_round_keys(&round3_key)[0];
    let u8key = gfarray2u8array(&key);

    let plain = gfarray2u8array(&original_plain);
    let original_cipher = gfarray2u8array(&original_cipher);

    let cipher = aes_3r(&plain, &u8key);

    if cipher == original_cipher {
        *result = Some(key);
    }
}

fn key_recovery(
    partial_keys: &[Vec<[GF256; 4]>],
    indices: &[[usize; 4]; 4],
    original_cipher: &[GF256; 16],
    original_plain: &[GF256; 16],
) -> Option<[GF256; 16]> {
    let mut select = [0; 4];
    let mut result = None;
    kr_sub(
        0,
        &mut select,
        partial_keys,
        indices,
        original_cipher,
        original_plain,
        &mut result,
    );
    result
}

fn inv_generate_round_keys(round3_key: &[GF256; 16]) -> [[GF256; 16]; 4] {
    let rcon = [
        0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a,
    ];

    let mut res = [[GF256::new(0); 16]; 4];

    for i in 0..16 {
        res[3][i] = round3_key[i];
    }

    /* hint

     0  1  2  3
     4  5  6  7
     8  9 10 11
    12 13 14 15

     */

    for i in (1..4).rev() {
        for j in (1..4).rev() {
            for k in 0..4 {
                res[i - 1][j + 4 * k] = res[i][j + 4 * k] ^ res[i][j + 4 * k - 1];
            }
        }

        // ２つ前に一番右の列をコピー
        for k in 0..4 {
            res[i - 1][4 * k] = res[i - 1][4 * k + 3];
        }

        // rot_word
        let tmp = res[i - 1][0];
        res[i - 1][0] = res[i - 1][4];
        res[i - 1][4] = res[i - 1][8];
        res[i - 1][8] = res[i - 1][12];
        res[i - 1][12] = tmp;

        // sub_word
        for j in 0..4 {
            res[i - 1][4 * j] = GF256::new(SBOX[res[i - 1][4 * j].get_u8() as usize]);
        }

        // rcon
        res[i - 1][0] ^= GF256::new(rcon[i]);

        // i番先頭と足し合わせ
        for k in 0..4 {
            res[i - 1][4 * k] ^= res[i][4 * k];
        }
    }

    res
}

#[macro_use]
extern crate anyhow;

use aes::dump_array;
use aes_limited::*;
use anyhow::Result;
use rand::prelude::*;

fn key_recovery_attack_using_differential_cryptanalysis(query: u8, verbose: bool) -> Result<bool> {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();

    let gf_key = GF256::from_u8array(&key).unwrap();
    // let keys = generate_round_keys(&gf_key);

    let original_plain: [u8; 16] = rng.gen();
    let original_cipher = aes_3r(&original_plain, &key);
    let mut diff_plains = Vec::new();
    let mut diff_ciphers = Vec::new();

    // let plain_indices = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];
    let key_indices = [[0, 7, 10, 13], [1, 4, 11, 14], [2, 5, 8, 15], [3, 6, 9, 12]];

    for i in 1_u8..=query {
        let mut delta = original_plain.clone();
        delta[0] ^= i;

        let diff_cipher = aes_3r(&delta, &key);
        diff_plains.push(GF256::from_u8array(&delta).unwrap());
        diff_ciphers.push(GF256::from_u8array(&diff_cipher).unwrap());
    }

    let original_plain = GF256::from_u8array(&original_plain).unwrap();
    let original_cipher = GF256::from_u8array(&original_cipher).unwrap();

    if verbose {
        dump_array(&original_plain, "original_plain");
        /*
        for (i, diff_plain) in diff_plains.iter().enumerate() {
            dump_array(diff_plain, format!("diff_plain_{}", i).as_str());
        }
        */

        dump_array(&original_cipher, "original_cipher");
        /*
        for (i, diff_cipher) in diff_ciphers.iter().enumerate() {
            dump_array(diff_cipher, format!("diff_cipher_{}", i).as_str());
        }
        */
    }

    let coefs: [Vec<GF256>; 4] = [
        vec![2, 1, 1, 3]
            .into_iter()
            .map(|v| GF256::new(v))
            .collect(),
        vec![1, 1, 3, 2]
            .into_iter()
            .map(|v| GF256::new(v))
            .collect(),
        vec![1, 3, 2, 1]
            .into_iter()
            .map(|v| GF256::new(v))
            .collect(),
        vec![3, 2, 1, 1]
            .into_iter()
            .map(|v| GF256::new(v))
            .collect(),
    ];

    let mut partial_keys = Vec::new();
    for i in 0..4 {
        if verbose {
            println!("Partial Key Guess Start: {}", i);
        }
        let partial_key =
            partial_key_guess(&original_cipher, &diff_ciphers, &key_indices[i], &coefs[i]);
        if verbose {
            println!("Cands num @ [{}] : {}", i, partial_key.len());
        }

        partial_keys.push(partial_key);
    }

    let rec_key = key_recovery(
        &partial_keys,
        &key_indices,
        &original_cipher,
        &original_plain,
    );

    let rec_key = match rec_key {
        Some(k) => k,
        None => {
            return Err(anyhow!("key recovery failed"));
        }
    };

    if verbose {
        dump_array(&gf_key, "Original key");
        dump_array(&rec_key, "Recovered key");
    }

    let result = &gf_key == &rec_key;

    Ok(result)
}

use std::env::args;

fn main() -> Result<()> {
    println!("level 3 Key Recovery Attack against 3 Round AES");

    let mut args = args();
    let query = args
        .nth(1)
        .and_then(|a| a.parse::<u8>().ok())
        .unwrap_or(255);
    let times = args
        .nth(0)
        .and_then(|a| a.parse::<usize>().ok())
        .unwrap_or(10);

    println!("query: {}", query);

    let verbose = true;
    let result = key_recovery_attack_using_differential_cryptanalysis(query, verbose)?;
    println!("{}", result);

    let mut success = 0;
    for _ in 0..times {
        let result = key_recovery_attack_using_differential_cryptanalysis(query, false)?;
        success += if result { 1 } else { 0 };
    }

    println!("success: {}\nresult: {}", success, success == times);

    Ok(())
}
