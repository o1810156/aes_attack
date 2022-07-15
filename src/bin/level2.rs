mod aes_limited {
    use aes::{add_round_key, generate_round_keys, mix_columns, shift_rows, sub_bytes, GF256};

    pub fn aes_4r_middle(plain: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let mut state = [GF256::new(0); 16];
        let mut cipher_key = [GF256::new(0); 16];
        for i in 0..16 {
            state[i] = GF256::new(plain[i]);
            cipher_key[i] = GF256::new(key[i]);
        }

        let round_keys = generate_round_keys(&cipher_key);
        // round 0
        add_round_key(&mut state, &round_keys[0]);
        // round 1 ~ 3
        for i in 1..=3 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &round_keys[i]);
        }

        let mut res = [0u8; 16];
        for i in 0..16 {
            res[i] = state[i].get_u8();
        }

        res
    }

    pub fn aes_4r(plain: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let mut state = [GF256::new(0); 16];
        let mut cipher_key = [GF256::new(0); 16];
        for i in 0..16 {
            state[i] = GF256::new(plain[i]);
            cipher_key[i] = GF256::new(key[i]);
        }

        let round_keys = generate_round_keys(&cipher_key);
        // round 0
        add_round_key(&mut state, &round_keys[0]);
        // round 1 ~ 3
        for i in 1..=3 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &round_keys[i]);
        }

        // round 4
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &round_keys[4]);

        let mut res = [0u8; 16];
        for i in 0..16 {
            res[i] = state[i].get_u8();
        }

        res
    }
}

#[macro_use]
extern crate anyhow;

use aes::{dump_array, generate_round_keys, GF256};
use aes_limited::*;
use anyhow::Result;
use rand::prelude::*;

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

fn key_guess(ciphers: &[[u8; 16]; 256]) -> Vec<Vec<GF256>> {
    let mut res = vec![vec![]; 16];
    for i in 0..16 {
        for k in 0_u8..=255 {
            let mut s = GF256::new(0);
            for j in 0..=255 {
                s ^= GF256::new(INV_SBOX[(ciphers[j][i] ^ k) as usize]);
            }

            if s == GF256::new(0) {
                res[i].push(GF256::new(k));
            }
        }
    }

    res
}

fn kr_sub(
    count: usize,
    key_index: &mut [usize; 16],
    guessed_keys: &[Vec<GF256>],
    ciphers: &[[u8; 16]; 256],
    plain_texts: &[[u8; 16]; 256],
    result: &mut Option<[[GF256; 16]; 5]>,
) {
    if result.is_some() {
        return;
    }

    if count <= 15 {
        let len = guessed_keys[count].len();
        for i in 0..len {
            if result.is_some() {
                return;
            }

            key_index[count] = i;
            kr_sub(
                count + 1,
                key_index,
                guessed_keys,
                ciphers,
                plain_texts,
                result,
            );
        }
        return;
    }

    let mut round4_key = [GF256::new(0); 16];
    key_index
        .iter()
        .enumerate()
        .for_each(|(i, &k)| round4_key[i] = guessed_keys[i][k]);

    // dump_array(&round4_key, "round4_key");

    let keys = inv_generate_round_keys(&round4_key);
    let mut key = [0_u8; 16];
    for i in 0..16 {
        key[i] = keys[0][i].get_u8();
    }

    for (i, cipher) in ciphers.iter().enumerate() {
        let c = aes_4r(&plain_texts[i], &key);

        if &c != cipher {
            return;
        }
    }

    *result = Some(keys);
}

fn key_recovery(
    ciphers: &[[u8; 16]; 256],
    plain_texts: &[[u8; 16]; 256],
    verbose: bool,
) -> (Option<[[GF256; 16]; 5]>, usize) {
    let guessed_keys = key_guess(ciphers);

    let cand_num = guessed_keys.iter().map(|v| v.len()).reduce(|acc, x| acc * x).unwrap();
    if verbose {
        println!("Candidate key num: {}", cand_num);
    }

    let mut result = None;
    let mut key_index = [0; 16];
    kr_sub(
        0,
        &mut key_index,
        &guessed_keys,
        ciphers,
        plain_texts,
        &mut result,
    );

    (result, cand_num)
}

fn inv_generate_round_keys(round4_key: &[GF256; 16]) -> [[GF256; 16]; 5] {
    let rcon = [
        0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a,
    ];

    let mut res = [[GF256::new(0); 16]; 5];

    for i in 0..16 {
        res[4][i] = round4_key[i];
    }

    /* hint

     0  1  2  3
     4  5  6  7
     8  9 10 11
    12 13 14 15

     */

    for i in (1..5).rev() {
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

fn balanced_prop() {
    let mut sum = [0u8; 16];

    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();

    for a in 0_u8..=255 {
        let mut plain = [0; 16];
        plain[0] = a;

        let cipher = aes_4r_middle(&plain, &key);

        for i in 0..16 {
            sum[i] ^= cipher[i];
        }
    }

    let sum = GF256::from_u8array(&sum).unwrap();
    dump_array(&sum, "Balanced Property Sum Check for R3");
}

fn integral_key_recovery_attack_for_r4_aes(verbose: bool) -> Result<(bool, usize)> {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();

    let gf_key = GF256::from_u8array(&key).unwrap();
    let keys = generate_round_keys(&gf_key);

    let mut sum = [0u8; 16];
    let mut ciphers = [[0u8; 16]; 256];
    let mut plain_texts = [[0u8; 16]; 256];
    let constant_p = rng.gen();
    for a in 0_u8..=255 {
        let mut plain = [constant_p; 16];
        plain[0] = a;

        let cipher = aes_4r(&plain, &key);

        for i in 0..16 {
            sum[i] ^= cipher[i];
        }

        plain_texts[a as usize] = plain;
        ciphers[a as usize] = cipher;
    }

    let sum = GF256::from_u8array(&sum).unwrap();

    if verbose {
        dump_array(&sum, "Balanced Property Sum Check for R4");
        for (i, key) in keys.iter().enumerate().take(5) {
            dump_array(key, format!("key {}", i).as_str());
        }
    }

    let (rec_keys, cands_num) = key_recovery(&ciphers, &plain_texts, verbose);

    let rec_keys = match rec_keys {
        Some(k) => k,
        None => {
            return Err(anyhow!("key recovery failed"));
        }
    };

    if verbose {
        for (i, key) in rec_keys.iter().enumerate().take(5) {
            dump_array(key, format!("rec key {}", i).as_str());
        }
    }

    let result = &keys[0] == &rec_keys[0];

    Ok((result, cands_num))
}

use std::env::args;

fn main() -> Result<()> {
    println!("level 2 Integral Key Recovery Attack against 4 Round AES");

    balanced_prop();

    let verbose = true;
    let (result, _) = integral_key_recovery_attack_for_r4_aes(verbose)?;
    println!("{}", result);

    let mut args = args();
    let times = args
        .nth(1)
        .and_then(|a| a.parse::<usize>().ok())
        .unwrap_or(10);

    let mut success = 0;
    let mut cands_num_sum = 0;
    for _ in 0..times {
        let (result, cands_num) = integral_key_recovery_attack_for_r4_aes(false)?;
        cands_num_sum += cands_num;
        success += if result { 1 } else { 0 };
    }

    println!("success: {}\nresult: {}", success, success == times);
    println!("cands_num_avg: {}", cands_num_sum as f64 / times as f64);

    Ok(())
}
