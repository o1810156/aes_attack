use aes_attack::*;
use rand::seq::SliceRandom;

use std::env::args;

fn main() {
    println!("level 1 SBOX's DDT");

    let table = ddt::sbox_ddt();

    let sbox_dist = show(&table);

    let const_sbox = (0..=255).collect::<Vec<u8>>();
    let const_ddt = ddt::make_ddt(&const_sbox);
    show(&const_ddt);

    let mut args = args();
    let times = args
        .nth(1)
        .and_then(|a| a.parse::<usize>().ok())
        .unwrap_or(5);

    println!("times: {}", times);

    let mut dists = Vec::new();

    let mut rng = rand::thread_rng();
    for _ in 0..times {
        let mut random_sbox = (0..=255).collect::<Vec<u8>>();
        random_sbox.shuffle(&mut rng);

        let random_ddt = ddt::make_ddt(&random_sbox);
        let dist = show(&random_ddt);
        dists.push(dist);
    }

    println!("sbox dist: {}", sbox_dist);
    for (i, dist) in dists.into_iter().enumerate() {
        if sbox_dist > dist {
            println!("More minimum distribution found! @ [{}]: {}", i, dist);
        }
    }
}

fn show(table: &Vec<Vec<usize>>) -> f64 {
    print!("   |");
    for i in 0..256 {
        print!("  {:02x}", i);
    }
    println!("");
    for _ in 0..=256 {
        print!("----");
    }
    println!("");

    let mut check_flag = None;

    let mut sum = 0;

    for (i, row) in table.iter().enumerate() {
        print!("{:02x} | ", i);
        let mut check_4 = 0;
        let mut check_2 = 0;
        let mut check_0 = 0;
        for col in row.iter() {
            print!("{:3} ", col);

            if *col == 4 {
                check_4 += 1;
            } else if *col == 2 {
                check_2 += 1;
            } else if *col == 0 {
                check_0 += 1;
            }

            let d = *col as i32 - 1;
            sum += d * d;
        }

        if i != 0 && (check_4 != 1 || check_2 != 126 || check_0 != 129) {
            check_flag = Some(format!(
                "Invalid row: {} ({}, {}, {})",
                i, check_4, check_2, check_0
            ));
        }

        println!("");
    }

    println!("\n==========\n");

    if let Some(check_result) = check_flag {
        println!("{}", check_result);
    } else {
        println!("DDT is valid");
    }

    println!("sum: {}", sum);
    let res = sum as f64 / (256 * 256) as f64;
    println!("Distributed: {}", res);

    println!("\n==========\n");

    res
}
