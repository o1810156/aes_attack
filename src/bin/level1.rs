use aes_attack::*;
use rand::seq::SliceRandom;

fn main() {
    println!("level 1 SBOX's DDT");

    let table = ddt::sbox_ddt();

    show(&table);

    let const_sbox = (0..=255).collect::<Vec<u8>>();
    let const_ddt = ddt::make_ddt(&const_sbox);
    show(&const_ddt);

    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let mut random_sbox = (0..=255).collect::<Vec<u8>>();
        random_sbox.shuffle(&mut rng);

        let random_ddt = ddt::make_ddt(&random_sbox);
        show(&random_ddt);
    }
}

fn show(table: &Vec<Vec<usize>>) {
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
    println!("Distributed: {}", sum as f64 / (256 * 256) as f64);

    println!("\n==========\n");
}
