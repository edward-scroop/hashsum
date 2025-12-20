use crate::hash_algorithm::{Hash, md5::MD5};
use std::{
    env::{self},
    fs::File,
    io::{self, Read},
    process,
};

mod hash_algorithm;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const GIB: usize = 1024 * MIB;
const FILE_BUFFER: usize = 512 * MIB;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut counter = 1;
    if args.len() == 1 {
        counter = 0;
    }

    while counter < args.len() {
        let mut data: Vec<u8>;

        if args[counter] == "-" || counter == 0 {
            // Read data from stdin
            let mut stdin = String::new();

            let mut bytes_read = io::stdin().read_line(&mut stdin).unwrap_or(0);
            while bytes_read != 0 {
                bytes_read = match io::stdin().read_line(&mut stdin) {
                    Ok(f) => f,
                    Err(error) => {
                        eprintln!("Error reading stdin: {}", error);
                        process::exit(1);
                    }
                }
            }

            data = stdin.clone().into_bytes();
        } else {
            // Read data from file passed as argument
            let mut file_handle = match File::open(&args[counter]) {
                Err(e) => {
                    eprintln!("Error opening file {}: {}", args[counter], e);
                    process::exit(1);
                }
                Ok(f) => f,
            };

            data = Vec::with_capacity(64 * MIB);
            let file_result = file_handle.read_to_end(&mut data);

            match file_result {
                Err(e) => {
                    eprintln!("Error loading file {}: {}", args[counter], e);
                    process::exit(1);
                }
                Ok(_) => (),
            };
        }

        let hashed_result = MD5::hash_data(&mut data);
        if counter != 0 {
            println!("{} {}", hashed_result, args[counter]);
        } else {
            println!("{} -", hashed_result);
        }

        counter += 1;
    }
}
