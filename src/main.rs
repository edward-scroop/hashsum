use std::{
    env,
    fs::File,
    io::{self, BufReader, Read},
    process,
    time::Instant,
};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const GIB: usize = 1024 * MIB;
const FILE_BUFFER: usize = 512 * MIB;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut counter = 1;

    if args.len() <= 1 {
        eprintln!("Error no file arguments passed to program.");
        process::exit(1);
    }

    while counter < args.len() {
        let file_handler = match File::open(&args[counter]) {
            Err(e) => {
                eprintln!("Error loading file {}: {}", args[counter], e);
                process::exit(1);
            }
            Ok(f) => f,
        };

        let now = Instant::now();
        match hash_file(file_handler, 64) {
            Err(e) => {
                eprintln!("Error hashing file {}: {}", args[counter], e);
                process::exit(1);
            }
            Ok(_) => (),
        };
        let elapsed_time = now.elapsed();
        print!(
            "\n\n\nLoading and processing {} took {}ms.\n\n\n",
            args[counter],
            elapsed_time.as_millis()
        );

        counter += 1;
    }
}

fn hash_file(file_handle: File, block_size: usize) -> io::Result<()> {
    let mut reader = BufReader::with_capacity(FILE_BUFFER, file_handle);
    let mut buffer = vec![0_u8; block_size];
    let mut bytes_read: usize;
    let mut blocks_processed = false;

    while !blocks_processed {
        bytes_read = reader.read(&mut buffer)?;
        //print!("{}", str::from_utf8(&buffer[0..bytes_read]).unwrap());
        let test = str::from_utf8(&buffer[0..bytes_read]).unwrap();

        if bytes_read < buffer.len() {
            blocks_processed = true;
        }
    }

    return Ok(());
}
