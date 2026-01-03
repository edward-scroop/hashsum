// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2025 Edward Scroop <edward.scroop@gmail.com>

use crate::hash_algorithm::{Hash, md5::MD5, sha1::SHA1};
use std::{
    env::{self},
    fmt::Display,
    fs::File,
    io::{self, BufReader},
    process,
};

mod hash_algorithm;

#[allow(dead_code)]
const VERSION_MAJOR: usize = 0;
#[allow(dead_code)]
const VERSION_MIN: usize = 1;
#[allow(dead_code)]
const VERSION_PATCH: usize = 0;
const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
#[allow(dead_code)]
const GIB: usize = 1024 * MIB;
const FILE_BUFFER: usize = 512 * MIB;
const HELP_STRING: &str = "Usage: hashsum [OPTION]... [FILE]...
With no FILE, or when FILE is -, read standard input.

Mandatory arguments to long options are mandatory for short options too.
    -a, --algorithm=DIGEST    Select the digest type to use. See DIGEST below for more info.
    -b, --base64              Emit base64-encoded digests instead of the default hexadecimal.
    -u, --untagged            Create a reversed style checksum, without digest type.
                                Default is a BSD-style checksum.
    -h, --help                Display this help and exit.
    -V, --version             Output version information and exit.

DIGEST determines the digest algorithm and default output format:
    md5
    sha1";
const HELP_INFO_STRING: &str = "Try \'hashsum --help\' for more information.";
const HELP_ALGORITHM_ARGUMENTS: &str = "Valid arguments are:
    - \'md5\'
    - \'sha1\'";

fn print_help_unrecognised_option(arg: impl Display) {
    println!("hashsum: unrecognised option \'{arg}\'\n{HELP_INFO_STRING}");
    process::exit(1);
}

fn print_help_invalid_option(arg: impl Display) {
    println!("hashsum: invalid option -- \'{arg}\'\n{HELP_INFO_STRING}");
    process::exit(1);
}

fn print_help_invalid_argument(arg: impl Display, option: impl Display, valid_arguments: &str) {
    println!(
        "hashsum: invalid argument \'{arg}\' for \'{option}\'\n{valid_arguments}\n{HELP_INFO_STRING}"
    );
    process::exit(1);
}
fn print_help_option_requires_argument(arg: impl Display) {
    println!("hashsum: option requires an argument -- '{arg}'\n{HELP_INFO_STRING}");
    process::exit(1);
}

fn print_help() {
    println!("{HELP_STRING}");
    process::exit(0);
}

fn print_version() {
    println!(
        "hashsum version {VERSION_MAJOR}.{VERSION_MIN}.{VERSION_PATCH}
hashsum comes with ABSOLUTELY NO WARRANTY.  This is free software, and you
are welcome to redistribute it under certain conditions.  See the GNU
General Public Licence for details."
    );
    process::exit(0);
}

struct State {
    pub arguments: Vec<String>,
    pub base64: bool,
    pub output_untagged: bool,
    pub algorithm: Algorithm,
}

enum Algorithm {
    MD5,
    SHA1,
}

impl State {
    fn process_arguments() -> Self {
        let mut end_of_command_options = false;
        let mut long_option;
        let mut args: Vec<String> = env::args().collect();
        args.remove(0);
        let mut arguments: Vec<String> = Vec::new();
        let mut base64 = false;
        let mut output_untagged = false;
        let mut algorithm = Algorithm::MD5;

        let mut args_iter = args.iter();
        while let Some(argument) = args_iter.next() {
            long_option = false;

            assert!(argument.len() != 0, "Stdin argument was somehow empty??");
            let arg_slice = if argument.len() == 1 {
                &argument[0..1]
            } else {
                &argument[0..2]
            };

            match arg_slice {
                "-a" if !end_of_command_options => {
                    if args.len() == 2 {
                        let next_arg = args_iter.next();
                        algorithm = match next_arg {
                            Some(arg) => match arg.as_str() {
                                "md5" => Algorithm::MD5,
                                "sha1" => Algorithm::SHA1,
                                _ => {
                                    print_help_invalid_argument(
                                        arg,
                                        "-a",
                                        HELP_ALGORITHM_ARGUMENTS,
                                    );
                                    // Redudant as rust can't see that print_help_invalid_argument exits aswell.
                                    process::exit(1);
                                }
                            },
                            None => {
                                print_help_option_requires_argument("-a");
                                // Redudant as rust can't see that print_help_invalid_argument exits aswell.
                                process::exit(1);
                            }
                        }
                    } else {
                        algorithm = match &argument[2..argument.len()] {
                            "md5" => Algorithm::MD5,
                            "sha1" => Algorithm::SHA1,
                            _ => {
                                print_help_invalid_argument(
                                    argument,
                                    "-a",
                                    HELP_ALGORITHM_ARGUMENTS,
                                );
                                algorithm
                            }
                        }
                    }
                }
                "-b" if !end_of_command_options => {
                    base64 = true;
                }
                "-h" if !end_of_command_options => {
                    print_help();
                }
                "-u" if !end_of_command_options => {
                    output_untagged = true;
                }
                "-V" if !end_of_command_options => {
                    print_version();
                }
                "--" if !end_of_command_options => {
                    if argument == "--" {
                        end_of_command_options = true
                    } else {
                        long_option = true;
                    }
                }
                _ if !end_of_command_options && arg_slice[0..1] == *"-" && argument.len() > 1 => {
                    print_help_invalid_option(argument)
                }
                _ => arguments.push(argument.to_string()),
            };

            match argument.as_str() {
                "--algorithm" if long_option => {
                    let next_arg = args_iter.next();
                    algorithm = match next_arg {
                        Some(arg) => match arg.as_str() {
                            "md5" => Algorithm::MD5,
                            "sha1" => Algorithm::SHA1,
                            _ => {
                                print_help_invalid_argument(
                                    arg,
                                    "--algorithm",
                                    HELP_ALGORITHM_ARGUMENTS,
                                );
                                // Redudant as rust can't see that print_help_invalid_argument exits aswell.
                                process::exit(1);
                            }
                        },
                        None => {
                            print_help_invalid_argument(
                                "",
                                "--algorithm",
                                HELP_ALGORITHM_ARGUMENTS,
                            );
                            // Redudant as rust can't see that print_help_invalid_argument exits aswell.
                            process::exit(1);
                        }
                    };
                }
                "--untagged" if long_option => output_untagged = true,
                "--version" if long_option => print_version(),
                "--base64" if long_option => base64 = true,
                "--help" if long_option => print_help(),
                _ if long_option => {
                    if argument.len() >= "--algorithm=".len() && argument[0..11] == *"--algorithm" {
                        algorithm = match &argument[12..argument.len()] {
                            "md5" => Algorithm::MD5,
                            "sha1" => Algorithm::SHA1,
                            _ => {
                                print_help_invalid_argument(
                                    &argument[12..argument.len()],
                                    "--algorithm",
                                    HELP_ALGORITHM_ARGUMENTS,
                                );
                                // Redudant as rust can't see that print_help_invalid_argument exits aswell.
                                process::exit(1);
                            }
                        };
                    } else {
                        print_help_unrecognised_option(argument);
                    }
                }
                _ => (), // Ignore this match statement if it is a short option,
            }
        }

        Self {
            arguments,
            base64,
            output_untagged,
            algorithm,
        }
    }
}

fn main() {
    let state = State::process_arguments();
    let mut counter = 0;
    let mut no_args = false;

    if state.arguments.len() == 0 {
        no_args = true;
    }

    loop {
        let mut data: Vec<u8>;
        let hashed_result: String;

        if no_args || state.arguments[counter] == "-" {
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
            hashed_result = match state.algorithm {
                Algorithm::MD5 => MD5::hash_slice(&mut data),
                Algorithm::SHA1 => SHA1::hash_slice(&mut data),
            }
        } else {
            // Read data from file passed as argument
            let file_handle = match File::open(&state.arguments[counter]) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Error opening file {}: {}", state.arguments[counter], e);
                    process::exit(1);
                }
            };

            let message = BufReader::with_capacity(FILE_BUFFER, file_handle);

            hashed_result = match MD5::hash_stream(message) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Error opening file {}: {}", state.arguments[counter], e);
                    process::exit(1);
                }
            }
        }

        if !no_args {
            println!("{} {}", hashed_result, state.arguments[counter]);
        } else {
            println!("{} -", hashed_result);
        }

        if counter + 1 >= state.arguments.len() {
            break;
        }
        counter += 1;
    }
}
