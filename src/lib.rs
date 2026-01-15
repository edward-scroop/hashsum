// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2026 Edward Scroop <edward.scroop@gmail.com>

use std::{env, fmt::Display, process};

pub mod hash_algorithm;

pub const VERSION_MAJOR: usize = 0;
pub const VERSION_MIN: usize = 1;
pub const VERSION_PATCH: usize = 0;
pub const KIB: usize = 1024;
pub const MIB: usize = 1024 * KIB;
pub const GIB: usize = 1024 * MIB;
pub const FILE_BUFFER: usize = 512 * MIB;
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
    sha1
    sha224
    sha256
    sha384
    sha512
    sha512224
    sha512256
    sha3224
    sha3256
    sha3384
    sha3512
    fnv32
    fnv32a
    fnv64
    fnv64a";
const HELP_INFO_STRING: &str = "Try 'hashsum --help' for more information.";
const HELP_ALGORITHM_ARGUMENTS: &str = "Valid arguments are:
    - 'md5'
    - 'sha1'
    - 'sha224'
    - 'sha256'
    - 'sha384'
    - 'sha512'
    - 'sha512224'
    - 'sha512256'
    - 'sha3224'
    - 'sha3256'
    - 'sha3384'
    - 'sha3512'
    - 'fnv32'
    - 'fnv32a'
    - 'fnv64'
    - 'fnv64a'";

pub enum Algorithm {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    FNV32,
    FNV32a,
    FNV64,
    FNV64a,
}

fn print_help_unrecognised_option(arg: impl Display) -> ! {
    eprintln!("hashsum: unrecognised option '{arg}'\n{HELP_INFO_STRING}");
    process::exit(1);
}

fn print_help_invalid_option(arg: impl Display) -> ! {
    eprintln!("hashsum: invalid option -- '{arg}'\n{HELP_INFO_STRING}");
    process::exit(1);
}

fn print_help_invalid_argument(
    arg: impl Display,
    option: impl Display,
    valid_arguments: &str,
) -> ! {
    eprintln!(
        "hashsum: invalid argument '{arg}' for '{option}'\n{valid_arguments}\n{HELP_INFO_STRING}"
    );
    process::exit(1);
}
fn print_help_option_requires_argument(arg: impl Display) -> ! {
    eprintln!("hashsum: option requires an argument -- '{arg}'\n{HELP_INFO_STRING}");
    process::exit(1);
}

fn print_help() -> ! {
    eprintln!("{HELP_STRING}");
    process::exit(0);
}

fn print_version() -> ! {
    eprintln!(
        "hashsum version {VERSION_MAJOR}.{VERSION_MIN}.{VERSION_PATCH}
hashsum comes with ABSOLUTELY NO WARRANTY.  This is free software, and you
are welcome to redistribute it under certain conditions.  See the GNU
General Public Licence for details."
    );
    process::exit(0);
}

fn match_algorithm(algorithm_string: &str, arg_flag: &str) -> Algorithm {
    match algorithm_string {
        "md5" => Algorithm::MD5,
        "sha1" => Algorithm::SHA1,
        "sha224" => Algorithm::SHA224,
        "sha256" => Algorithm::SHA256,
        "sha384" => Algorithm::SHA384,
        "sha512" => Algorithm::SHA512,
        "sha512224" => Algorithm::SHA512_224,
        "sha512256" => Algorithm::SHA512_256,
        "sha3224" => Algorithm::SHA3_224,
        "sha3256" => Algorithm::SHA3_256,
        "sha3384" => Algorithm::SHA3_384,
        "sha3512" => Algorithm::SHA3_512,
        "fnv32" => Algorithm::FNV32,
        "fnv32a" => Algorithm::FNV32a,
        "fnv64" => Algorithm::FNV64,
        "fnv64a" => Algorithm::FNV64a,
        _ => {
            print_help_invalid_argument(algorithm_string, arg_flag, HELP_ALGORITHM_ARGUMENTS);
        }
    }
}

pub struct State {
    pub arguments: Vec<String>,
    pub base64: bool,
    pub output_untagged: bool,
    pub algorithm: Algorithm,
}

impl State {
    pub fn process_arguments() -> Self {
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

            assert!(!argument.is_empty(), "Stdin argument was somehow empty??");
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
                            Some(arg) => match_algorithm(arg, "-a"),
                            None => {
                                print_help_option_requires_argument("-a");
                            }
                        }
                    } else {
                        algorithm = match_algorithm(&argument[2..argument.len()], "-a");
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
                        Some(arg) => match_algorithm(arg, "--algorithm"),
                        None => {
                            print_help_invalid_argument(
                                "",
                                "--algorithm",
                                HELP_ALGORITHM_ARGUMENTS,
                            );
                        }
                    };
                }
                "--untagged" if long_option => output_untagged = true,
                "--version" if long_option => print_version(),
                "--base64" if long_option => base64 = true,
                "--help" if long_option => print_help(),
                _ if long_option => {
                    if argument.len() >= "--algorithm=".len() && argument[0..11] == *"--algorithm" {
                        algorithm = match_algorithm(&argument[12..argument.len()], "--algorithm");
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
