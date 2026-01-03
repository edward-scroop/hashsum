// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2025 Edward Scroop <edward.scroop@gmail.com>

use std::io::Read;

pub mod md5;
pub mod sha1;

pub trait Hash {
    fn hash_slice(message: &[u8]) -> String;

    fn hash_stream(message: impl Read) -> std::io::Result<String>;
}
