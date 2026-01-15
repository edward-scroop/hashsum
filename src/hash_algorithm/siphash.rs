// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2026 Edward Scroop <edward.scroop@gmail.com>

use crate::hash_algorithm::Hash;

pub struct SIPHASH24 {}

struct SIPHASHContext {
    k0: u64,
    k1: u64,
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    compression_rounds: usize,
    finalization_rounds: usize,
    length: usize,
    hash: Option<String>,
}

impl Default for SIPHASHContext {
    fn default() -> Self {
        Self {
            k0: 0,
            k1: 0,
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            compression_rounds: 2,
            finalization_rounds: 4,
            length: 0,
            hash: None,
        }
    }
}
fn sip_round(context: &mut SIPHASHContext) {
    context.v0 = context.v0.wrapping_add(context.v1);
    context.v2 = context.v2.wrapping_add(context.v3);

    context.v1 = context.v1.rotate_left(13);
    context.v3 = context.v3.rotate_left(16);

    context.v1 ^= context.v0;
    context.v3 ^= context.v2;

    context.v0 = context.v0.rotate_left(32);

    context.v0 = context.v0.wrapping_add(context.v3);
    context.v2 = context.v2.wrapping_add(context.v1);

    context.v1 = context.v1.rotate_left(17);
    context.v3 = context.v3.rotate_left(21);

    context.v1 ^= context.v2;
    context.v3 ^= context.v0;

    context.v2 = context.v2.rotate_left(32);
}

impl SIPHASHContext {
    fn init(&mut self) {
        self.v0 = self.k0 ^ 0x736F6D6570736575u64;
        self.v1 = self.k1 ^ 0x646F72616E646F6Du64;
        self.v2 = self.k0 ^ 0x6C7967656E657261u64;
        self.v3 = self.k1 ^ 0x7465646279746573u64;
    }
}

impl SIPHASH24 {
    fn hash_word(mut context: SIPHASHContext, original_word_bytes: &[u8]) -> SIPHASHContext {
        assert!(
            original_word_bytes.len() <= 8,
            "Too large of an array passed to hash block. Must be 8 bytes or less."
        );

        let word_length = original_word_bytes.len();
        let mut padding_array = [0x00u8; 8];
        let mut padded = false;
        let mut word_bytes = original_word_bytes;

        context.length += word_length;

        // Pad if not a full word
        if word_length != 8 {
            padding_array[0..word_length].copy_from_slice(word_bytes);
            padding_array[padding_array.len() - 1] = context.length as u8;
            word_bytes = &padding_array;
            padded = true;
        }

        let word = u64::from_le_bytes([
            word_bytes[0],
            word_bytes[1],
            word_bytes[2],
            word_bytes[3],
            word_bytes[4],
            word_bytes[5],
            word_bytes[6],
            word_bytes[7],
        ]);

        context.v3 ^= word;

        for _ in 0..context.compression_rounds {
            sip_round(&mut context);
        }

        context.v0 ^= word;

        if padded {
            context.v2 ^= 0xff;

            for _ in 0..context.finalization_rounds {
                sip_round(&mut context);
            }

            let hash = context.v0 ^ context.v1 ^ context.v2 ^ context.v3;
            context.hash = Some(format!("{:0x}", hash));
        }

        context
    }
}

impl Hash for SIPHASH24 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: SIPHASHContext = Default::default();
        context.init();

        for word in message.chunks(8) {
            context = Self::hash_word(context, word);
        }

        if context.hash.is_none() {
            context = Self::hash_word(context, &[]);
        }

        context
            .hash
            .expect("Hash should have always been produced.")
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: SIPHASHContext = Default::default();
        let mut buffer = [0u8; 8];

        loop {
            let bytes = stream.read(&mut buffer)?;
            context = Self::hash_word(context, &buffer[0..bytes]);

            if bytes < 8 {
                break;
            }
        }

        if context.hash.is_none() {
            context = Self::hash_word(context, &[])
        }

        Ok(context
            .hash
            .expect("Hash should have always been produced."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash() {
        assert_eq!(SIPHASH24::hash_slice(&[]), "1e924b9d737700d7");
    }

    #[test]
    fn siphash24_hash() {
        assert_eq!(SIPHASH24::hash_slice("a".as_bytes()), "96c20860cd93a249");

        assert_eq!(SIPHASH24::hash_slice("abc".as_bytes()), "3fc884964770eede");

        assert_eq!(
            SIPHASH24::hash_slice(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes()
            ),
            "cbf763b2ded8f799"
        );
    }
}
