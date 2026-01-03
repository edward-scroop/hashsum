// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2025 Edward Scroop <edward.scroop@gmail.com>

use crate::hash_algorithm::Hash;

pub struct SHA1 {}

struct SHA1Context {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    total_data_size_bits: u64,
    non_zero_padding_required: bool,
    padded: bool,
    hash: Option<String>,
}

impl Default for SHA1Context {
    fn default() -> Self {
        Self {
            a: 0x67_45_23_01_u32,
            b: 0xEF_CD_AB_89_u32,
            c: 0x98_BA_DC_FE_u32,
            d: 0x10_32_54_76_u32,
            e: 0xC3_D2_E1_F0_u32,
            total_data_size_bits: 0,
            non_zero_padding_required: true,
            padded: false,
            hash: None,
        }
    }
}

impl SHA1 {
    fn hash_block(mut context: SHA1Context, original_data_block: &[u8]) -> SHA1Context {
        assert!(
            original_data_block.len() <= 64,
            "Too large of an array passed to hash block. Must be 64 bytes or less."
        );

        let mut data_block = original_data_block;
        let mut temp_vec = Vec::new();

        context.total_data_size_bits += (8 * original_data_block.len()) as u64;

        // Pad only is block is less than 512 bits.
        if original_data_block.len() != 64 {
            // Add padding
            let mut padding = [0x00_u8; 56];
            let mut padding_bytes = 56;

            // Add non zero padding unless current block has no data / end of stream.
            if context.non_zero_padding_required {
                // Add 0b10000000 to start of padding.
                padding[0] = 0x80;
            }

            // Pad to full 512 bit block and change context if next block needs to be a padding
            // block.
            if original_data_block.len() < 56 {
                padding_bytes -= original_data_block.len();
            } else {
                padding_bytes = 64 - original_data_block.len();
                context.non_zero_padding_required = false;
            }

            // Add original data and padding to temp vec
            temp_vec.extend_from_slice(original_data_block);
            temp_vec.extend(&padding[0..padding_bytes]);

            // Add original size of message in bits if block is last block.
            if original_data_block.len() < 56 {
                temp_vec.extend(context.total_data_size_bits.to_be_bytes());
                context.padded = true;
            }

            data_block = temp_vec.as_slice();
        }

        // Load 512 bit data block into 16 big-endian 32 bit words of an 80 word buffer.
        let mut words = [0u32; 80];
        for i in 0..16 {
            words[i] = u32::from_be_bytes([
                data_block[i * 4],
                data_block[i * 4 + 1],
                data_block[i * 4 + 2],
                data_block[i * 4 + 3],
            ]);
        }

        // Extend the 16 words into 80 words.
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }

        let mut temp_a = context.a;
        let mut temp_b = context.b;
        let mut temp_c = context.c;
        let mut temp_d = context.d;
        let mut temp_e = context.e;

        for i in 0..80 {
            let f: u32;
            let k: u32;

            if i < 20 {
                f = (temp_b & temp_c) | (!temp_b & temp_d);
                k = 0x5A827999_u32;
            } else if i < 40 {
                f = temp_b ^ temp_c ^ temp_d;
                k = 0x6ED9EBA1_u32;
            } else if i < 60 {
                f = (temp_b & temp_c) | (temp_b & temp_d) | (temp_c & temp_d);
                k = 0x8F1BBCDC_u32;
            } else {
                f = temp_b ^ temp_c ^ temp_d;
                k = 0xCA62C1D6_u32;
            }

            //temp_word = (a leftrotate 5) + f + e + k + words[i]
            let temp_word = (temp_a.rotate_left(5))
                .wrapping_add(f)
                .wrapping_add(temp_e)
                .wrapping_add(k)
                .wrapping_add(words[i]);

            temp_e = temp_d;
            temp_d = temp_c;
            temp_c = temp_b.rotate_left(30);
            temp_b = temp_a;
            temp_a = temp_word;
        }

        context.a = context.a.wrapping_add(temp_a);
        context.b = context.b.wrapping_add(temp_b);
        context.c = context.c.wrapping_add(temp_c);
        context.d = context.d.wrapping_add(temp_d);
        context.e = context.e.wrapping_add(temp_e);

        if context.padded {
            // message_digest of 160 bits.
            let mut message_digest = Vec::with_capacity(20);
            message_digest.extend_from_slice(&context.a.to_be_bytes());
            message_digest.extend_from_slice(&context.b.to_be_bytes());
            message_digest.extend_from_slice(&context.c.to_be_bytes());
            message_digest.extend_from_slice(&context.d.to_be_bytes());
            message_digest.extend_from_slice(&context.e.to_be_bytes());

            let mut return_string = String::new();
            for byte in message_digest.iter() {
                return_string.push_str(&format!("{:02x}", byte));
            }
            context.hash = Some(return_string);
        }

        return context;
    }
}

impl Hash for SHA1 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: SHA1Context = Default::default();

        for chunk in message.chunks(64) {
            context = Self::hash_block(context, chunk);
        }

        if context.hash == None {
            context = Self::hash_block(context, &[])
        }

        // Cannot panic as a hash will always be produced.
        return context.hash.unwrap();
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: SHA1Context = Default::default();
        let mut buffer = [0u8; 64];

        loop {
            let bytes = stream.read(&mut buffer)?;
            context = Self::hash_block(context, &buffer[0..bytes]);

            if bytes < 64 {
                break;
            }
        }

        // Cannot panic as a hash will always be produced.
        return Ok(context.hash.unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash() {
        let test_vec = Vec::new();

        assert_eq!(
            SHA1::hash_slice(&test_vec),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn rfc_hash_suite() {
        let mut test_vec = Vec::new();
        test_vec.extend_from_slice("abc".as_bytes());

        assert_eq!(
            SHA1::hash_slice(&test_vec),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );

        test_vec.clear();
        test_vec.extend_from_slice("abcdbcdecdefdefgefghfghighijhi".as_bytes());

        assert_eq!(
            SHA1::hash_slice(&test_vec),
            "f9537c23893d2014f365adf8ffe33b8eb0297ed1"
        );

        test_vec.clear();
        test_vec.extend_from_slice("jkijkljklmklmnlmnomnopnopq".as_bytes());

        assert_eq!(
            SHA1::hash_slice(&test_vec),
            "346fb528a24b48f563cb061470bcfd23740427ad"
        );

        test_vec.clear();
        test_vec.extend_from_slice("a".as_bytes());

        assert_eq!(
            SHA1::hash_slice(&test_vec),
            "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"
        );

        test_vec.clear();
        test_vec.extend_from_slice("01234567012345670123456701234567".as_bytes());

        assert_eq!(
            SHA1::hash_slice(&test_vec),
            "c729c8996ee0a6f74f4f3248e8957edf704fb624"
        );
    }
}
