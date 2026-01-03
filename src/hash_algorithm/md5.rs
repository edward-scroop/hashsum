// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2025 Edward Scroop <edward.scroop@gmail.com>

use crate::hash_algorithm::Hash;

// 64 constants calculated as 'Let T[i] denote the i-th element of the table, which is equal to the integer part
// of 4294967296 times abs(sin(i)), where i is in radians.' in rfc 1321.
const CONSTANTS: [u32; 64] = [
    0xD7_6A_A4_78_u32,
    0xE8_C7_B7_56_u32,
    0x24_20_70_DB_u32,
    0xC1_BD_CE_EE_u32,
    0xF5_7C_0F_AF_u32,
    0x47_87_C6_2A_u32,
    0xA8_30_46_13_u32,
    0xFD_46_95_01_u32,
    0x69_80_98_D8_u32,
    0x8B_44_F7_AF_u32,
    0xFF_FF_5B_B1_u32,
    0x89_5C_D7_BE_u32,
    0x6B_90_11_22_u32,
    0xFD_98_71_93_u32,
    0xA6_79_43_8E_u32,
    0x49_B4_08_21_u32,
    0xF6_1E_25_62_u32,
    0xC0_40_B3_40_u32,
    0x26_5E_5A_51_u32,
    0xE9_B6_C7_AA_u32,
    0xD6_2F_10_5D_u32,
    0x02_44_14_53_u32,
    0xD8_A1_E6_81_u32,
    0xE7_D3_FB_C8_u32,
    0x21_E1_CD_E6_u32,
    0xC3_37_07_D6_u32,
    0xF4_D5_0D_87_u32,
    0x45_5A_14_ED_u32,
    0xA9_E3_E9_05_u32,
    0xFC_EF_A3_F8_u32,
    0x67_6F_02_D9_u32,
    0x8D_2A_4C_8A_u32,
    0xFF_FA_39_42_u32,
    0x87_71_F6_81_u32,
    0x6D_9D_61_22_u32,
    0xFD_E5_38_0C_u32,
    0xA4_BE_EA_44_u32,
    0x4B_DE_CF_A9_u32,
    0xF6_BB_4B_60_u32,
    0xBE_BF_BC_70_u32,
    0x28_9B_7E_C6_u32,
    0xEA_A1_27_FA_u32,
    0xD4_EF_30_85_u32,
    0x04_88_1D_05_u32,
    0xD9_D4_D0_39_u32,
    0xE6_DB_99_E5_u32,
    0x1F_A2_7C_F8_u32,
    0xC4_AC_56_65_u32,
    0xF4_29_22_44_u32,
    0x43_2A_FF_97_u32,
    0xAB_94_23_A7_u32,
    0xFC_93_A0_39_u32,
    0x65_5B_59_C3_u32,
    0x8F_0C_CC_92_u32,
    0xFF_EF_F4_7D_u32,
    0x85_84_5D_D1_u32,
    0x6F_A8_7E_4F_u32,
    0xFE_2C_E6_E0_u32,
    0xA3_01_43_14_u32,
    0x4E_08_11_A1_u32,
    0xF7_53_7E_82_u32,
    0xBD_3A_F2_35_u32,
    0x2A_D7_D2_BB_u32,
    0xEB_86_D3_91_u32,
];

// Defines number of bits to rotate for each iteration.
const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

pub struct MD5 {}

struct MD5Context {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    total_data_size_bits: u64,
    non_zero_padding_required: bool,
    padded: bool,
    hash: Option<String>,
}

impl Default for MD5Context {
    fn default() -> Self {
        MD5Context {
            a: 0x67_45_23_01_u32,
            b: 0xEF_CD_AB_89_u32,
            c: 0x98_BA_DC_FE_u32,
            d: 0x10_32_54_76_u32,
            total_data_size_bits: 0,
            non_zero_padding_required: true,
            padded: false,
            hash: None,
        }
    }
}

impl MD5 {
    fn hash_block(mut context: MD5Context, original_data_block: &[u8]) -> MD5Context {
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
                temp_vec.extend(context.total_data_size_bits.to_le_bytes());
                context.padded = true;
            }

            data_block = temp_vec.as_slice();
        }

        // Load 512 bit data block into 16 little-endian 32 bit words.
        let mut words = [0u32; 16];
        for i in 0..16 {
            words[i] = u32::from_le_bytes([
                data_block[i * 4],
                data_block[i * 4 + 1],
                data_block[i * 4 + 2],
                data_block[i * 4 + 3],
            ]);
        }

        let mut temp_a = context.a;
        let mut temp_b = context.b;
        let mut temp_c = context.c;
        let mut temp_d = context.d;

        for i in 0..64 {
            let mut f: u32;
            let g: u32;

            if i < 16 {
                f = (temp_b & temp_c) | (!temp_b & temp_d);
                g = i;
            } else if i < 32 {
                f = (temp_d & temp_b) | (!temp_d & temp_c);
                g = (5 * i + 1) % 16;
            } else if i < 48 {
                f = temp_b ^ temp_c ^ temp_d;
                g = (3 * i + 5) % 16;
            } else {
                f = temp_c ^ (temp_b | !temp_d);
                g = (7 * i) % 16;
            }

            //f += temp_a + constants[i as usize] + data_block[g as usize];
            f = f
                .wrapping_add(temp_a)
                .wrapping_add(CONSTANTS[i as usize])
                .wrapping_add(words[g as usize]);
            temp_a = temp_d;
            temp_d = temp_c;
            temp_c = temp_b;
            //temp_b += f << rotate_left(SHIFTS[i as usize]);
            temp_b = temp_b.wrapping_add(f.rotate_left(SHIFTS[i as usize]));
        }

        context.a = context.a.wrapping_add(temp_a);
        context.b = context.b.wrapping_add(temp_b);
        context.c = context.c.wrapping_add(temp_c);
        context.d = context.d.wrapping_add(temp_d);

        if context.padded {
            // message_digest of 128 bits.
            let mut message_digest = Vec::with_capacity(16);
            message_digest.extend_from_slice(&context.a.to_le_bytes());
            message_digest.extend_from_slice(&context.b.to_le_bytes());
            message_digest.extend_from_slice(&context.c.to_le_bytes());
            message_digest.extend_from_slice(&context.d.to_le_bytes());

            let mut return_string = String::new();
            for byte in message_digest.iter() {
                return_string.push_str(&format!("{:02x}", byte));
            }
            context.hash = Some(return_string);
        }

        return context;
    }
}

impl Hash for MD5 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: MD5Context = Default::default();

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
        let mut context: MD5Context = Default::default();
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
            MD5::hash_slice(&test_vec),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn rfc_hash_suite() {
        let mut test_vec = Vec::new();
        test_vec.extend_from_slice("a".as_bytes());

        assert_eq!(
            MD5::hash_slice(&test_vec),
            "0cc175b9c0f1b6a831c399e269772661"
        );

        test_vec.clear();
        test_vec.extend_from_slice("abc".as_bytes());

        assert_eq!(
            MD5::hash_slice(&test_vec),
            "900150983cd24fb0d6963f7d28e17f72"
        );

        test_vec.clear();
        test_vec.extend_from_slice("message digest".as_bytes());

        assert_eq!(
            MD5::hash_slice(&test_vec),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );

        test_vec.clear();
        test_vec.extend_from_slice("abcdefghijklmnopqrstuvwxyz".as_bytes());

        assert_eq!(
            MD5::hash_slice(&test_vec),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );

        test_vec.clear();
        test_vec.extend_from_slice(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
        );

        assert_eq!(
            MD5::hash_slice(&test_vec),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );

        test_vec.clear();
        test_vec.extend_from_slice(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
        );

        assert_eq!(
            MD5::hash_slice(&test_vec),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }
}
