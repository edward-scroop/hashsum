use crate::hash_algorithm::Hash;

pub struct MD5 {}

impl Hash for MD5 {
    fn hash_data(message: &mut Vec<u8>) -> String {
        let file_size_bytes = message.len();
        let mut message_digest = Vec::new();
        let mut padding = [0x00_u8; 64];
        let mut padding_bytes = 56_u8;

        // Add 0b10000000 to start of padding.
        padding[0] = 0x80;

        // Cannot overflow as result will always be in range of 0 to 63
        let file_size_modulo: u8 = (file_size_bytes % 64) as u8;

        // Check if message was 440 bits or less than a multiple of 512 bits and add up to 448 bits of padding.
        if file_size_modulo < 56 {
            padding_bytes -= file_size_modulo;
        // Else message is 448 bits or larger than a multiple of 512 bits and add up to 512 bits of padding.
        } else {
            padding_bytes += 64 - file_size_modulo;
        }

        // Pad total to 64 bits less than a multiple of 512 bits.
        message.extend_from_slice(&padding[0..padding_bytes as usize]);
        // Add message size in bits as a 64 bit int to end of message.
        message.extend_from_slice(&(file_size_bytes * 8).to_le_bytes());

        // 64 constants calculated as 'Let T[i] denote the i-th element of the table, which is equal to the integer part
        // of 4294967296 times abs(sin(i)), where i is in radians.' in rfc 1321.
        let constants = [
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
        let shifts = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];

        // Initialize default values of word blocks.
        let (mut a, mut b, mut c, mut d) = (
            0x67_45_23_01_u32,
            0xEF_CD_AB_89_u32,
            0x98_BA_DC_FE_u32,
            0x10_32_54_76_u32,
        );

        let mut m = [0u32; 16];
        let mut message_index = 0;

        // Loop over 512 bits block of message.
        while message_index < message.len() {
            for word in m.iter_mut() {
                *word = (*word & 0xFFFFFF00) | message[message_index] as u32;
                *word = (*word & 0xFFFF00FF) | (message[message_index + 1] as u32) << 8;
                *word = (*word & 0xFF00FFFF) | (message[message_index + 2] as u32) << 16;
                *word = (*word & 0x00FFFFFF) | (message[message_index + 3] as u32) << 24;

                message_index += 4;
            }

            let mut temp_a = a;
            let mut temp_b = b;
            let mut temp_c = c;
            let mut temp_d = d;

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

                //f += temp_a + constants[i as usize] + m[g as usize];
                f = f
                    .overflowing_add(
                        temp_a
                            .overflowing_add(constants[i as usize].overflowing_add(m[g as usize]).0)
                            .0,
                    )
                    .0;
                temp_a = temp_d;
                temp_d = temp_c;
                temp_c = temp_b;
                //temp_b += f << rotate_left([i as usize]);
                temp_b = temp_b.overflowing_add(f.rotate_left(shifts[i as usize])).0;
            }

            a = a.overflowing_add(temp_a).0;
            b = b.overflowing_add(temp_b).0;
            c = c.overflowing_add(temp_c).0;
            d = d.overflowing_add(temp_d).0;
        }

        message_digest.extend_from_slice(&a.to_le_bytes());
        message_digest.extend_from_slice(&b.to_le_bytes());
        message_digest.extend_from_slice(&c.to_le_bytes());
        message_digest.extend_from_slice(&d.to_le_bytes());

        let mut return_string = String::new();
        for byte in message_digest.iter() {
            return_string.push_str(&format!("{:02X}", byte));
        }
        return return_string;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash() {
        let mut test_vec = Vec::new();

        assert_eq!(
            MD5::hash_data(&mut test_vec),
            "D41D8CD98F00B204E9800998ECF8427E"
        );
    }

    #[test]
    fn rfc_hash_suite() {
        let mut test_vec = Vec::new();
        test_vec.extend_from_slice("a".as_bytes());

        assert_eq!(
            MD5::hash_data(&mut test_vec),
            "0CC175B9C0F1B6A831C399E269772661"
        );

        test_vec.clear();
        test_vec.extend_from_slice("abc".as_bytes());

        assert_eq!(
            MD5::hash_data(&mut test_vec),
            "900150983CD24FB0D6963F7D28E17F72"
        );

        test_vec.clear();
        test_vec.extend_from_slice("message digest".as_bytes());

        assert_eq!(
            MD5::hash_data(&mut test_vec),
            "F96B697D7CB7938D525A2F31AAF161D0"
        );

        test_vec.clear();
        test_vec.extend_from_slice("abcdefghijklmnopqrstuvwxyz".as_bytes());

        assert_eq!(
            MD5::hash_data(&mut test_vec),
            "C3FCD3D76192E4007DFB496CCA67E13B"
        );

        test_vec.clear();
        test_vec.extend_from_slice(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
        );

        assert_eq!(
            MD5::hash_data(&mut test_vec),
            "D174AB98D277D9F5A5611C2C9F419D9F"
        );

        test_vec.clear();
        test_vec.extend_from_slice(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .as_bytes(),
        );

        assert_eq!(
            MD5::hash_data(&mut test_vec),
            "57EDF4A22BE3C955AC49DA2E2107B67A"
        );
    }
}
