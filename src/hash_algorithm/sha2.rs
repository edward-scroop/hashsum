// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright 2026 Edward Scroop <edward.scroop@gmail.com>

use crate::hash_algorithm::Hash;

const SHA2_SMALL_CONSTANTS: [u32; 64] = [
    0x42_8A_2F_98u32,
    0x71_37_44_91u32,
    0xB5_C0_FB_CFu32,
    0xE9_B5_DB_A5u32,
    0x39_56_C2_5Bu32,
    0x59_F1_11_F1u32,
    0x92_3F_82_A4u32,
    0xAB_1C_5E_D5u32,
    0xD8_07_AA_98u32,
    0x12_83_5B_01u32,
    0x24_31_85_BEu32,
    0x55_0C_7D_C3u32,
    0x72_BE_5D_74u32,
    0x80_DE_B1_FEu32,
    0x9B_DC_06_A7u32,
    0xC1_9B_F1_74u32,
    0xE4_9B_69_C1u32,
    0xEF_BE_47_86u32,
    0x0F_C1_9D_C6u32,
    0x24_0C_A1_CCu32,
    0x2D_E9_2C_6Fu32,
    0x4A_74_84_AAu32,
    0x5C_B0_A9_DCu32,
    0x76_F9_88_DAu32,
    0x98_3E_51_52u32,
    0xA8_31_C6_6Du32,
    0xB0_03_27_C8u32,
    0xBF_59_7F_C7u32,
    0xC6_E0_0B_F3u32,
    0xD5_A7_91_47u32,
    0x06_CA_63_51u32,
    0x14_29_29_67u32,
    0x27_B7_0A_85u32,
    0x2E_1B_21_38u32,
    0x4D_2C_6D_FCu32,
    0x53_38_0D_13u32,
    0x65_0A_73_54u32,
    0x76_6A_0A_BBu32,
    0x81_C2_C9_2Eu32,
    0x92_72_2C_85u32,
    0xA2_BF_E8_A1u32,
    0xA8_1A_66_4Bu32,
    0xC2_4B_8B_70u32,
    0xC7_6C_51_A3u32,
    0xD1_92_E8_19u32,
    0xD6_99_06_24u32,
    0xF4_0E_35_85u32,
    0x10_6A_A0_70u32,
    0x19_A4_C1_16u32,
    0x1E_37_6C_08u32,
    0x27_48_77_4Cu32,
    0x34_B0_BC_B5u32,
    0x39_1C_0C_B3u32,
    0x4E_D8_AA_4Au32,
    0x5B_9C_CA_4Fu32,
    0x68_2E_6F_F3u32,
    0x74_8F_82_EEu32,
    0x78_A5_63_6Fu32,
    0x84_C8_78_14u32,
    0x8C_C7_02_08u32,
    0x90_BE_FF_FAu32,
    0xA4_50_6C_EBu32,
    0xBE_F9_A3_F7u32,
    0xC6_71_78_F2u32,
];

const SHA2_LARGE_CONSTANTS: [u64; 80] = [
    0x42_8A_2F_98_D7_28_AE_22u64,
    0x71_37_44_91_23_EF_65_CDu64,
    0xB5_C0_FB_CF_EC_4D_3B_2Fu64,
    0xE9_B5_DB_A5_81_89_DB_BCu64,
    0x39_56_C2_5B_F3_48_B5_38u64,
    0x59_F1_11_F1_B6_05_D0_19u64,
    0x92_3F_82_A4_AF_19_4F_9Bu64,
    0xAB_1C_5E_D5_DA_6D_81_18u64,
    0xD8_07_AA_98_A3_03_02_42u64,
    0x12_83_5B_01_45_70_6F_BEu64,
    0x24_31_85_BE_4E_E4_B2_8Cu64,
    0x55_0C_7D_C3_D5_FF_B4_E2u64,
    0x72_BE_5D_74_F2_7B_89_6Fu64,
    0x80_DE_B1_FE_3B_16_96_B1u64,
    0x9B_DC_06_A7_25_C7_12_35u64,
    0xC1_9B_F1_74_CF_69_26_94u64,
    0xE4_9B_69_C1_9E_F1_4A_D2u64,
    0xEF_BE_47_86_38_4F_25_E3u64,
    0x0F_C1_9D_C6_8B_8C_D5_B5u64,
    0x24_0C_A1_CC_77_AC_9C_65u64,
    0x2D_E9_2C_6F_59_2B_02_75u64,
    0x4A_74_84_AA_6E_A6_E4_83u64,
    0x5C_B0_A9_DC_BD_41_FB_D4u64,
    0x76_F9_88_DA_83_11_53_B5u64,
    0x98_3E_51_52_EE_66_DF_ABu64,
    0xA8_31_C6_6D_2D_B4_32_10u64,
    0xB0_03_27_C8_98_FB_21_3Fu64,
    0xBF_59_7F_C7_BE_EF_0E_E4u64,
    0xC6_E0_0B_F3_3D_A8_8F_C2u64,
    0xD5_A7_91_47_93_0A_A7_25u64,
    0x06_CA_63_51_E0_03_82_6Fu64,
    0x14_29_29_67_0A_0E_6E_70u64,
    0x27_B7_0A_85_46_D2_2F_FCu64,
    0x2E_1B_21_38_5C_26_C9_26u64,
    0x4D_2C_6D_FC_5A_C4_2A_EDu64,
    0x53_38_0D_13_9D_95_B3_DFu64,
    0x65_0A_73_54_8B_AF_63_DEu64,
    0x76_6A_0A_BB_3C_77_B2_A8u64,
    0x81_C2_C9_2E_47_ED_AE_E6u64,
    0x92_72_2C_85_14_82_35_3Bu64,
    0xA2_BF_E8_A1_4C_F1_03_64u64,
    0xA8_1A_66_4B_BC_42_30_01u64,
    0xC2_4B_8B_70_D0_F8_97_91u64,
    0xC7_6C_51_A3_06_54_BE_30u64,
    0xD1_92_E8_19_D6_EF_52_18u64,
    0xD6_99_06_24_55_65_A9_10u64,
    0xF4_0E_35_85_57_71_20_2Au64,
    0x10_6A_A0_70_32_BB_D1_B8u64,
    0x19_A4_C1_16_B8_D2_D0_C8u64,
    0x1E_37_6C_08_51_41_AB_53u64,
    0x27_48_77_4C_DF_8E_EB_99u64,
    0x34_B0_BC_B5_E1_9B_48_A8u64,
    0x39_1C_0C_B3_C5_C9_5A_63u64,
    0x4E_D8_AA_4A_E3_41_8A_CBu64,
    0x5B_9C_CA_4F_77_63_E3_73u64,
    0x68_2E_6F_F3_D6_B2_B8_A3u64,
    0x74_8F_82_EE_5D_EF_B2_FCu64,
    0x78_A5_63_6F_43_17_2F_60u64,
    0x84_C8_78_14_A1_F0_AB_72u64,
    0x8C_C7_02_08_1A_64_39_ECu64,
    0x90_BE_FF_FA_23_63_1E_28u64,
    0xA4_50_6C_EB_DE_82_BD_E9u64,
    0xBE_F9_A3_F7_B2_C6_79_15u64,
    0xC6_71_78_F2_E3_72_53_2Bu64,
    0xCA_27_3E_CE_EA_26_61_9Cu64,
    0xD1_86_B8_C7_21_C0_C2_07u64,
    0xEA_DA_7D_D6_CD_E0_EB_1Eu64,
    0xF5_7D_4F_7F_EE_6E_D1_78u64,
    0x06_F0_67_AA_72_17_6F_BAu64,
    0x0A_63_7D_C5_A2_C8_98_A6u64,
    0x11_3F_98_04_BE_F9_0D_AEu64,
    0x1B_71_0B_35_13_1C_47_1Bu64,
    0x28_DB_77_F5_23_04_7D_84u64,
    0x32_CA_AB_7B_40_C7_24_93u64,
    0x3C_9E_BE_0A_15_C9_BE_BCu64,
    0x43_1D_67_C4_9C_10_0D_4Cu64,
    0x4C_C5_D4_BE_CB_3E_42_B6u64,
    0x59_7F_29_9C_FC_65_7E_2Au64,
    0x5F_CB_6F_AB_3A_D6_FA_ECu64,
    0x6C_44_19_8C_4A_47_58_17u64,
];

fn ch_u32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn ch_u64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

fn maj_u32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn maj_u64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0_u32(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn bsig0_u64(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

fn bsig1_u32(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn bsig1_u64(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

fn ssig0_u32(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3
}

fn ssig0_u64(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ x >> 7
}

fn ssig1_u32(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10
}

fn ssig1_u64(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ x >> 6
}

enum SHA2LargeType {
    SHA2_384,
    SHA2_512,
    SHA2_512_224,
    SHA2_512_256,
}

pub struct SHA224 {}
pub struct SHA256 {}
pub struct SHA512_224 {}
pub struct SHA512_256 {}
pub struct SHA384 {}
pub struct SHA512 {}

trait SHA2SmallContext {
    fn get_h0(&self) -> u32;
    fn get_h1(&self) -> u32;
    fn get_h2(&self) -> u32;
    fn get_h3(&self) -> u32;
    fn get_h4(&self) -> u32;
    fn get_h5(&self) -> u32;
    fn get_h6(&self) -> u32;
    fn get_h7(&self) -> u32;
    fn set_h0(&mut self, h0: u32);
    fn set_h1(&mut self, h1: u32);
    fn set_h2(&mut self, h2: u32);
    fn set_h3(&mut self, h3: u32);
    fn set_h4(&mut self, h4: u32);
    fn set_h5(&mut self, h5: u32);
    fn set_h6(&mut self, h6: u32);
    fn set_h7(&mut self, h7: u32);
    fn get_total_data_size_bits(&self) -> u64;
    fn add_to_total_data_size_bits(&mut self, total_data_size_bits: u64);
    fn get_non_zero_padding_required(&self) -> bool;
    fn set_non_zero_padding_required(&mut self, non_zero_padding_required: bool);
    fn get_padded(&self) -> bool;
    fn set_padded(&mut self, padded: bool);
    fn set_hash(&mut self, hash: Option<String>);
    fn must_be_truncated(&self) -> bool;
}

trait SHA2LargeContext {
    fn get_h0(&self) -> u64;
    fn get_h1(&self) -> u64;
    fn get_h2(&self) -> u64;
    fn get_h3(&self) -> u64;
    fn get_h4(&self) -> u64;
    fn get_h5(&self) -> u64;
    fn get_h6(&self) -> u64;
    fn get_h7(&self) -> u64;
    fn set_h0(&mut self, h0: u64);
    fn set_h1(&mut self, h1: u64);
    fn set_h2(&mut self, h2: u64);
    fn set_h3(&mut self, h3: u64);
    fn set_h4(&mut self, h4: u64);
    fn set_h5(&mut self, h5: u64);
    fn set_h6(&mut self, h6: u64);
    fn set_h7(&mut self, h7: u64);
    fn get_total_data_size_bits(&self) -> u128;
    fn add_to_total_data_size_bits(&mut self, total_data_size_bits: u128);
    fn get_non_zero_padding_required(&self) -> bool;
    fn set_non_zero_padding_required(&mut self, non_zero_padding_required: bool);
    fn get_padded(&self) -> bool;
    fn set_padded(&mut self, padded: bool);
    fn set_hash(&mut self, hash: Option<String>);
    fn get_sha_type(&self) -> SHA2LargeType;
}

struct SHA224Context {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
    total_data_size_bits: u64,
    non_zero_padding_required: bool,
    padded: bool,
    hash: Option<String>,
}

impl SHA2SmallContext for SHA224Context {
    fn get_h0(&self) -> u32 {
        self.h0
    }
    fn get_h1(&self) -> u32 {
        self.h1
    }
    fn get_h2(&self) -> u32 {
        self.h2
    }
    fn get_h3(&self) -> u32 {
        self.h3
    }
    fn get_h4(&self) -> u32 {
        self.h4
    }
    fn get_h5(&self) -> u32 {
        self.h5
    }
    fn get_h6(&self) -> u32 {
        self.h6
    }
    fn get_h7(&self) -> u32 {
        self.h7
    }
    fn set_h0(&mut self, h0: u32) {
        self.h0 = h0;
    }
    fn set_h1(&mut self, h1: u32) {
        self.h1 = h1;
    }
    fn set_h2(&mut self, h2: u32) {
        self.h2 = h2;
    }
    fn set_h3(&mut self, h3: u32) {
        self.h3 = h3;
    }
    fn set_h4(&mut self, h4: u32) {
        self.h4 = h4;
    }
    fn set_h5(&mut self, h5: u32) {
        self.h5 = h5;
    }
    fn set_h6(&mut self, h6: u32) {
        self.h6 = h6;
    }
    fn set_h7(&mut self, h7: u32) {
        self.h7 = h7;
    }
    fn get_total_data_size_bits(&self) -> u64 {
        self.total_data_size_bits
    }
    fn add_to_total_data_size_bits(&mut self, total_data_size_bits: u64) {
        self.total_data_size_bits += total_data_size_bits;
    }
    fn get_non_zero_padding_required(&self) -> bool {
        self.non_zero_padding_required
    }
    fn set_non_zero_padding_required(&mut self, non_zero_padding_required: bool) {
        self.non_zero_padding_required = non_zero_padding_required;
    }
    fn get_padded(&self) -> bool {
        self.padded
    }
    fn set_padded(&mut self, padded: bool) {
        self.padded = padded;
    }
    fn set_hash(&mut self, hash: Option<String>) {
        self.hash = hash;
    }
    fn must_be_truncated(&self) -> bool {
        true
    }
}

impl Default for SHA224Context {
    fn default() -> Self {
        Self {
            h0: 0xC1_05_9E_D8u32,
            h1: 0x36_7C_D5_07u32,
            h2: 0x30_70_DD_17u32,
            h3: 0xF7_0E_59_39u32,
            h4: 0xFF_C0_0B_31u32,
            h5: 0x68_58_15_11u32,
            h6: 0x64_F9_8F_A7u32,
            h7: 0xBE_FA_4F_A4u32,
            total_data_size_bits: 0,
            non_zero_padding_required: true,
            padded: false,
            hash: None,
        }
    }
}

struct SHA256Context {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
    total_data_size_bits: u64,
    non_zero_padding_required: bool,
    padded: bool,
    hash: Option<String>,
}

impl SHA2SmallContext for SHA256Context {
    fn get_h0(&self) -> u32 {
        self.h0
    }
    fn get_h1(&self) -> u32 {
        self.h1
    }
    fn get_h2(&self) -> u32 {
        self.h2
    }
    fn get_h3(&self) -> u32 {
        self.h3
    }
    fn get_h4(&self) -> u32 {
        self.h4
    }
    fn get_h5(&self) -> u32 {
        self.h5
    }
    fn get_h6(&self) -> u32 {
        self.h6
    }
    fn get_h7(&self) -> u32 {
        self.h7
    }
    fn set_h0(&mut self, h0: u32) {
        self.h0 = h0;
    }
    fn set_h1(&mut self, h1: u32) {
        self.h1 = h1;
    }
    fn set_h2(&mut self, h2: u32) {
        self.h2 = h2;
    }
    fn set_h3(&mut self, h3: u32) {
        self.h3 = h3;
    }
    fn set_h4(&mut self, h4: u32) {
        self.h4 = h4;
    }
    fn set_h5(&mut self, h5: u32) {
        self.h5 = h5;
    }
    fn set_h6(&mut self, h6: u32) {
        self.h6 = h6;
    }
    fn set_h7(&mut self, h7: u32) {
        self.h7 = h7;
    }
    fn get_total_data_size_bits(&self) -> u64 {
        self.total_data_size_bits
    }
    fn add_to_total_data_size_bits(&mut self, total_data_size_bits: u64) {
        self.total_data_size_bits += total_data_size_bits;
    }
    fn get_non_zero_padding_required(&self) -> bool {
        self.non_zero_padding_required
    }
    fn set_non_zero_padding_required(&mut self, non_zero_padding_required: bool) {
        self.non_zero_padding_required = non_zero_padding_required;
    }
    fn get_padded(&self) -> bool {
        self.padded
    }
    fn set_padded(&mut self, padded: bool) {
        self.padded = padded;
    }
    fn set_hash(&mut self, hash: Option<String>) {
        self.hash = hash;
    }
    fn must_be_truncated(&self) -> bool {
        false
    }
}

impl Default for SHA256Context {
    fn default() -> Self {
        Self {
            h0: 0x6A_09_E6_67u32,
            h1: 0xBB_67_AE_85u32,
            h2: 0x3C_6E_F3_72u32,
            h3: 0xA5_4F_F5_3Au32,
            h4: 0x51_0E_52_7Fu32,
            h5: 0x9B_05_68_8Cu32,
            h6: 0x1F_83_D9_ABu32,
            h7: 0x5B_E0_CD_19u32,
            total_data_size_bits: 0,
            non_zero_padding_required: true,
            padded: false,
            hash: None,
        }
    }
}
struct SHA384Context {
    h0: u64,
    h1: u64,
    h2: u64,
    h3: u64,
    h4: u64,
    h5: u64,
    h6: u64,
    h7: u64,
    total_data_size_bits: u128,
    non_zero_padding_required: bool,
    padded: bool,
    hash: Option<String>,
}

impl SHA2LargeContext for SHA384Context {
    fn get_h0(&self) -> u64 {
        self.h0
    }
    fn get_h1(&self) -> u64 {
        self.h1
    }
    fn get_h2(&self) -> u64 {
        self.h2
    }
    fn get_h3(&self) -> u64 {
        self.h3
    }
    fn get_h4(&self) -> u64 {
        self.h4
    }
    fn get_h5(&self) -> u64 {
        self.h5
    }
    fn get_h6(&self) -> u64 {
        self.h6
    }
    fn get_h7(&self) -> u64 {
        self.h7
    }
    fn set_h0(&mut self, h0: u64) {
        self.h0 = h0;
    }
    fn set_h1(&mut self, h1: u64) {
        self.h1 = h1;
    }
    fn set_h2(&mut self, h2: u64) {
        self.h2 = h2;
    }
    fn set_h3(&mut self, h3: u64) {
        self.h3 = h3;
    }
    fn set_h4(&mut self, h4: u64) {
        self.h4 = h4;
    }
    fn set_h5(&mut self, h5: u64) {
        self.h5 = h5;
    }
    fn set_h6(&mut self, h6: u64) {
        self.h6 = h6;
    }
    fn set_h7(&mut self, h7: u64) {
        self.h7 = h7;
    }
    fn get_total_data_size_bits(&self) -> u128 {
        self.total_data_size_bits
    }
    fn add_to_total_data_size_bits(&mut self, total_data_size_bits: u128) {
        self.total_data_size_bits += total_data_size_bits;
    }
    fn get_non_zero_padding_required(&self) -> bool {
        self.non_zero_padding_required
    }
    fn set_non_zero_padding_required(&mut self, non_zero_padding_required: bool) {
        self.non_zero_padding_required = non_zero_padding_required;
    }
    fn get_padded(&self) -> bool {
        self.padded
    }
    fn set_padded(&mut self, padded: bool) {
        self.padded = padded;
    }
    fn set_hash(&mut self, hash: Option<String>) {
        self.hash = hash;
    }
    fn get_sha_type(&self) -> SHA2LargeType {
        SHA2LargeType::SHA2_384
    }
}

impl Default for SHA384Context {
    fn default() -> Self {
        Self {
            h0: 0xCB_BB_9D_5D_C1_05_9E_D8u64,
            h1: 0x62_9A_29_2A_36_7C_D5_07u64,
            h2: 0x91_59_01_5A_30_70_DD_17u64,
            h3: 0x15_2F_EC_D8_F7_0E_59_39u64,
            h4: 0x67_33_26_67_FF_C0_0B_31u64,
            h5: 0x8E_B4_4A_87_68_58_15_11u64,
            h6: 0xDB_0C_2E_0D_64_F9_8F_A7u64,
            h7: 0x47_B5_48_1D_BE_FA_4F_A4u64,
            total_data_size_bits: 0,
            non_zero_padding_required: true,
            padded: false,
            hash: None,
        }
    }
}

struct SHA512Context {
    h0: u64,
    h1: u64,
    h2: u64,
    h3: u64,
    h4: u64,
    h5: u64,
    h6: u64,
    h7: u64,
    total_data_size_bits: u128,
    non_zero_padding_required: bool,
    padded: bool,
    hash: Option<String>,
}

impl SHA2LargeContext for SHA512Context {
    fn get_h0(&self) -> u64 {
        self.h0
    }
    fn get_h1(&self) -> u64 {
        self.h1
    }
    fn get_h2(&self) -> u64 {
        self.h2
    }
    fn get_h3(&self) -> u64 {
        self.h3
    }
    fn get_h4(&self) -> u64 {
        self.h4
    }
    fn get_h5(&self) -> u64 {
        self.h5
    }
    fn get_h6(&self) -> u64 {
        self.h6
    }
    fn get_h7(&self) -> u64 {
        self.h7
    }
    fn set_h0(&mut self, h0: u64) {
        self.h0 = h0;
    }
    fn set_h1(&mut self, h1: u64) {
        self.h1 = h1;
    }
    fn set_h2(&mut self, h2: u64) {
        self.h2 = h2;
    }
    fn set_h3(&mut self, h3: u64) {
        self.h3 = h3;
    }
    fn set_h4(&mut self, h4: u64) {
        self.h4 = h4;
    }
    fn set_h5(&mut self, h5: u64) {
        self.h5 = h5;
    }
    fn set_h6(&mut self, h6: u64) {
        self.h6 = h6;
    }
    fn set_h7(&mut self, h7: u64) {
        self.h7 = h7;
    }
    fn get_total_data_size_bits(&self) -> u128 {
        self.total_data_size_bits
    }
    fn add_to_total_data_size_bits(&mut self, total_data_size_bits: u128) {
        self.total_data_size_bits += total_data_size_bits;
    }
    fn get_non_zero_padding_required(&self) -> bool {
        self.non_zero_padding_required
    }
    fn set_non_zero_padding_required(&mut self, non_zero_padding_required: bool) {
        self.non_zero_padding_required = non_zero_padding_required;
    }
    fn get_padded(&self) -> bool {
        self.padded
    }
    fn set_padded(&mut self, padded: bool) {
        self.padded = padded;
    }
    fn set_hash(&mut self, hash: Option<String>) {
        self.hash = hash;
    }
    fn get_sha_type(&self) -> SHA2LargeType {
        SHA2LargeType::SHA2_512
    }
}

impl Default for SHA512Context {
    fn default() -> Self {
        Self {
            h0: 0x6A_09_E6_67_F3_BC_C9_08u64,
            h1: 0xBB_67_AE_85_84_CA_A7_3Bu64,
            h2: 0x3C_6E_F3_72_FE_94_F8_2Bu64,
            h3: 0xA5_4F_F5_3A_5F_1D_36_F1u64,
            h4: 0x51_0E_52_7F_AD_E6_82_D1u64,
            h5: 0x9B_05_68_8C_2B_3E_6C_1Fu64,
            h6: 0x1F_83_D9_AB_FB_41_BD_6Bu64,
            h7: 0x5B_E0_CD_19_13_7E_21_79u64,
            total_data_size_bits: 0,
            non_zero_padding_required: true,
            padded: false,
            hash: None,
        }
    }
}

struct SHA512_224Context {
    h0: u64,
    h1: u64,
    h2: u64,
    h3: u64,
    h4: u64,
    h5: u64,
    h6: u64,
    h7: u64,
    total_data_size_bits: u128,
    non_zero_padding_required: bool,
    padded: bool,
    hash: Option<String>,
}

impl SHA2LargeContext for SHA512_224Context {
    fn get_h0(&self) -> u64 {
        self.h0
    }
    fn get_h1(&self) -> u64 {
        self.h1
    }
    fn get_h2(&self) -> u64 {
        self.h2
    }
    fn get_h3(&self) -> u64 {
        self.h3
    }
    fn get_h4(&self) -> u64 {
        self.h4
    }
    fn get_h5(&self) -> u64 {
        self.h5
    }
    fn get_h6(&self) -> u64 {
        self.h6
    }
    fn get_h7(&self) -> u64 {
        self.h7
    }
    fn set_h0(&mut self, h0: u64) {
        self.h0 = h0;
    }
    fn set_h1(&mut self, h1: u64) {
        self.h1 = h1;
    }
    fn set_h2(&mut self, h2: u64) {
        self.h2 = h2;
    }
    fn set_h3(&mut self, h3: u64) {
        self.h3 = h3;
    }
    fn set_h4(&mut self, h4: u64) {
        self.h4 = h4;
    }
    fn set_h5(&mut self, h5: u64) {
        self.h5 = h5;
    }
    fn set_h6(&mut self, h6: u64) {
        self.h6 = h6;
    }
    fn set_h7(&mut self, h7: u64) {
        self.h7 = h7;
    }
    fn get_total_data_size_bits(&self) -> u128 {
        self.total_data_size_bits
    }
    fn add_to_total_data_size_bits(&mut self, total_data_size_bits: u128) {
        self.total_data_size_bits += total_data_size_bits;
    }
    fn get_non_zero_padding_required(&self) -> bool {
        self.non_zero_padding_required
    }
    fn set_non_zero_padding_required(&mut self, non_zero_padding_required: bool) {
        self.non_zero_padding_required = non_zero_padding_required;
    }
    fn get_padded(&self) -> bool {
        self.padded
    }
    fn set_padded(&mut self, padded: bool) {
        self.padded = padded;
    }
    fn set_hash(&mut self, hash: Option<String>) {
        self.hash = hash;
    }
    fn get_sha_type(&self) -> SHA2LargeType {
        SHA2LargeType::SHA2_512_224
    }
}

impl Default for SHA512_224Context {
    fn default() -> Self {
        Self {
            h0: 0x8C_3D_37_C8_19_54_4D_A2u64,
            h1: 0x73_E1_99_66_89_DC_D4_D6u64,
            h2: 0x1D_FA_B7_AE_32_FF_9C_82u64,
            h3: 0x67_9D_D5_14_58_2F_9F_CFu64,
            h4: 0x0F_6D_2B_69_7B_D4_4D_A8u64,
            h5: 0x77_E3_6F_73_04_C4_89_42u64,
            h6: 0x3F_9D_85_A8_6A_1D_36_C8u64,
            h7: 0x11_12_E6_AD_91_D6_92_A1u64,
            total_data_size_bits: 0,
            non_zero_padding_required: true,
            padded: false,
            hash: None,
        }
    }
}

struct SHA512_256Context {
    h0: u64,
    h1: u64,
    h2: u64,
    h3: u64,
    h4: u64,
    h5: u64,
    h6: u64,
    h7: u64,
    total_data_size_bits: u128,
    non_zero_padding_required: bool,
    padded: bool,
    hash: Option<String>,
}

impl SHA2LargeContext for SHA512_256Context {
    fn get_h0(&self) -> u64 {
        self.h0
    }
    fn get_h1(&self) -> u64 {
        self.h1
    }
    fn get_h2(&self) -> u64 {
        self.h2
    }
    fn get_h3(&self) -> u64 {
        self.h3
    }
    fn get_h4(&self) -> u64 {
        self.h4
    }
    fn get_h5(&self) -> u64 {
        self.h5
    }
    fn get_h6(&self) -> u64 {
        self.h6
    }
    fn get_h7(&self) -> u64 {
        self.h7
    }
    fn set_h0(&mut self, h0: u64) {
        self.h0 = h0;
    }
    fn set_h1(&mut self, h1: u64) {
        self.h1 = h1;
    }
    fn set_h2(&mut self, h2: u64) {
        self.h2 = h2;
    }
    fn set_h3(&mut self, h3: u64) {
        self.h3 = h3;
    }
    fn set_h4(&mut self, h4: u64) {
        self.h4 = h4;
    }
    fn set_h5(&mut self, h5: u64) {
        self.h5 = h5;
    }
    fn set_h6(&mut self, h6: u64) {
        self.h6 = h6;
    }
    fn set_h7(&mut self, h7: u64) {
        self.h7 = h7;
    }
    fn get_total_data_size_bits(&self) -> u128 {
        self.total_data_size_bits
    }
    fn add_to_total_data_size_bits(&mut self, total_data_size_bits: u128) {
        self.total_data_size_bits += total_data_size_bits;
    }
    fn get_non_zero_padding_required(&self) -> bool {
        self.non_zero_padding_required
    }
    fn set_non_zero_padding_required(&mut self, non_zero_padding_required: bool) {
        self.non_zero_padding_required = non_zero_padding_required;
    }
    fn get_padded(&self) -> bool {
        self.padded
    }
    fn set_padded(&mut self, padded: bool) {
        self.padded = padded;
    }
    fn set_hash(&mut self, hash: Option<String>) {
        self.hash = hash;
    }
    fn get_sha_type(&self) -> SHA2LargeType {
        SHA2LargeType::SHA2_512_256
    }
}

impl Default for SHA512_256Context {
    fn default() -> Self {
        Self {
            h0: 0x22_31_21_94_FC_2B_F7_2Cu64,
            h1: 0x9F_55_5F_A3_C8_4C_64_C2u64,
            h2: 0x23_93_B8_6B_6F_53_B1_51u64,
            h3: 0x96_38_77_19_59_40_EA_BDu64,
            h4: 0x96_28_3E_E2_A8_8E_FF_E3u64,
            h5: 0xBE_5E_1E_25_53_86_39_92u64,
            h6: 0x2B_01_99_FC_2C_85_B8_AAu64,
            h7: 0x0E_B7_2D_DC_81_C5_2C_A2u64,
            total_data_size_bits: 0,
            non_zero_padding_required: true,
            padded: false,
            hash: None,
        }
    }
}

fn private_small_hash_block<T: SHA2SmallContext>(mut context: T, original_data_block: &[u8]) -> T {
    assert!(
        original_data_block.len() <= 64,
        "Too large of an array passed to hash block. Must be 64 bytes or less."
    );

    let mut data_block = original_data_block;
    let mut temp_vec = Vec::new();

    context.add_to_total_data_size_bits((8 * original_data_block.len()) as u64);

    // Pad only is block is less than 512 bits.
    if original_data_block.len() != 64 {
        // Add padding
        let mut padding = [0x00u8; 56];
        let mut padding_bytes = 56;

        // Add non zero padding unless current block has no data / end of stream.
        if context.get_non_zero_padding_required() {
            // Add 0b10000000 to start of padding.
            padding[0] = 0x80;
        }

        // Pad to full 512 bit block and change context if next block needs to be a padding
        // block.
        if original_data_block.len() < 56 {
            padding_bytes -= original_data_block.len();
        } else {
            padding_bytes = 64 - original_data_block.len();
            context.set_non_zero_padding_required(false);
        }

        // Add original data and padding to temp vec
        temp_vec.extend_from_slice(original_data_block);
        temp_vec.extend(&padding[0..padding_bytes]);

        // Add original size of message in bits if block is last block.
        if original_data_block.len() < 56 {
            temp_vec.extend(context.get_total_data_size_bits().to_be_bytes());
            context.set_padded(true);
        }

        data_block = temp_vec.as_slice();
    }

    // Load 512 bit data block into 16 big-endian 32 bit words of an 64 word buffer.
    let mut words = [0u32; 64];
    for i in 0..16 {
        words[i] = u32::from_be_bytes([
            data_block[i * 4],
            data_block[i * 4 + 1],
            data_block[i * 4 + 2],
            data_block[i * 4 + 3],
        ]);
    }

    // Extend the 16 words into 64 words.
    for i in 16..64 {
        words[i] = ssig1_u32(words[i - 2])
            .wrapping_add(words[i - 7])
            .wrapping_add(ssig0_u32(words[i - 15]))
            .wrapping_add(words[i - 16]);
    }

    let mut a = context.get_h0();
    let mut b = context.get_h1();
    let mut c = context.get_h2();
    let mut d = context.get_h3();
    let mut e = context.get_h4();
    let mut f = context.get_h5();
    let mut g = context.get_h6();
    let mut h = context.get_h7();

    for t in 0..64 {
        let t1 = h
            .wrapping_add(bsig1_u32(e))
            .wrapping_add(ch_u32(e, f, g))
            .wrapping_add(SHA2_SMALL_CONSTANTS[t])
            .wrapping_add(words[t]);
        let t2 = bsig0_u32(a).wrapping_add(maj_u32(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    context.set_h0(a.wrapping_add(context.get_h0()));
    context.set_h1(b.wrapping_add(context.get_h1()));
    context.set_h2(c.wrapping_add(context.get_h2()));
    context.set_h3(d.wrapping_add(context.get_h3()));
    context.set_h4(e.wrapping_add(context.get_h4()));
    context.set_h5(f.wrapping_add(context.get_h5()));
    context.set_h6(g.wrapping_add(context.get_h6()));
    context.set_h7(h.wrapping_add(context.get_h7()));

    if context.get_padded() {
        // message_digest of 256 bits.
        let mut message_digest = Vec::with_capacity(32);
        message_digest.extend_from_slice(&context.get_h0().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h1().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h2().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h3().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h4().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h5().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h6().to_be_bytes());
        if !context.must_be_truncated() {
            message_digest.extend_from_slice(&context.get_h7().to_be_bytes());
        }

        let mut return_string = String::new();
        for byte in message_digest.iter() {
            return_string.push_str(&format!("{:02x}", byte));
        }
        context.set_hash(Some(return_string));
    }

    context
}

fn private_large_hash_block<T: SHA2LargeContext>(mut context: T, original_data_block: &[u8]) -> T {
    assert!(
        original_data_block.len() <= 128,
        "Too large of an array passed to hash block. Must be 128 bytes or less."
    );

    let mut data_block = original_data_block;
    let mut temp_vec = Vec::new();

    context.add_to_total_data_size_bits((8 * original_data_block.len()) as u128);

    // Pad only is block is less than 1024 bits.
    if original_data_block.len() != 128 {
        // Add padding
        let mut padding = [0x00u8; 112];
        let mut padding_bytes = 112;

        // Add non zero padding unless current block has no data / end of stream.
        if context.get_non_zero_padding_required() {
            // Add 0b10000000 to start of padding.
            padding[0] = 0x80;
        }

        // Pad to full 1024 bit block and change context if next block needs to be a padding
        // block.
        if original_data_block.len() < 112 {
            padding_bytes -= original_data_block.len();
        } else {
            padding_bytes = 128 - original_data_block.len();
            context.set_non_zero_padding_required(false);
        }

        // Add original data and padding to temp vec
        temp_vec.extend_from_slice(original_data_block);
        temp_vec.extend(&padding[0..padding_bytes]);

        // Add original size of message in bits if block is last block.
        if original_data_block.len() < 112 {
            temp_vec.extend(context.get_total_data_size_bits().to_be_bytes());
            context.set_padded(true);
        }

        data_block = temp_vec.as_slice();
    }

    // Load 1024 bit data block into 16 big-endian 64 bit words of an 80 word buffer.
    let mut words = [0u64; 80];
    for i in 0..16 {
        words[i] = u64::from_be_bytes([
            data_block[i * 8],
            data_block[i * 8 + 1],
            data_block[i * 8 + 2],
            data_block[i * 8 + 3],
            data_block[i * 8 + 4],
            data_block[i * 8 + 5],
            data_block[i * 8 + 6],
            data_block[i * 8 + 7],
        ]);
    }

    // Extend the 16 words into 80 words.
    for i in 16..80 {
        words[i] = ssig1_u64(words[i - 2])
            .wrapping_add(words[i - 7])
            .wrapping_add(ssig0_u64(words[i - 15]))
            .wrapping_add(words[i - 16]);
    }

    let mut a = context.get_h0();
    let mut b = context.get_h1();
    let mut c = context.get_h2();
    let mut d = context.get_h3();
    let mut e = context.get_h4();
    let mut f = context.get_h5();
    let mut g = context.get_h6();
    let mut h = context.get_h7();

    for t in 0..80 {
        let t1 = h
            .wrapping_add(bsig1_u64(e))
            .wrapping_add(ch_u64(e, f, g))
            .wrapping_add(SHA2_LARGE_CONSTANTS[t])
            .wrapping_add(words[t]);
        let t2 = bsig0_u64(a).wrapping_add(maj_u64(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    context.set_h0(a.wrapping_add(context.get_h0()));
    context.set_h1(b.wrapping_add(context.get_h1()));
    context.set_h2(c.wrapping_add(context.get_h2()));
    context.set_h3(d.wrapping_add(context.get_h3()));
    context.set_h4(e.wrapping_add(context.get_h4()));
    context.set_h5(f.wrapping_add(context.get_h5()));
    context.set_h6(g.wrapping_add(context.get_h6()));
    context.set_h7(h.wrapping_add(context.get_h7()));

    if context.get_padded() {
        // message_digest of 512 bits.
        let mut message_digest = Vec::with_capacity(64);
        message_digest.extend_from_slice(&context.get_h0().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h1().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h2().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h3().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h4().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h5().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h6().to_be_bytes());
        message_digest.extend_from_slice(&context.get_h7().to_be_bytes());

        match context.get_sha_type() {
            SHA2LargeType::SHA2_384 => message_digest.truncate(48),
            SHA2LargeType::SHA2_512 => (),
            SHA2LargeType::SHA2_512_224 => message_digest.truncate(28),
            SHA2LargeType::SHA2_512_256 => message_digest.truncate(32),
        }

        let mut return_string = String::new();
        for byte in message_digest.iter() {
            return_string.push_str(&format!("{:02x}", byte));
        }
        context.set_hash(Some(return_string));
    }

    context
}

impl SHA224 {
    fn hash_block(context: SHA224Context, original_data_block: &[u8]) -> SHA224Context {
        self::private_small_hash_block(context, original_data_block)
    }
}

impl Hash for SHA224 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: SHA224Context = Default::default();

        for chunk in message.chunks(64) {
            context = Self::hash_block(context, chunk);
        }

        if context.hash.is_none() {
            context = Self::hash_block(context, &[])
        }

        context
            .hash
            .expect("Hash should have always been produced.")
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: SHA224Context = Default::default();
        let mut buffer = [0u8; 64];

        loop {
            let bytes = stream.read(&mut buffer)?;
            context = Self::hash_block(context, &buffer[0..bytes]);

            if bytes < 64 {
                break;
            }
        }

        Ok(context
            .hash
            .expect("Hash should have always been produced."))
    }
}

impl SHA256 {
    fn hash_block(context: SHA256Context, original_data_block: &[u8]) -> SHA256Context {
        self::private_small_hash_block(context, original_data_block)
    }
}

impl Hash for SHA256 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: SHA256Context = Default::default();

        for chunk in message.chunks(64) {
            context = Self::hash_block(context, chunk);
        }

        if context.hash.is_none() {
            context = Self::hash_block(context, &[])
        }

        context
            .hash
            .expect("Hash should have always been produced.")
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: SHA256Context = Default::default();
        let mut buffer = [0u8; 64];

        loop {
            let bytes = stream.read(&mut buffer)?;
            context = Self::hash_block(context, &buffer[0..bytes]);

            if bytes < 64 {
                break;
            }
        }

        Ok(context
            .hash
            .expect("Hash should have always been produced."))
    }
}

impl SHA384 {
    fn hash_block(context: SHA384Context, original_data_block: &[u8]) -> SHA384Context {
        self::private_large_hash_block(context, original_data_block)
    }
}

impl Hash for SHA384 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: SHA384Context = Default::default();

        for chunk in message.chunks(128) {
            context = Self::hash_block(context, chunk);
        }

        if context.hash.is_none() {
            context = Self::hash_block(context, &[])
        }

        context
            .hash
            .expect("Hash should have always been produced.")
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: SHA384Context = Default::default();
        let mut buffer = [0u8; 128];

        loop {
            let bytes = stream.read(&mut buffer)?;
            context = Self::hash_block(context, &buffer[0..bytes]);

            if bytes < 128 {
                break;
            }
        }

        Ok(context
            .hash
            .expect("Hash should have always been produced."))
    }
}

impl SHA512 {
    fn hash_block(context: SHA512Context, original_data_block: &[u8]) -> SHA512Context {
        self::private_large_hash_block(context, original_data_block)
    }
}

impl Hash for SHA512 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: SHA512Context = Default::default();

        for chunk in message.chunks(128) {
            context = Self::hash_block(context, chunk);
        }

        if context.hash.is_none() {
            context = Self::hash_block(context, &[])
        }

        context
            .hash
            .expect("Hash should have always been produced.")
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: SHA512Context = Default::default();
        let mut buffer = [0u8; 128];

        loop {
            let bytes = stream.read(&mut buffer)?;
            context = Self::hash_block(context, &buffer[0..bytes]);

            if bytes < 128 {
                break;
            }
        }

        Ok(context
            .hash
            .expect("Hash should have always been produced."))
    }
}

impl SHA512_224 {
    fn hash_block(context: SHA512_224Context, original_data_block: &[u8]) -> SHA512_224Context {
        self::private_large_hash_block(context, original_data_block)
    }
}

impl Hash for SHA512_224 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: SHA512_224Context = Default::default();

        for chunk in message.chunks(128) {
            context = Self::hash_block(context, chunk);
        }

        if context.hash.is_none() {
            context = Self::hash_block(context, &[])
        }

        context
            .hash
            .expect("Hash should have always been produced.")
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: SHA512_224Context = Default::default();
        let mut buffer = [0u8; 128];

        loop {
            let bytes = stream.read(&mut buffer)?;
            context = Self::hash_block(context, &buffer[0..bytes]);

            if bytes < 128 {
                break;
            }
        }

        Ok(context
            .hash
            .expect("Hash should have always been produced."))
    }
}

impl SHA512_256 {
    fn hash_block(context: SHA512_256Context, original_data_block: &[u8]) -> SHA512_256Context {
        self::private_large_hash_block(context, original_data_block)
    }
}

impl Hash for SHA512_256 {
    fn hash_slice(message: &[u8]) -> String {
        let mut context: SHA512_256Context = Default::default();

        for chunk in message.chunks(128) {
            context = Self::hash_block(context, chunk);
        }

        if context.hash.is_none() {
            context = Self::hash_block(context, &[])
        }

        context
            .hash
            .expect("Hash should have always been produced.")
    }

    fn hash_stream(mut stream: impl std::io::Read) -> std::io::Result<String> {
        let mut context: SHA512_256Context = Default::default();
        let mut buffer = [0u8; 128];

        loop {
            let bytes = stream.read(&mut buffer)?;
            context = Self::hash_block(context, &buffer[0..bytes]);

            if bytes < 128 {
                break;
            }
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
    fn sha224_empty_hash() {
        assert_eq!(
            SHA224::hash_slice(&[]),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn sha256_empty_hash() {
        assert_eq!(
            SHA256::hash_slice(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha384_empty_hash() {
        assert_eq!(
            SHA384::hash_slice(&[]),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn sha512_empty_hash() {
        assert_eq!(
            SHA512::hash_slice(&[]),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha512_224_empty_hash() {
        assert_eq!(
            SHA512_224::hash_slice(&[]),
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
        );
    }

    #[test]
    fn sha512_256_empty_hash() {
        assert_eq!(
            SHA512_256::hash_slice(&[]),
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        );
    }

    #[test]
    fn sha224_rfc_hash_suite() {
        assert_eq!(
            SHA224::hash_slice("abc".as_bytes()),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );

        assert_eq!(
            SHA224::hash_slice(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes()
            ),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        );

        assert_eq!(
            SHA224::hash_slice(["a"; 1000000].concat().as_bytes()),
            "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
        );

        assert_eq!(
            SHA224::hash_slice(
                ["0123456701234567012345670123456701234567012345670123456701234567"; 10]
                    .concat()
                    .as_bytes()
            ),
            "567f69f168cd7844e65259ce658fe7aadfa25216e68eca0eb7ab8262"
        );

        assert_eq!(
            SHA224::hash_slice("\x07".as_bytes()),
            "00ecd5f138422b8ad74c9799fd826c531bad2fcabc7450bee2aa8c2a"
        );
    }

    #[test]
    fn sha256_rfc_hash_suite() {
        assert_eq!(
            SHA256::hash_slice("abc".as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        assert_eq!(
            SHA256::hash_slice(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes()
            ),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );

        assert_eq!(
            SHA256::hash_slice(["a"; 1000000].concat().as_bytes()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );

        assert_eq!(
            SHA256::hash_slice(
                ["0123456701234567012345670123456701234567012345670123456701234567"; 10]
                    .concat()
                    .as_bytes()
            ),
            "594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5"
        );

        assert_eq!(
            SHA256::hash_slice("\x19".as_bytes()),
            "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4"
        );
    }

    #[test]
    fn sha384_rfc_hash_suite() {
        assert_eq!(
            SHA384::hash_slice("abc".as_bytes()),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );

        assert_eq!(
            SHA384::hash_slice("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes()),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        );

        assert_eq!(
            SHA384::hash_slice(["a"; 1000000].concat().as_bytes()),
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
        );

        assert_eq!(
            SHA384::hash_slice(
                ["0123456701234567012345670123456701234567012345670123456701234567"; 10]
                    .concat()
                    .as_bytes()
            ),
            "2fc64a4f500ddb6828f6a3430b8dd72a368eb7f3a8322a70bc84275b9c0b3ab00d27a5cc3c2d224aa6b61a0d79fb4596"
        );
    }

    #[test]
    fn sha512_rfc_hash_suite() {
        assert_eq!(
            SHA512::hash_slice("abc".as_bytes()),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );

        assert_eq!(
            SHA512::hash_slice("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes()),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );

        assert_eq!(
            SHA512::hash_slice(["a"; 1000000].concat().as_bytes()),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        );

        assert_eq!(
            SHA512::hash_slice(
                ["0123456701234567012345670123456701234567012345670123456701234567"; 10]
                    .concat()
                    .as_bytes()
            ),
            "89d05ba632c699c31231ded4ffc127d5a894dad412c0e024db872d1abd2ba8141a0f85072a9be1e2aa04cf33c765cb510813a39cd5a84c4acaa64d3f3fb7bae9"
        );
    }

    #[test]
    fn sha512_224_rfc_hash_suite_like() {
        assert_eq!(
            SHA512_224::hash_slice("abc".as_bytes()),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
        );

        assert_eq!(
            SHA512_224::hash_slice(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes()
            ),
            "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174"
        );

        assert_eq!(
            SHA512_224::hash_slice(["a"; 1000000].concat().as_bytes()),
            "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287"
        );

        assert_eq!(
            SHA512_224::hash_slice(
                ["0123456701234567012345670123456701234567012345670123456701234567"; 10]
                    .concat()
                    .as_bytes()
            ),
            "406338c163ad81f50d6b4c9bb45240c5d706b498863404bab6b84938"
        );

        assert_eq!(
            SHA512_224::hash_slice("\x07".as_bytes()),
            "a7bbe21f5a6f088c8f8de08b72ffc4c1333a29eedd8e26755bdd97c0"
        );
    }

    #[test]
    fn sha512_256_rfc_hash_suite_like() {
        assert_eq!(
            SHA512_256::hash_slice("abc".as_bytes()),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );

        assert_eq!(
            SHA512_256::hash_slice(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes()
            ),
            "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461"
        );

        assert_eq!(
            SHA512_256::hash_slice(["a"; 1000000].concat().as_bytes()),
            "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21"
        );

        assert_eq!(
            SHA512_256::hash_slice(
                ["0123456701234567012345670123456701234567012345670123456701234567"; 10]
                    .concat()
                    .as_bytes()
            ),
            "cf78e4ba935b4d9eb91052aeddf8e2d606c590f708573693ea94be826a666ee4"
        );

        assert_eq!(
            SHA512_256::hash_slice("\x19".as_bytes()),
            "b92633716453b7b7fd33c83e5707e6c135c4a91a19d161b93307b93ba5bdf434"
        );
    }
}
