use crate::ops::Rotr;
use std::{fmt::LowerHex, ops::IndexMut};

pub trait Sha2Word:
    Clone
    + std::fmt::Debug
    + Copy
    + Sized
    + LowerHex
    + std::ops::Shl<usize, Output = Self>
    + std::ops::Shr<usize, Output = Self>
    + crate::ops::Rotr<usize, Output = Self>
    + std::ops::BitAnd<Output = Self>
    + std::ops::BitOr<Output = Self>
    + std::ops::BitXor<Output = Self>
    + std::ops::Not<Output = Self>
    + num_traits::ops::wrapping::WrappingAdd
{
    const ZERO: Self;
}

pub trait Sha2Params {
    type Word: Sha2Word;

    /* I didn't want to use min_const_generics because I wanted to avoid requiring nightly, but
     * doing so would allow us to just use arrays instead of
     * - implementing Index and IndexMut
     * - having a separate constant for the length. */

    type IntermediateHash: AsMut<[Self::Word]>;
    type Constants: AsRef<[Self::Word]>;
    type Digest;
    const MSG_BLOCK_SIZE: usize;

    type MessageBlock: AsRef<[u8]> + AsMut<[u8]>;
    type W: IndexMut<usize, Output = Self::Word>;
    fn new_msg_block() -> Self::MessageBlock;
    fn new_w() -> Self::W;

    const HASH_LEN_BYTES: usize;
    const H0: Self::IntermediateHash;
    const K: Self::Constants;
    const W_LEN: usize;

    fn parse_word(src: &[u8]) -> Self::Word;
    fn write_hash(dst: &mut Self::Digest, ihash: &Self::IntermediateHash);

    fn upper_sigma0(word: Self::Word) -> Self::Word;
    fn upper_sigma1(word: Self::Word) -> Self::Word;
    fn lower_sigma0(word: Self::Word) -> Self::Word;
    fn lower_sigma1(word: Self::Word) -> Self::Word;
}

impl Sha2Word for u32 {
    const ZERO: u32 = 0u32;
}

impl Sha2Word for u64 {
    const ZERO: u64 = 0u64;
}

pub struct Sha256Params;

impl Sha2Params for Sha256Params {
    type Word = u32;

    type IntermediateHash = [u32; 8];
    type Digest = [u8; 32];
    type W = [u32; 64];

    type Constants = [u32; 64];

    type MessageBlock = [u8; 64];

    const W_LEN: usize = 64;
    const MSG_BLOCK_SIZE: usize = 64;
    const HASH_LEN_BYTES: usize = 32;

    const H0: Self::IntermediateHash = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    const K: Self::Constants = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn parse_word(src: &[u8]) -> Self::Word {
        assert!(src.len() >= 4);

        ((src[0] as u32) << 24) | ((src[1] as u32) << 16) | ((src[2] as u32) << 8) | (src[3] as u32)
    }

    fn new_msg_block() -> Self::MessageBlock {
        [0u8; 64]
    }

    fn new_w() -> Self::W {
        [0u32; 64]
    }

    fn write_hash(dst: &mut Self::Digest, ihash: &Self::IntermediateHash) {
        for i in 0..Self::HASH_LEN_BYTES {
            dst[i] = (ihash[i >> 2] >> (8 * (3 - (i & 3)))) as u8;
        }
    }

    fn upper_sigma0(word: Self::Word) -> Self::Word {
        word.rotr(2) ^ word.rotr(13) ^ word.rotr(22)
    }

    fn upper_sigma1(word: Self::Word) -> Self::Word {
        word.rotr(6) ^ word.rotr(11) ^ word.rotr(25)
    }

    fn lower_sigma0(word: Self::Word) -> Self::Word {
        word.rotr(7) ^ word.rotr(18) ^ (word >> 3)
    }

    fn lower_sigma1(word: Self::Word) -> Self::Word {
        word.rotr(17) ^ word.rotr(19) ^ (word >> 10)
    }
}

pub struct Sha512Params;

impl Sha2Params for Sha512Params {
    type Word = u64;

    type IntermediateHash = [u64; 8];
    type Digest = [u8; 64];
    type W = [u64; 80];

    type Constants = [u64; 80];

    type MessageBlock = [u8; 128];

    const W_LEN: usize = 80;
    const MSG_BLOCK_SIZE: usize = 128;
    const HASH_LEN_BYTES: usize = 64;

    const H0: Self::IntermediateHash = [
        0x6A09E667F3BCC908u64,
        0xBB67AE8584CAA73Bu64,
        0x3C6EF372FE94F82Bu64,
        0xA54FF53A5F1D36F1u64,
        0x510E527FADE682D1u64,
        0x9B05688C2B3E6C1Fu64,
        0x1F83D9ABFB41BD6Bu64,
        0x5BE0CD19137E2179u64,
    ];

    const K: Self::Constants = [
        0x428A2F98D728AE22u64,
        0x7137449123EF65CDu64,
        0xB5C0FBCFEC4D3B2Fu64,
        0xE9B5DBA58189DBBCu64,
        0x3956C25BF348B538u64,
        0x59F111F1B605D019u64,
        0x923F82A4AF194F9Bu64,
        0xAB1C5ED5DA6D8118u64,
        0xD807AA98A3030242u64,
        0x12835B0145706FBEu64,
        0x243185BE4EE4B28Cu64,
        0x550C7DC3D5FFB4E2u64,
        0x72BE5D74F27B896Fu64,
        0x80DEB1FE3B1696B1u64,
        0x9BDC06A725C71235u64,
        0xC19BF174CF692694u64,
        0xE49B69C19EF14AD2u64,
        0xEFBE4786384F25E3u64,
        0x0FC19DC68B8CD5B5u64,
        0x240CA1CC77AC9C65u64,
        0x2DE92C6F592B0275u64,
        0x4A7484AA6EA6E483u64,
        0x5CB0A9DCBD41FBD4u64,
        0x76F988DA831153B5u64,
        0x983E5152EE66DFABu64,
        0xA831C66D2DB43210u64,
        0xB00327C898FB213Fu64,
        0xBF597FC7BEEF0EE4u64,
        0xC6E00BF33DA88FC2u64,
        0xD5A79147930AA725u64,
        0x06CA6351E003826Fu64,
        0x142929670A0E6E70u64,
        0x27B70A8546D22FFCu64,
        0x2E1B21385C26C926u64,
        0x4D2C6DFC5AC42AEDu64,
        0x53380D139D95B3DFu64,
        0x650A73548BAF63DEu64,
        0x766A0ABB3C77B2A8u64,
        0x81C2C92E47EDAEE6u64,
        0x92722C851482353Bu64,
        0xA2BFE8A14CF10364u64,
        0xA81A664BBC423001u64,
        0xC24B8B70D0F89791u64,
        0xC76C51A30654BE30u64,
        0xD192E819D6EF5218u64,
        0xD69906245565A910u64,
        0xF40E35855771202Au64,
        0x106AA07032BBD1B8u64,
        0x19A4C116B8D2D0C8u64,
        0x1E376C085141AB53u64,
        0x2748774CDF8EEB99u64,
        0x34B0BCB5E19B48A8u64,
        0x391C0CB3C5C95A63u64,
        0x4ED8AA4AE3418ACBu64,
        0x5B9CCA4F7763E373u64,
        0x682E6FF3D6B2B8A3u64,
        0x748F82EE5DEFB2FCu64,
        0x78A5636F43172F60u64,
        0x84C87814A1F0AB72u64,
        0x8CC702081A6439ECu64,
        0x90BEFFFA23631E28u64,
        0xA4506CEBDE82BDE9u64,
        0xBEF9A3F7B2C67915u64,
        0xC67178F2E372532Bu64,
        0xCA273ECEEA26619Cu64,
        0xD186B8C721C0C207u64,
        0xEADA7DD6CDE0EB1Eu64,
        0xF57D4F7FEE6ED178u64,
        0x06F067AA72176FBAu64,
        0x0A637DC5A2C898A6u64,
        0x113F9804BEF90DAEu64,
        0x1B710B35131C471Bu64,
        0x28DB77F523047D84u64,
        0x32CAAB7B40C72493u64,
        0x3C9EBE0A15C9BEBCu64,
        0x431D67C49C100D4Cu64,
        0x4CC5D4BECB3E42B6u64,
        0x597F299CFC657E2Au64,
        0x5FCB6FAB3AD6FAECu64,
        0x6C44198C4A475817u64,
    ];

    fn parse_word(src: &[u8]) -> Self::Word {
        assert!(src.len() >= 8);

        ((src[0] as u64) << 56)
            | ((src[1] as u64) << 48)
            | ((src[2] as u64) << 40)
            | ((src[3] as u64) << 32)
            | ((src[4] as u64) << 24)
            | ((src[5] as u64) << 16)
            | ((src[6] as u64) << 8)
            | (src[7] as u64)
    }

    fn new_msg_block() -> Self::MessageBlock {
        [0u8; 128]
    }

    fn new_w() -> Self::W {
        [0u64; 80]
    }

    fn write_hash(dst: &mut Self::Digest, ihash: &Self::IntermediateHash) {
        for i in 0..Self::HASH_LEN_BYTES {
            dst[i] = (ihash[i >> 3] >> 8 * (7 - (i % 8))) as u8;
        }
    }

    fn upper_sigma0(word: Self::Word) -> Self::Word {
        word.rotr(28) ^ word.rotr(34) ^ word.rotr(39)
    }

    fn upper_sigma1(word: Self::Word) -> Self::Word {
        word.rotr(14) ^ word.rotr(18) ^ word.rotr(41)
    }

    fn lower_sigma0(word: Self::Word) -> Self::Word {
        word.rotr(1) ^ word.rotr(8) ^ (word >> 7)
    }

    fn lower_sigma1(word: Self::Word) -> Self::Word {
        word.rotr(19) ^ word.rotr(61) ^ (word >> 6)
    }
}
