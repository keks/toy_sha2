use crate::ops::Rotr;
use std::fmt::LowerHex;

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
    type MessageBlock: AsRef<[u8]> + AsMut<[u8]>;
    type Digest;
    const MSG_BLOCK_SIZE: usize;

    const HASH_LEN_BYTES: usize;
    const H0: Self::IntermediateHash;
    const K: Self::Constants;

    fn new_msg_block() -> Self::MessageBlock;
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

pub struct Sha256Params;

impl Sha2Params for Sha256Params {
    type Word = u32;

    type IntermediateHash = [u32; 8];
    type Digest = [u8; 32];

    type Constants = [u32; 64];

    type MessageBlock = [u8; 64];

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

    fn ch(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & y) ^ (!x & z)
    }

    fn maj(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y | z)) | (y & z)
    }
}
