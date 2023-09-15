use std::fmt::LowerHex;
use std::ops::Shr;

use num_traits::ops::wrapping::WrappingAdd;

#[derive(Debug, Clone, Copy)]
pub enum Sha2Corrupted {
    Success,
    BadParam,
    StateError,
}

impl Sha2Corrupted {
    fn into_result<T>(self, value: T) -> Result<T> {
        match self {
            Sha2Corrupted::Success => Ok(value),
            _ => Err(Error(self)),
        }
    }
}

#[derive(Debug)]
pub struct Error(Sha2Corrupted);

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(status) = self;

        match status {
            Sha2Corrupted::StateError => write!(f, "invalid state"),
            Sha2Corrupted::BadParam => write!(f, "bad parameter"),
            Sha2Corrupted::Success => unreachable!(),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

impl From<Sha2Corrupted> for Result<()> {
    fn from(value: Sha2Corrupted) -> Self {
        match value {
            Sha2Corrupted::Success => Ok(()),
            other => Err(Error(other)),
        }
    }
}

pub trait Rotr<Rhs = Self> {
    type Output;

    fn rotr(self, other: Rhs) -> Self::Output;
}

impl Rotr<usize> for u32 {
    type Output = u32;

    fn rotr(self, by: usize) -> u32 {
        (self >> by) | (self << (32 - by))
    }
}

pub trait Sha2Word:
    Clone
    + std::fmt::Debug
    + Copy
    + Sized
    + LowerHex
    + std::ops::Shl<usize, Output = Self>
    + std::ops::Shr<usize, Output = Self>
    + Rotr<usize, Output = Self>
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
}

pub struct Sha2Context<P: Sha2Params + ?Sized> {
    intermediate_hash: P::IntermediateHash,
    length: u128,

    msg_block_idx: usize,
    msg_block: P::MessageBlock,

    computed: bool,
    corrupted: Sha2Corrupted,
}

impl<P: Sha2Params> Sha2Context<P> {
    pub fn new() -> Self {
        Sha2Context {
            intermediate_hash: P::H0,
            length: 0,
            msg_block_idx: 0,
            computed: false,
            corrupted: Sha2Corrupted::Success,
            msg_block: P::new_msg_block(),
        }
    }

    pub fn reset(&mut self) -> Result<()> {
        self.length = 0;
        self.msg_block_idx = 0;
        self.intermediate_hash = P::H0;
        self.computed = false;
        self.corrupted = Sha2Corrupted::Success;

        self.corrupted.into()
    }

    pub fn input(&mut self, mut msg_chunk: &[u8]) -> Result<()> {
        if msg_chunk.len() == 0 {
            return Ok(());
        }

        if self.computed {
            self.corrupted = Sha2Corrupted::StateError;
        }

        self.corrupted.into_result(())?;

        while !msg_chunk.is_empty() {
            let msg_block = self.msg_block.as_mut();
            msg_block[self.msg_block_idx] = msg_chunk[0];
            self.msg_block_idx += 1;

            if let Some(new_length) = self.length.checked_add(8) {
                self.length = new_length
            } else {
                self.corrupted = Sha2Corrupted::StateError;
                break;
            }

            if self.msg_block_idx == P::MSG_BLOCK_SIZE {
                self.process_message_block()?;
            }

            msg_chunk = &msg_chunk[1..];
        }

        self.corrupted.into_result(())
    }

    pub fn process_message_block(&mut self) -> Result<()> {
        let mut w = [P::Word::ZERO; 64];

        let msg_block_bytes: &[u8] = self.msg_block.as_ref();

        println!("message block bytes: {:x?}", msg_block_bytes);

        for t in 0..16 {
            //println!("t:{t} msgblockbyte:{msg_block_bytes:#?}");
            w[t] = P::parse_word(&msg_block_bytes[(t * 4)..]);
        }

        println!("first 16 words in w:");
        println!(
            "{:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ",
            w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]
        );
        println!(
            "{:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ",
            w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]
        );

        for t in 16..64 {
            w[t] = Self::lower_sigma1(w[t - 2])
                .wrapping_add(&w[t - 7])
                .wrapping_add(&Self::lower_sigma0(w[t - 15]))
                .wrapping_add(&w[t - 16])
        }

        let v = &w[16..];

        println!("next 32 words in w:");
        println!(
            "{:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ",
            v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]
        );
        println!(
            "{:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ",
            v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]
        );
        println!(
            "{:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ",
            v[16], v[17], v[18], v[19], v[20], v[21], v[22], v[23]
        );
        println!(
            "{:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ",
            v[24], v[25], v[26], v[27], v[28], v[29], v[30], v[31]
        );

        let intermediate_hash = self.intermediate_hash.as_mut();

        let mut a = intermediate_hash[0];
        let mut b = intermediate_hash[1];
        let mut c = intermediate_hash[2];
        let mut d = intermediate_hash[3];
        let mut e = intermediate_hash[4];
        let mut f = intermediate_hash[5];
        let mut g = intermediate_hash[6];
        let mut h = intermediate_hash[7];

        let mut temp1: P::Word;
        let mut temp2: P::Word;

        for t in 0..64 {
            temp1 = h
                .wrapping_add(&Self::upper_sigma1(e))
                .wrapping_add(&Self::ch(e, f, g))
                .wrapping_add(&P::K.as_ref()[t])
                .wrapping_add(&w[t]);
            temp2 = Self::upper_sigma0(a).wrapping_add(&Self::maj(a, b, c));
            // println!("temp1: {temp1:?}");
            // println!("temp2: {temp2:?}");
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(&temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(&temp2);
        }

        intermediate_hash[0] = intermediate_hash[0].wrapping_add(&a);
        intermediate_hash[1] = intermediate_hash[1].wrapping_add(&b);
        intermediate_hash[2] = intermediate_hash[2].wrapping_add(&c);
        intermediate_hash[3] = intermediate_hash[3].wrapping_add(&d);
        intermediate_hash[4] = intermediate_hash[4].wrapping_add(&e);
        intermediate_hash[5] = intermediate_hash[5].wrapping_add(&f);
        intermediate_hash[6] = intermediate_hash[6].wrapping_add(&g);
        intermediate_hash[7] = intermediate_hash[7].wrapping_add(&h);

        self.msg_block_idx = 0;

        self.corrupted.into_result(())
    }

    const FINAL_BITS_MASKS: [u8; 8] = [0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe];
    const FINAL_BITS_MASKBIT: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x1];

    fn final_bits(&mut self, msg_bits: u8, msg_bits_count: usize) -> Result<()> {
        if msg_bits_count == 0 {
            // the RFC says to return success, but this seems more reasonable
            return self.corrupted.into_result(());
        }

        self.corrupted.into_result(())?;

        if self.computed {
            self.corrupted = Sha2Corrupted::StateError;
            return self.corrupted.into_result(());
        }

        if msg_bits_count >= 8 {
            self.corrupted = Sha2Corrupted::BadParam;
            return self.corrupted.into_result(());
        }

        if let Some(new_length) = self.length.checked_add(msg_bits_count as u128) {
            self.length = new_length
        } else {
            self.corrupted = Sha2Corrupted::StateError;
            return self.corrupted.into_result(());
        }

        self.finalize(
            (msg_bits & Self::FINAL_BITS_MASKS[msg_bits_count])
                | Self::FINAL_BITS_MASKBIT[msg_bits_count],
        )?;

        self.corrupted.into_result(())
    }

    fn finalize(&mut self, pad_byte: u8) -> Result<()> {
        self.pad_message(pad_byte)?;

        for i in 0..(P::MSG_BLOCK_SIZE) {
            self.msg_block.as_mut()[i] = 0;
        }

        self.length = 0;
        self.computed = true;

        Ok(())
    }

    fn pad_message(&mut self, pad_byte: u8) -> Result<()> {
        println!("pad byte= {pad_byte}");
        if self.msg_block_idx >= P::MSG_BLOCK_SIZE - 8 {
            self.msg_block.as_mut()[self.msg_block_idx] = pad_byte;
            self.msg_block_idx += 1;

            while self.msg_block_idx < P::MSG_BLOCK_SIZE {
                self.msg_block.as_mut()[self.msg_block_idx] = 0;
                self.msg_block_idx += 1;
            }

            self.process_message_block()?
        } else {
            self.msg_block.as_mut()[self.msg_block_idx] = pad_byte;
            self.msg_block_idx += 1;
        }

        while self.msg_block_idx < P::MSG_BLOCK_SIZE - 8 {
            self.msg_block.as_mut()[self.msg_block_idx] = 0;
            self.msg_block_idx += 1;
        }

        // TODO make this generic

        self.msg_block.as_mut()[56] = (self.length >> 56) as u8;
        self.msg_block.as_mut()[57] = (self.length >> 48) as u8;
        self.msg_block.as_mut()[58] = (self.length >> 40) as u8;
        self.msg_block.as_mut()[59] = (self.length >> 32) as u8;
        self.msg_block.as_mut()[60] = (self.length >> 24) as u8;
        self.msg_block.as_mut()[61] = (self.length >> 16) as u8;
        self.msg_block.as_mut()[62] = (self.length >> 8) as u8;
        self.msg_block.as_mut()[63] = self.length as u8;

        self.process_message_block()
    }

    fn result(&mut self, dst: &mut P::Digest) -> Result<()> {
        self.corrupted.into_result(())?;

        if !self.computed {
            self.finalize(0x80)?;
        }

        P::write_hash(dst, &self.intermediate_hash);

        Ok(())
    }

    fn upper_sigma0(word: P::Word) -> P::Word {
        word.rotr(2) ^ word.rotr(13) ^ word.rotr(22)
    }

    fn upper_sigma1(word: P::Word) -> P::Word {
        word.rotr(6) ^ word.rotr(11) ^ word.rotr(25)
    }

    fn lower_sigma0(word: P::Word) -> P::Word {
        word.rotr(7) ^ word.rotr(18) ^ word.shr(3)
    }

    fn lower_sigma1(word: P::Word) -> P::Word {
        word.rotr(17) ^ word.rotr(19) ^ word.shr(10)
    }

    fn ch(x: P::Word, y: P::Word, z: P::Word) -> P::Word {
        (x & y) ^ (!x & z)
    }

    fn maj(x: P::Word, y: P::Word, z: P::Word) -> P::Word {
        (x & (y | z)) | (y & z)
    }
}

impl Sha2Word for u32 {
    const ZERO: u32 = 0u32;
}

struct Sha256Params;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn test_singleblock() -> Result<()> {
        let mut ctx: Sha2Context<Sha256Params> = Sha2Context::new();
        let mut digest_out = [0u8; 32];

        let msg = hex!(
            "d26826db9baeaa892691b68900b96163208e806a1da077429e454fa011840951a031327e605ab82ecce2"
        );

        ctx.input(&msg)?;
        ctx.result(&mut digest_out)?;
        println!("{digest_out:x?}");
        Ok(())
    }

    #[test]
    fn test_exactblock() -> Result<()> {
        let mut ctx: Sha2Context<Sha256Params> = Sha2Context::new();
        let mut digest_out = [0u8; 32];

        let msg = hex!(
            "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509"
        );

        ctx.input(&msg)?;
        ctx.result(&mut digest_out)?;
        println!("{digest_out:x?} (got)");
        println!("42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa (exp)");
        Ok(())
    }

    #[test]
    fn test_multiblock() -> Result<()> {
        let mut ctx: Sha2Context<Sha256Params> = Sha2Context::new();
        let mut digest_out = [0u8; 32];

        let msg = hex!(
            "451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae086b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b85c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480858bec"
        );

        ctx.input(&msg)?;
        ctx.result(&mut digest_out)?;
        println!("{digest_out:x?} (got)");
        println!("3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2 (exp)");
        Ok(())
    }
}
