use super::{Sha2Params, Sha2Word};
use crate::error::{Result, Sha2Corrupted};
use crate::ops::Rotr;
use num_traits::ops::wrapping::WrappingAdd;

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

        self.corrupted.into_result(())
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

    pub fn result(&mut self, dst: &mut P::Digest) -> Result<()> {
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
        word.rotr(7) ^ word.rotr(18) ^ (word >> 3)
    }

    fn lower_sigma1(word: P::Word) -> P::Word {
        word.rotr(17) ^ word.rotr(19) ^ (word >> 10)
    }

    fn ch(x: P::Word, y: P::Word, z: P::Word) -> P::Word {
        (x & y) ^ (!x & z)
    }

    fn maj(x: P::Word, y: P::Word, z: P::Word) -> P::Word {
        (x & (y | z)) | (y & z)
    }
}
