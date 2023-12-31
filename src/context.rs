use super::Sha2Params;
use crate::error::{Result, Sha2Corrupted};
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
        if msg_chunk.is_empty() {
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
        let mut w = P::new_w();

        let msg_block_bytes: &[u8] = self.msg_block.as_ref();

        #[allow(clippy::needless_range_loop)]
        for t in 0..16 {
            w[t] = P::parse_word(&msg_block_bytes[(t * 4)..]);
        }

        #[allow(clippy::needless_range_loop)]
        for t in 16..P::W_LEN {
            w[t] = P::lower_sigma1(w[t - 2])
                .wrapping_add(&w[t - 7])
                .wrapping_add(&P::lower_sigma0(w[t - 15]))
                .wrapping_add(&w[t - 16])
        }

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

        #[allow(clippy::needless_range_loop)]
        for t in 0..P::W_LEN {
            temp1 = h
                .wrapping_add(&P::upper_sigma1(e))
                .wrapping_add(&Self::ch(e, f, g))
                .wrapping_add(&P::K.as_ref()[t])
                .wrapping_add(&w[t]);
            temp2 = P::upper_sigma0(a).wrapping_add(&Self::maj(a, b, c));
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

    pub fn final_bits(&mut self, msg_bits: u8, msg_bits_count: usize) -> Result<()> {
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

    fn ch(x: P::Word, y: P::Word, z: P::Word) -> P::Word {
        (x & y) ^ (!x & z)
    }

    fn maj(x: P::Word, y: P::Word, z: P::Word) -> P::Word {
        (x & (y | z)) | (y & z)
    }
}

impl<P: Sha2Params> std::default::Default for Sha2Context<P> {
    fn default() -> Self {
        Self::new()
    }
}
