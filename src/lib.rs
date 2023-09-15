pub mod error;
pub mod ops;

mod context;
mod params;

pub use context::Sha2Context;
pub use params::{Sha2Params, Sha2Word};

#[cfg(test)]
mod tests {
    use super::context::Sha2Context;
    use super::params::Sha256Params;
    use crate::error::Result;

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
