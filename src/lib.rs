pub mod error;
pub mod ops;

mod context;
mod params;

pub use context::Sha2Context;
pub use params::{Sha2Params, Sha2Word};

#[cfg(test)]
mod tests {
    use super::context::Sha2Context;
    use super::params::{Sha256Params, Sha512Params};
    use crate::error::Result;

    use hex_literal::hex;
    #[test]
    fn test256_empty() -> Result<()> {
        let mut ctx: Sha2Context<Sha256Params> = Sha2Context::new();
        let mut digest_out = [0u8; 32];
        let digest_exp = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        ctx.result(&mut digest_out)?;
        assert_eq!(digest_out, digest_exp);
        Ok(())
    }

    #[test]
    fn test256_singlebit() -> Result<()> {
        let mut ctx: Sha2Context<Sha256Params> = Sha2Context::new();
        let mut digest_out = [0u8; 32];

        let digest_exp = hex!("bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375");

        ctx.final_bits(0, 1)?;
        ctx.result(&mut digest_out)?;
        assert_eq!(digest_out, digest_exp);
        Ok(())
    }

    #[test]
    fn test256_singleblock() -> Result<()> {
        let mut ctx: Sha2Context<Sha256Params> = Sha2Context::new();
        let mut digest_out = [0u8; 32];

        let msg = hex!(
            "d26826db9baeaa892691b68900b96163208e806a1da077429e454fa011840951a031327e605ab82ecce2"
        );
        let digest_exp = hex!("3ac7ac6bed82fdc8cd15b746f0ee7489158192c238f371c1883c9fe90b3e2831");

        ctx.input(&msg)?;
        ctx.result(&mut digest_out)?;
        println!("{digest_out:x?}");
        assert_eq!(digest_out, digest_exp);
        Ok(())
    }

    #[test]
    fn test256_exactblock() -> Result<()> {
        let mut ctx: Sha2Context<Sha256Params> = Sha2Context::new();
        let mut digest_out = [0u8; 32];

        let msg = hex!(
            "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509"
        );
        let digest_exp = hex!("42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa");

        ctx.input(&msg)?;
        ctx.result(&mut digest_out)?;
        assert_eq!(digest_out, digest_exp);
        Ok(())
    }

    #[test]
    fn test256_multiblock() -> Result<()> {
        let mut ctx: Sha2Context<Sha256Params> = Sha2Context::new();
        let mut digest_out = [0u8; 32];

        let msg = hex!(
            "451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae086b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b85c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480858bec"
        );
        let digest_exp = hex!("3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2");

        ctx.input(&msg)?;
        ctx.result(&mut digest_out)?;
        assert_eq!(digest_out, digest_exp);
        Ok(())
    }

    #[test]
    fn test512_empty() -> Result<()> {
        let mut ctx: Sha2Context<Sha512Params> = Sha2Context::new();
        let mut digest_out = [0u8; 64];
        let digest_exp = hex!("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        ctx.result(&mut digest_out)?;
        assert_eq!(digest_out, digest_exp);
        Ok(())
    }

    #[test]
    fn test512_singlebyte() -> Result<()> {
        let mut ctx: Sha2Context<Sha512Params> = Sha2Context::new();
        let mut digest_out = [0u8; 64];

        let msg = hex!("21");
        let digest_exp = hex!("3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a");

        ctx.input(&msg)?;
        ctx.result(&mut digest_out)?;
        assert_eq!(digest_out, digest_exp);
        Ok(())
    }
}
