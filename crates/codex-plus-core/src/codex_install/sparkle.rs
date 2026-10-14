//! Sparkle EdDSA（Ed25519）验签。
//!
//! Sparkle 用 Ed25519 对整个安装包文件签名，签名写在 appcast 的 `sparkle:edSignature` 里，
//! 公钥写在 Codex.app Info.plist 的 `SUPublicEDKey` 里。这里固定 OpenAI 的公钥：
//! 镜像或 CDN 即使被篡改，也伪造不出能通过校验的安装包。

use anyhow::{Context, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// OpenAI 的 Sparkle EdDSA 公钥：取自官方 Codex.app 的 `SUPublicEDKey`（已在真机核对）。
pub(crate) const OPENAI_SPARKLE_PUBLIC_KEY: &str = "mNfr1v9t63BfgDtlw4C8lRvSY6uMggIXABDOCi3tS6k=";

/// 用 `public_key_b64` 校验 `message` 的 Ed25519 签名。
pub(crate) fn verify(
    public_key_b64: &str,
    message: &[u8],
    signature_b64: &str,
) -> anyhow::Result<()> {
    let public_key = STANDARD
        .decode(public_key_b64.trim())
        .context("Sparkle 公钥不是合法的 base64")?;
    if public_key.len() != 32 {
        bail!("Sparkle 公钥长度应为 32 字节，实际 {}", public_key.len());
    }
    let signature = STANDARD
        .decode(signature_b64.trim())
        .context("安装包签名不是合法的 base64")?;
    if signature.len() != 64 {
        bail!("安装包签名长度应为 64 字节，实际 {}", signature.len());
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public_key)
        .verify(message, &signature)
        .map_err(|_| anyhow!("OpenAI 签名校验失败：安装包可能被篡改或下载损坏"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap()
    }

    #[test]
    fn pinned_openai_key_is_a_valid_ed25519_key() {
        let decoded = STANDARD.decode(OPENAI_SPARKLE_PUBLIC_KEY).unwrap();
        assert_eq!(decoded.len(), 32);
        // 用固定公钥校验一份伪造签名：应当是「签名不匹配」，而不是公钥格式错误。
        let error = verify(
            OPENAI_SPARKLE_PUBLIC_KEY,
            b"payload",
            &STANDARD.encode([1u8; 64]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("签名校验失败"), "{error:#}");
    }

    #[test]
    fn accepts_genuine_signature_and_rejects_tampering() {
        let key = test_key();
        let public_key = STANDARD.encode(key.public_key().as_ref());
        let message = b"codex package bytes";
        let signature = STANDARD.encode(key.sign(message).as_ref());

        assert!(verify(&public_key, message, &signature).is_ok());
        assert!(verify(&public_key, b"tampered package", &signature).is_err());
    }

    #[test]
    fn rejects_malformed_signatures() {
        let public_key = STANDARD.encode(test_key().public_key().as_ref());

        assert!(verify(&public_key, b"x", "not-base64!!").is_err());
        assert!(verify(&public_key, b"x", "aGVsbG8=").is_err());
        assert!(verify("aGVsbG8=", b"x", &STANDARD.encode([0u8; 64])).is_err());
    }
}
