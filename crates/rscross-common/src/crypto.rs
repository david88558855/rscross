//! 加密与哈希工具：密码哈希、HMAC 签名、AES-CBC、JWT

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};

type HmacSha256 = Hmac<Sha256>;

/// 口令哈希（argon2id）
pub fn hash_password(password: &str) -> AppResult<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::msg(format!("密码哈希失败: {e}")))
}

/// 校验口令
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// SHA256 十六进制摘要
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// MD5 十六进制摘要（用于隧道标识等非安全场景）
pub fn md5_hex(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// HMAC-SHA256 十六进制签名
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// 定长比较，避免时序侧信道
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 从任意长度密钥派生固定 32 字节的 AES 密钥
fn derive_key(secret: &str) -> [u8; 32] {
    let digest = Sha256::digest(secret.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// AES-256-CBC 加密，返回 base64
pub fn aes_cbc_encrypt(plaintext: &[u8], secret: &str) -> AppResult<String> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockEncryptMut, KeyIvInit};

    type Encryptor = cbc::Encryptor<aes::Aes256>;
    let key = derive_key(secret);
    let iv_bytes = derive_key(&format!("{secret}:iv"));
    let iv = aes::cipher::generic_array::GenericArray::from_slice(&iv_bytes);

    let enc = Encryptor::new(&key.into(), iv);
    let buf = enc
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
        .map_err(|_| AppError::msg("AES 加密失败"))?;
    Ok(B64.encode(buf))
}

/// AES-256-CBC 解密，输入为 base64
pub fn aes_cbc_decrypt(ciphertext_b64: &str, secret: &str) -> AppResult<Vec<u8>> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockDecryptMut, KeyIvInit};

    type Decryptor = cbc::Decryptor<aes::Aes256>;
    let raw = B64
        .decode(ciphertext_b64)
        .map_err(|_| AppError::msg("密文 base64 解码失败"))?;
    if raw.is_empty() || raw.len() % 16 != 0 {
        return Err(AppError::msg("密文长度非法"));
    }

    let key = derive_key(secret);
    let iv_bytes = derive_key(&format!("{secret}:iv"));
    let iv = aes::cipher::generic_array::GenericArray::from_slice(&iv_bytes);

    let mut buf = raw;
    let dec = Decryptor::new(&key.into(), iv);
    dec.decrypt_padded_vec_mut::<Pkcs7>(&mut buf)
        .map_err(|_| AppError::msg("AES 解密失败：密钥不匹配或数据损坏"))
}

/// JWT 载荷
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JwtPayload {
    /// 用户编号
    pub code: String,
    /// 角色：admin / user
    pub role: String,
    /// 过期时间（秒级时间戳）
    pub exp: i64,
    /// 签发时间
    pub iat: i64,
}

/// 签发 JWT
pub fn jwt_encode(payload: &JwtPayload, secret: &str) -> AppResult<String> {
    use jsonwebtoken::{EncodingKey, Header};

    jsonwebtoken::encode(
        &Header::default(),
        payload,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::msg(format!("JWT 签发失败: {e}")))
}

/// 校验并解析 JWT
pub fn jwt_decode(token: &str, secret: &str) -> AppResult<JwtPayload> {
    use jsonwebtoken::{DecodingKey, Validation};

    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims.clear();

    jsonwebtoken::decode::<JwtPayload>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|d| d.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            AppError::Unauthorized
        }
        _ => AppError::Unauthorized,
    })
}

/// 生成一次性随机串，用于验证码/重置令牌
pub fn random_token(n_bytes: usize) -> String {
    use rand::Rng;
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill(&mut buf[..]);
    B64.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_verify() {
        let hash = hash_password("admin123").unwrap();
        assert!(verify_password("admin123", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn test_aes_roundtrip() {
        let secret = "my-secret-key";
        let plain = b"hello rscross world";
        let enc = aes_cbc_encrypt(plain, secret).unwrap();
        assert_ne!(enc, B64.encode(plain));
        let dec = aes_cbc_decrypt(&enc, secret).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_aes_wrong_key() {
        let enc = aes_cbc_encrypt(b"data", "key1").unwrap();
        assert!(aes_cbc_decrypt(&enc, "key2").is_err());
    }

    #[test]
    fn test_jwt_roundtrip() {
        let payload = JwtPayload {
            code: "u1".into(),
            role: "admin".into(),
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
        };
        let token = jwt_encode(&payload, "secret").unwrap();
        let decoded = jwt_decode(&token, "secret").unwrap();
        assert_eq!(decoded.code, "u1");
        assert_eq!(decoded.role, "admin");
    }

    #[test]
    fn test_jwt_expired() {
        let payload = JwtPayload {
            code: "u1".into(),
            role: "user".into(),
            exp: chrono::Utc::now().timestamp() - 10,
            iat: chrono::Utc::now().timestamp() - 100,
        };
        let token = jwt_encode(&payload, "secret").unwrap();
        assert!(matches!(
            jwt_decode(&token, "secret"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }
}
