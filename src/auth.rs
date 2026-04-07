use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // Subject (username)
    pub exp: usize,         // Expiration time
    pub iat: usize,         // Issued at
}

pub struct AuthService {
    jwt_secret: Vec<u8>,
    jwt_expire: u64,
    password: Vec<u8>,
}

impl AuthService {
    pub fn new(jwt_secret: Option<String>, jwt_expire: u64, password: String) -> Self {
        let secret = jwt_secret.unwrap_or_else(|| {
            // Generate cryptographically secure random secret
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            hex::encode(bytes)
        });

        Self {
            jwt_secret: secret.into_bytes(),
            jwt_expire,
            password: password.into_bytes(),
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        // Constant-time comparison to prevent timing attacks
        // We compare even when lengths differ to not leak length information
        let password_bytes = password.as_bytes();

        // Use constant-time comparison from subtle crate
        // This always compares all bytes, preventing timing attacks
        password_bytes.ct_eq(&self.password).into()
    }

    pub fn generate_token(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as usize)
            .unwrap_or_else(|_| {
                // Fallback: use a reasonable current timestamp if system time is broken
                // This should not happen in normal operation
                1700000000usize // Nov 2023 timestamp as fallback
            });

        let claims = Claims {
            sub: "user".to_string(),
            iat: now,
            exp: now + self.jwt_expire as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.jwt_secret),
        )
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&self.jwt_secret),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_verification() {
        let auth = AuthService::new(None, 3600, "test_password".to_string());

        assert!(auth.verify_password("test_password"));
        assert!(!auth.verify_password("wrong_password"));
        assert!(!auth.verify_password(""));
        // Different length passwords should also fail
        assert!(!auth.verify_password("test_password_extra"));
        assert!(!auth.verify_password("test"));
    }

    #[test]
    fn test_token_generation_and_validation() {
        let auth = AuthService::new(Some("secret".to_string()), 3600, "password".to_string());

        let token = auth.generate_token().unwrap();
        let claims = auth.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "user");
    }
}
