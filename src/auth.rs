use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // Subject (username)
    pub exp: usize,         // Expiration time
    pub iat: usize,         // Issued at
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthError {
    pub error: String,
}

pub struct AuthService {
    jwt_secret: Vec<u8>,
    jwt_expire: u64,
    password: String,
}

impl AuthService {
    pub fn new(jwt_secret: Option<String>, jwt_expire: u64, password: String) -> Self {
        let secret = jwt_secret.unwrap_or_else(|| {
            // Generate random secret if not provided
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};
            let state = RandomState::new();
            let mut hasher = state.build_hasher();
            hasher.write_u64(std::process::id());
            hasher.write_u64(chrono::Utc::now().timestamp_millis() as u64);
            format!("{:x}", hasher.finish())
        });
        
        Self {
            jwt_secret: secret.into_bytes(),
            jwt_expire,
            password,
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        // Constant-time comparison to prevent timing attacks
        use std::cmp::Ordering;
        let password_bytes = password.as_bytes();
        let expected_bytes = self.password.as_bytes();
        
        if password_bytes.len() != expected_bytes.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (a, b) in password_bytes.iter().zip(expected_bytes.iter()) {
            result |= a ^ b;
        }
        result == 0
    }

    pub fn generate_token(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        
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
    }

    #[test]
    fn test_token_generation_and_validation() {
        let auth = AuthService::new(Some("secret".to_string()), 3600, "password".to_string());
        
        let token = auth.generate_token().unwrap();
        let claims = auth.validate_token(&token).unwrap();
        
        assert_eq!(claims.sub, "user");
    }
}
