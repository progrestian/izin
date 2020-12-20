use crate::{Claims, Login, Token, User};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use std::{error::Error, time::{SystemTime, UNIX_EPOCH}};

const EXPIRY_TIME: u64 = 3600; // 1 hour (in seconds)

pub fn request(users: sled::Tree, secret: String, login: Login) -> Result<Option<Token>, Box<dyn Error>> {
    let bytes = users.get(login.username.as_bytes())?;

    if bytes.is_none() {
        return Ok(None);
    }

    let user: User = bincode::deserialize(&bytes.unwrap())?;

    let check = argon2::verify_encoded(&user.hash, login.password.as_bytes());

    if check.is_err() {
        return Ok(None);
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let claim = Claims {
        expiry: EXPIRY_TIME + now,
        issued: now,
        subject: login.username,
    };

    let encoded = jsonwebtoken::encode(
        &Header::default(),
        &claim,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    let token = Token { encoded };

    Ok(Some(token))
}

pub fn verify(users: sled::Tree, secret: String, token: Token) -> Result<bool, Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let decoded = jsonwebtoken::decode::<Claims>(
        &token.encoded,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation {
            validate_exp: false,
            ..Default::default()
        },
    );

    if decoded.is_err() {
        return Ok(false);
    }

    let claims = decoded?.claims;

    let bytes = users.get(&claims.subject)?;

    if bytes.is_none() {
        return Ok(false);
    }

    let user: User = bincode::deserialize(&bytes.unwrap())?;

    if claims.expiry < now || user.updated > claims.issued {
        Ok(false)
    } else {
        Ok(true)
    }
}

