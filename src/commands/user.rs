use crate::{Login, User};
use ring::{rand::{SecureRandom, SystemRandom}};
use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

const SECURITY_LENGTH: u32 = 64;

pub async fn create(users: sled::Tree, login: Login) -> Result<bool, Box<dyn Error>> {
    let mut salt = [0; SECURITY_LENGTH as usize];
    SystemRandom::new().fill(&mut salt)?;

    let config = argon2::Config {
        ad: &[],
        hash_length: SECURITY_LENGTH,
        lanes: 1,
        mem_cost: 65535,
        secret: &[],
        thread_mode: argon2::ThreadMode::Sequential,
        time_cost: 8,
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13
    };

    let hash = argon2::hash_encoded(login.password.as_bytes(), &salt, &config);

    let user = User {
        salt: salt.to_vec(),
        hash: hash.unwrap(),
        updated: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };

    let swap = users.compare_and_swap(
        login.username.as_bytes(),
        None as Option<&[u8]>,
        Some(bincode::serialize(&user)?),
    )?;

    users.flush_async().await?;

    Ok(swap.is_ok())
}

pub async fn delete(users: sled::Tree, name: String) -> Result<bool, Box<dyn Error>> {
    let user = users.remove(&name.as_bytes())?;

    users.flush_async().await?;

    Ok(user.is_some())
}

pub fn list(users: sled::Tree) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    let names = users
        .iter()
        .map(|user| vec![String::from_utf8(user.unwrap().0.to_vec()).unwrap_or_default()])
        .collect();

    Ok(names)
}

