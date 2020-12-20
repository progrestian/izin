use serde::{Deserialize, Serialize};
use std::env;

pub mod commands;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub database: String,
    pub logging: bool,
    pub origins: Vec<String>,
    pub port: u16,
    pub secret: String,
}

impl Default for Config {
    fn default() -> Self {
        let mut config = Config {
            database: String::from("/var/lib/izin/database"),
            logging: false,
            origins: vec![],
            port: 80,
            secret: String::from(""),
        };

        if let Ok(database) = env::var("IZIN_DATABASE") {
            config.database = database;
        }

        if let Ok(logging) = env::var("IZIN_LOGGING") {
            if logging == "true" {
                config.logging = true
            }
        }

        if let Ok(origins) = env::var("IZIN_ORIGINS") {
            for origin in origins.split(',') {
                config.origins.push(origin.to_string());
            }
        }

        if let Ok(port) = env::var("IZIN_PORT") {
            if let Ok(num) = port.parse() {
                config.port = num;
            }
        }

        if let Ok(secret) = env::var("IZIN_SECRET") {
            config.secret = secret;
        }

        config
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub salt: Vec<u8>,
    pub hash: String,
    pub updated: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    #[serde(rename = "exp")]
    pub expiry: u64,
    #[serde(rename = "iat")]
    pub issued: u64,
    #[serde(rename = "sub")]
    pub subject: String,
}

#[derive(Debug, Deserialize)]
pub struct Login {
    #[serde(rename = "name")]
    pub username: String,
    #[serde(rename = "pass")]
    pub password: String,
}

impl Default for Login {
    fn default() -> Self {
        Login {
            username: String::from(""),
            password: String::from(""),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    #[serde(rename = "enc")]
    pub encoded: String,
}

impl Default for Token {
    fn default() -> Self {
        Token {
            encoded: String::from(""),
        }
    }
}

