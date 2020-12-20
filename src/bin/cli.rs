use clap::{App, AppSettings, SubCommand};
use izin::{Config, Login, Token, commands};
use std::error::Error;

fn prompt_username() -> String {
    rprompt::prompt_reply_stdout("Username: ").unwrap_or_default()
}

fn prompt_login() -> Login {
    Login {
        username: prompt_username(),
        password: rpassword::prompt_password_stdout("Password: ").unwrap_or_default(),
    }
}

fn prompt_token() -> Token {
    Token {
        encoded: rprompt::prompt_reply_stdout("Encoded: ").unwrap_or_default()
    }
}

#[async_std::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::default();

    let database = sled::open(config.database)?;
    let users = database.open_tree(b"users")?;

    let app_matches = App::new("izin")
        .version("0.1.0")
        .author("Daniel Progrestian <progrestian@tuta.io>")
        .about("A lightweight JWT-based HTTP authentication server for personal use")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("token")
                .about("Manage tokens")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(SubCommand::with_name("request").about("Request a new token"))
                .subcommand(SubCommand::with_name("verify").about("Verify a token"))
        )
        .subcommand(
            SubCommand::with_name("user")
                .about("Manage users")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(SubCommand::with_name("create").about("Create a new user"))
                .subcommand(SubCommand::with_name("delete").about("Delete an existing user"))
                .subcommand(SubCommand::with_name("list").about("List all existing users"))
        )
        .get_matches();

    match app_matches.subcommand() {
        ("token", Some(token_matches)) => {
            match token_matches.subcommand() {
                ("request", _) => {
                    match commands::token::request(users, config.secret, prompt_login()) {
                        Ok(result) => {
                            match result {
                                Some(auth) => println!("Success!\n{}", auth.encoded),
                                None => eprintln!("Fail!\nInvalid login!")
                            }
                            Ok(())
                        }
                        Err(err) => Err(err)
                    }
                }
                ("verify", _) => {
                    match commands::token::verify(users, config.secret, prompt_token()) {
                        Ok(success) => {
                            match success {
                                true => println!("Success!"),
                                false => eprintln!("Fail!\nInvalid token!")
                            }
                            Ok(())
                        }
                        Err(err) => Err(err)
                    }
                }
                _ => unreachable!()
            }
        }
        ("user", Some(token_matches)) => {
            match token_matches.subcommand() {
                ("create", _) => {
                    match commands::user::create(users, prompt_login()).await {
                        Ok(success) => {
                            match success {
                                true => println!("Success!"),
                                false => eprintln!("Fail!\nUsername already taken!")
                            }
                            Ok(())
                        }
                        Err(err) => Err(err)
                    }
                }
                ("delete", _) => {
                    match commands::user::delete(users, prompt_username()).await {
                        Ok(success) => {
                            match success {
                                true => println!("Success!"),
                                false => eprintln!("Fail!\nUser not found!")
                            }
                            Ok(())
                        }
                        Err(err) => Err(err)
                    }
                }
                ("list", _) => {
                    match commands::user::list(users) {
                        Ok(lines) => {
                            println!("Success!\n{}", lines
                                .iter()
                                .map(|line| line.iter()
                                    .map(|cell| format!("{: <32}", cell))
                                    .collect::<Vec<String>>()
                                    .join(", ")
                                )
                                .collect::<Vec<String>>()
                                .join("\n")
                            );
                            Ok(())
                        }
                        Err(err) => Err(err)
                    }
                }
                _ => unreachable!()
            }
        }
        _ => unreachable!()
    }
}

