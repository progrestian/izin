use izin::{Config, commands};
use tide::{
    http::headers::HeaderValue, security::CorsMiddleware, security::Origin, Body, Request,
    Response, StatusCode,
};

#[derive(Clone)]
struct State {
    users: sled::Tree,
    secret: String,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let config = Config::default();

    if config.logging {
        tide::log::start();
    }

    let database = sled::open(config.database)?;
    let users = database.open_tree(b"users")?;

    let mut app = tide::with_state(State { users, secret: config.secret });

    app.with(
        CorsMiddleware::new()
            .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
            .allow_origin(config.origins)
            .allow_credentials(false)
    );

    app.at("/").get(|mut req: Request<State>| async move {
        let state = req.state();

        if let Ok(output) = commands::token::verify(
            state.users.clone(),
            state.secret.clone(),
            req.body_json().await.unwrap_or_default()
        ) {
            if output {
                return Ok(Response::new(StatusCode::Ok));
            }
        }

        Ok(Response::new(StatusCode::Unauthorized))
    });

    app.at("/").post(|mut req: Request<State>| async move {
        let state = req.state();

        if let Ok(output) = commands::token::request(
            state.users.clone(),
            state.secret.clone(),
            req.body_json().await.unwrap_or_default()
        ) {
            if let Some(token) = output {
                let mut res = Response::new(StatusCode::Ok);
                res.set_body(Body::from_json(&token)?);
                return Ok(res);
            }
        }

        Ok(Response::new(StatusCode::Unauthorized))
    });

    app.listen(format!("127.0.0.1:{}", config.port)).await?;

    Ok(())
}

