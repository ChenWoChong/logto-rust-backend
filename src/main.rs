use axum::{
    Json, Router,
    extract::Request,
    http::{StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    aud: String,
    iss: String,
}

async fn fetch_logto_jwks() -> Result<String, Box<dyn std::error::Error>> {
    let jwks_url = "http://localhost:3001/oidc/jwks";
    println!(" getting Logto JWKS...");
    let response = reqwest::get(jwks_url).await?.text().await?;
    Ok(response)
}

async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .filter(|header| header.starts_with("Bearer "));

    let token = match auth_header {
        Some(header) => header.trim_start_matches("Bearer "),
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let jwks_url = "http://localhost:3001/oidc/jwks";
    let jwks: serde_json::Value = reqwest::get(jwks_url).await.unwrap().json().await.unwrap();

    let header = decode_header(token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let kid = header.kid.ok_or(StatusCode::UNAUTHORIZED)?;

    let keys_array = jwks["keys"].as_array().ok_or_else(|| {
        eprintln!("JWKS keys is not an array: {:?}", jwks["keys"]);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let key = keys_array.iter().find(|k| k["kid"] == kid).ok_or_else(|| {
        eprintln!(
            "No matching kid found. Looking for: {}, available keys: {:?}",
            kid, keys_array
        );
        StatusCode::UNAUTHORIZED
    })?;
    let kty = key["kty"].as_str().unwrap_or("");

    let decoding_key = if kty == "EC" {
        let x = key["x"].as_str().unwrap();
        let y = key["y"].as_str().unwrap();
        DecodingKey::from_ec_components(x, y).map_err(|_| StatusCode::UNAUTHORIZED)?
    } else if kty == "RSA" {
        let n = key["n"].as_str().unwrap();
        let e = key["e"].as_str().unwrap();
        DecodingKey::from_rsa_components(n, e).map_err(|_| StatusCode::UNAUTHORIZED)?
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&["https://api.rust-demo.com"]);
    validation.set_issuer(&["http://localhost:3001/oidc"]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
        println!("Token verify fail: {:?}", e);
        StatusCode::UNAUTHORIZED
    })?;

    req.extensions_mut().insert(token_data.claims);
    Ok(next.run(req).await)
}

async fn protected_handler(
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
) -> impl IntoResponse {
    let response = serde_json::json!({
        "message": "Hello from Rust, your token is valid",
        "user_id": claims.sub,
        "audience": claims.aud,
    });

    Json(response)
}

#[tokio::main]
async fn main() {
    let _ = fetch_logto_jwks()
        .await
        .expect("can't connect to Logto, please sure 3001 port is start");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/data", get(protected_handler))
        .route_layer(middleware::from_fn(auth_middleware))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Rust Backend Server running at http://localhost:8080");

    axum::serve(listener, app).await.unwrap();
}
