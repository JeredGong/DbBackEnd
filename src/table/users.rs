use actix_web::{ delete, get, post, web::{ self, Bytes, Json }, Error, HttpRequest, HttpResponse };
use chrono::{Duration, Utc};
use jsonwebtoken::{ decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation };
use sqlx::PgPool;

#[derive(PartialEq)]
enum Role {
    Admin,
    User
}

impl Role {

    fn toRole(value: i16) -> Option<Role> {
        match value {
            0 => Some(Role::Admin),
            1 => Some(Role::User),
            _ => None
        }
    }

    fn equal(self, value: i16) -> bool {
        Some(self) == Role::toRole(value)
    }
}

pub struct Users {
    id: i64,
    username: String,
    password_hash: String,
    role: i16,
    image: Vec<u8>
}

#[derive(serde::Deserialize)]
struct LoginReq {
    username: String,
    password_hash: String
}

#[derive(Debug, serde::Deserialize)]
struct RegisterReq {
    username: String,
    password_hash: String,
    role: i16,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    id: String,
    role: i16,
    exp: u64
}

#[post("/login")]
pub async fn Login(
    pool: web::Data<PgPool>,
    loginInfo: Json<LoginReq>
) -> Result<HttpResponse, Error> {

    // Get user infomation from database
    let user = 
        sqlx::query!("SELECT id, username, password_hash, role, image FROM \"user\" WHERE username = $1", loginInfo.username)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorNotFound("User not found.")
            })?;

    // Check whether password hash is valid
    if let Some(stored_hash) = user.password_hash {
        if loginInfo.password_hash != stored_hash {
            return Err(actix_web::error::ErrorUnauthorized("Invalid password."));
        }
    } else {
        return Err(actix_web::error::ErrorUnauthorized("Password not found."));
    }

    // Token expiration timestamp
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(30))
        .expect("Valid timestamp")
        .timestamp() as u64;

    let claims: Claims = Claims {
        id: user.id.to_string(),
        role: user.role.unwrap_or_default() as i16, 
        exp: expiration
    };

    let key = 
        std::env::var("ENCODING_KEY")
            .expect("Encoding Key undefined.");

    // Calculate token (HS256 algorithm)
    let token = 
        encode(
            &Header::default(), 
            &claims, 
            &EncodingKey::from_secret(key.as_ref())
        ).map_err(|err| {
            println!("JWT token error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to create Token.")
        })?;

    Ok(HttpResponse::Ok().json(token))
}

#[post("/register")]
pub async fn Register(
    pool: web::Data<PgPool>,
    regInfo: Json<RegisterReq>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    // Non-administrator accounts cannot create administrator accounts
    if (Role::Admin.equal(regInfo.role)) {
        if (!CheckIs(&UnwrapToken(&request)?, Role::Admin)?) { 
            return Err(actix_web::error::ErrorUnauthorized("Non-administrator accounts cannot create administrator accounts."));
        }
    }

    // Insert a new user
    sqlx::query!("INSERT INTO \"user\" (username, password_hash, role) VALUES ($1, $2, $3)", 
        &regInfo.username, &regInfo.password_hash, &regInfo.role) 
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorForbidden("Insert failed.")
        })?;

    Ok(HttpResponse::Ok().body("Register success."))
}

#[delete("/delete")]
pub async fn Delete(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = UnwrapToken(&request)?;
    sqlx::query!("DELETE FROM \"user\" WHERE id = $1", claims.id.parse::<i64>().expect("Failed to parse string to i64"))
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorForbidden("Insert failed.")
        })?;

    Ok(HttpResponse::Ok().body("Account Cancellation success."))
}

fn UnwrapToken(
    request: &HttpRequest
) -> Result<Claims, Error> {

    let key = 
        std::env::var("ENCODING_KEY")
            .expect("Encoding Key undefined.");

    let mut validation = Validation::default();

    // Decode and unwrap for claims in token
    if let Some(authorHeader) = request.headers().get("Authorization") {
        if let Ok(authorString) = authorHeader.to_str() {
            if let Some(token) = authorString.strip_prefix("Bearer ") {
                return match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(key.as_ref()), 
                    &validation
                ) {
                    Ok(data) => Ok(data.claims),
                    Err(_) => Err(actix_web::error::ErrorUnauthorized("Decode failed."))
                };
            }
        }
    }

    Err(actix_web::error::ErrorUnauthorized("Failed to fetch and parse token."))
}

fn CheckIs(
    claims: &Claims,
    roleCheck: Role
) -> Result<bool, Error> {

    match Role::toRole(claims.role) {
        Some(role) => {
            if role == roleCheck {
                Ok(true)
            } else {
                Ok(false)
            }
        },
        _ => {
            Err(actix_web::error::ErrorUnauthorized("Role invalid."))
        }
    }
}
