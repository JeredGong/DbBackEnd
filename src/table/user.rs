use actix_web::{delete, get, post, web::{self, Json}, Error, HttpRequest, HttpResponse};
use chrono::{ Duration, Utc };
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::PgPool;
use super::logs::RecordLog;

/*
 *  PostgreSQL schema 
 * 
 *      user(
 *          id              bigint PRIMARY KEY SERIAL,
 *          username        character varying(256),
 *          password_hash   character varying(512),
 *          role            smallint,
 *          image           bytea
 *      )
 */

#[derive(PartialEq)]
pub enum Role {
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

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub id: i64,
    pub role: i16,
    pub exp: u64
}

pub fn UnwrapToken(
    request: &HttpRequest
) -> Result<Claims, Error> {

    let key = 
        std::env::var("ENCODING_KEY")
            .expect("Encoding Key undefined.");

    let validation = Validation::default();

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

pub fn CheckIs(
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

pub fn CheckAdmin(request: &HttpRequest) -> Result<Claims, Error> {
    let claims = UnwrapToken(request)?;
    if !CheckIs(&claims, Role::Admin)? {
        return Err(actix_web::error::ErrorUnauthorized("Only admins can perform this action."));
    }
    Ok(claims)
}

pub fn CheckUser(request: &HttpRequest) -> Result<Claims, Error> {
    let claims = UnwrapToken(&request)
        .map_err(|err| {
            actix_web::error::ErrorUnauthorized("Only users can perform this action.")
        })?;
    
    Ok(claims)
}

#[derive(serde::Deserialize)]
struct UsersRequest {
    username: String,
    password_hash: String,
    role: i16
}

#[derive(serde::Serialize)]
struct UsersResponse {
    id: i64,
    username: String,
    role: i16
}

#[post("/login")]
pub async fn Login(
    pool: web::Data<PgPool>,
    usersReq: Json<UsersRequest>
) -> Result<HttpResponse, Error> {

    // Get user infomation from database
    let user = 
        sqlx::query!("SELECT id, username, password_hash, role, image FROM \"user\" WHERE username = $1", usersReq.username)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorNotFound("User not found.")
            })?;

    // Check whether password hash is valid
    if let Some(stored_hash) = user.password_hash {
        if usersReq.password_hash != stored_hash {
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
        id: user.id,
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
    
    RecordLog(user.id, &pool, format!("User Login"));
    Ok(HttpResponse::Ok().body(token))
}

#[post("/register")]
pub async fn Register(
    pool: web::Data<PgPool>,
    usersReq: Json<UsersRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    // Non-administrator accounts cannot create administrator accounts
    if Role::Admin.equal(usersReq.role) {
        CheckAdmin(&request)?;
    }

    // Insert a new user
    sqlx::query!("INSERT INTO \"user\" (username, password_hash, role) VALUES ($1, $2, $3)", 
        &usersReq.username, &usersReq.password_hash, &usersReq.role) 
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorForbidden("Insert failed.")
        })?;

    let user = 
        sqlx::query!("SELECT id FROM \"user\" WHERE username = $1", &usersReq.username)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorForbidden("Fetch user ID failed.")
            })?;
    
    RecordLog(user.id, &pool, format!("Registered"));
    Ok(HttpResponse::Ok().body("Register success."))
}

#[delete("/cancel")]
pub async fn Cancel(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = UnwrapToken(&request)?;
    sqlx::query!("UPDATE \"user\" SET username = NULL, password_hash = NULL, role = NULL, image = NULL WHERE id = $1", claims.id)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorForbidden("Insert failed.")
        })?;

    RecordLog(claims.id, &pool, format!("Self cancelled"));
    Ok(HttpResponse::Ok().body("Account Cancellation success."))
}

#[delete("/delete/{id}")]
pub async fn Delete(
    pool: web::Data<PgPool>,
    UserID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {
    
    let claims = CheckAdmin(&request)?;

    sqlx::query!("UPDATE \"user\" SET username = NULL, password_hash = NULL, role = NULL, image = NULL WHERE id = $1", *UserID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorForbidden("Insert failed.")
        })?;
    
    RecordLog(claims.id, &pool, format!("(Administrator) Delete User fo ID {}", UserID));
    Ok(HttpResponse::Ok().body("Delete account success."))
}

#[get("/users")]
pub async fn Users(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let users = 
        sqlx::query!("SELECT id, username, role FROM \"user\"")
            .fetch_all(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorForbidden("Insert failed.")
            })?;

    let usersResponse: Vec<UsersResponse> = 
        users.into_iter()
            .map(|user| UsersResponse{
                id: user.id,
                username: user.username.expect("Username not found."),
                role: user.role.expect("User role not found.")
            }).collect();

    RecordLog(claims.id, &pool, format!("(Administrator) Request for user list"));
    Ok(HttpResponse::Ok().json(usersResponse))
}
