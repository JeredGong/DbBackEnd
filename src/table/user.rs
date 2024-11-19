use actix_web::{delete, get, post, put, web::{self, Json}, Error, HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
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
 *          email           character varying(256),
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
    pub fn toRole(value: i16) -> Option<Role> {
        match value {
            0 => Some(Role::Admin),
            1 => Some(Role::User),
            _ => None
        }
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
        .map_err(|_| {
            actix_web::error::ErrorUnauthorized("Only users can perform this action.")
        })?;
    
    Ok(claims)
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    username: String,
    password_hash: String,
}

#[derive(serde::Deserialize)]
struct UsersRequest {
    username: String,
    password_hash: String,
    email: String,
    role: i16,
    image: String
}

#[derive(serde::Serialize)]
struct UsersResponse {
    id: i64,
    username: String,
    email: String,
    role: i16,
    image: String
}

#[derive(serde::Deserialize)]
struct ImageRequest {
    image: String
}

#[derive(serde::Serialize)]
struct ImageResponse {
    image: String
}

#[derive(serde::Deserialize)]
struct PasswdRequest {
    passwd: String
}

#[derive(serde::Deserialize)]
struct EmailRequest {
    email: String
}

#[post("/login")]
pub async fn Login(
    pool: web::Data<PgPool>,
    usersReq: Json<LoginRequest>
) -> Result<HttpResponse, Error> {

    // Get user infomation from database
    let user = sqlx::query!("SELECT id, username, password_hash, role FROM \"user\" WHERE username = $1", &usersReq.username)
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
    
    RecordLog(user.id, &pool, format!("User Login")).await?;
    Ok(HttpResponse::Ok().body(token))
}

#[post("/register")]
pub async fn Register(
    pool: web::Data<PgPool>,
    usersReq: Json<UsersRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    // Non-administrator accounts cannot create accounts
    let claims = CheckAdmin(&request)?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to start transaction.")
    })?;

    // Insert a new user
    sqlx::query!("INSERT INTO \"user\" (username, password_hash, email, role, image) VALUES ($1, $2, $3, $4, decode($5, 'base64'))", 
        &usersReq.username, &usersReq.password_hash, &usersReq.email, &usersReq.role, &usersReq.image) 
        .execute(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorForbidden("Insert failed.")
        })?;

    let user = 
        sqlx::query!("SELECT id FROM \"user\" WHERE username = $1", &usersReq.username)
            .fetch_one(&mut transaction)
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorForbidden("Fetch user ID failed.")
            })?;
    
    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to commit transaction.")
    })?;
    
    RecordLog(claims.id, &pool, format!("(Administrator) Register user of ID {}", user.id)).await?;
    Ok(HttpResponse::Ok().body("Register success."))
}

#[get("/info")]
pub async fn GetInfo(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;
    
    let user = sqlx::query!("SELECT id, username, email, role, encode(image, 'base64') AS image FROM \"user\" WHERE id = $1", &claims.id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorForbidden("Insert failed.")
        })?;

    let userResponse: UsersResponse = UsersResponse {
        id: user.id,
        username: user.username.unwrap_or_default(),
        email: user.email.unwrap_or_default(),
        role: user.role.unwrap_or_default(),
        image: user.image.unwrap_or_default()
    };

    RecordLog(claims.id, &pool, format!("Fetch user information")).await?;
    Ok(HttpResponse::Ok().json(userResponse))
}

#[get("/image")]
pub async fn GetImage(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;
    
    let image = 
        sqlx::query!("SELECT encode(image, 'base64') AS image FROM \"user\" WHERE id = $1", claims.id)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorForbidden("Fetch image failed.")
            })?;

    let imageResponse: ImageResponse = ImageResponse {
        image: image.image.expect("Image not found")
    };

    RecordLog(claims.id, &pool, format!("Fetch image")).await?;
    Ok(HttpResponse::Ok().json(imageResponse))
}

#[put("/image")]
pub async fn ModifyImage(
    pool: web::Data<PgPool>,
    imageReq: Json<ImageRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;
    
    sqlx::query!(
        "UPDATE \"user\" SET image = decode($1, 'base64') WHERE id = $2",
        &imageReq.image,
        &claims.id
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to update user image.")
    })?;

    RecordLog(claims.id, &pool, format!("Modify image")).await?;
    Ok(HttpResponse::Ok().body("User image modified success."))
}

#[put("/password")]
pub async fn ModifyPasswd(
    pool: web::Data<PgPool>,
    passwdReq: Json<PasswdRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;
    
    sqlx::query!(
        "UPDATE \"user\" SET password_hash = $1 WHERE id = $2",
        &passwdReq.passwd,
        &claims.id
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to update user password.")
    })?;

    RecordLog(claims.id, &pool, format!("Modify password")).await?;
    Ok(HttpResponse::Ok().body("User password modified success."))
}

#[put("/email")]
pub async fn ModifyEmail(
    pool: web::Data<PgPool>,
    emailReq: Json<EmailRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;
    
    sqlx::query!(
        "UPDATE \"user\" SET email = $1 WHERE id = $2",
        &emailReq.email,
        &claims.id
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to update user email.")
    })?;

    RecordLog(claims.id, &pool, format!("Modify email")).await?;
    Ok(HttpResponse::Ok().body("User email modified success."))
}

#[delete("/cancel")]
pub async fn Cancel(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    sqlx::query!("UPDATE \"user\" SET username = NULL, password_hash = NULL, role = NULL, image = NULL WHERE id = $1", claims.id)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorForbidden("Insert failed.")
        })?;

    RecordLog(claims.id, &pool, format!("Self cancelled")).await?;
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
    
    RecordLog(claims.id, &pool, format!("(Administrator) Delete User fo ID {}", UserID)).await?;
    Ok(HttpResponse::Ok().body("Delete account success."))
}

#[get("/users")]
pub async fn Users(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let users = 
        sqlx::query!("SELECT id, username, email, role, encode(image, 'base64') AS image FROM \"user\"")
            .fetch_all(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorForbidden("Insert failed.")
            })?;

    let usersResponse: Vec<UsersResponse> = users
        .into_iter()
        .map(|user| UsersResponse {
            id: user.id,
            username: user.username.expect("Username not found."),
            role: user.role.expect("User role not found."),
            image: user.image.unwrap_or_default(),
            email: user.email.unwrap_or_default()
        }).collect();

    RecordLog(claims.id, &pool, format!("(Administrator) Request for user list")).await?;
    Ok(HttpResponse::Ok().json(usersResponse))
}
