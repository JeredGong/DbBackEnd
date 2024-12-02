use super::docs::save_file; 
use super::logs::RecordLog; 
use actix_web::{
    delete, get, post, put,
    web::{self, Json},
    Error, HttpRequest, HttpResponse,
}; 
use chrono::{Duration, Utc}; 
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation}; 
use serde::Deserialize;  // 确保引入了 serde::Deserialize
use sqlx::PgPool; 

/*
 *  PostgreSQL schema
 *
 *      user(
 *          id              bigint PRIMARY KEY SERIAL,
 *          username        character varying(256),
 *          password_hash   character varying(512),
 *          email           character varying(256),
 *          role            smallint,
 *          image           text
 *      )
 */

#[derive(PartialEq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn toRole(value: i16) -> Option<Role> {
        match value {
            0 => Some(Role::Admin),
            1 => Some(Role::User),
            _ => None,
        }
    }
}

#[derive(serde::Serialize, Deserialize)]
pub struct Claims {
    pub id: i64,
    pub role: i16,
    pub exp: u64,
}
/**
 * retrive specified user info, admin only
 * @param pool      alias to Postgres
 * @param request   httprequest
 * @return          user info in `Result`
 */
#[get("/user/info")]
pub async fn GetInfo(pool: web::Data<PgPool>, request: HttpRequest) -> Result<HttpResponse, Error> {
    let claims = CheckUser(&pool, &request).await?; 

    let user = sqlx::query!(
        "SELECT id, username, email, role, image FROM \"user\" WHERE id = $1",
        &claims.id
    )
    .fetch_one(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorForbidden(format!("Insert failed.\nDatabase error: {}", err))
    })?; 

    let mut image_file = Vec::default(); 

    if user.image != None {
        let file_path = user.image.unwrap_or_default(); 
        image_file = tokio::fs::read(&file_path).await.map_err(|err| {
            println!("Image read error: {:?}", err); 
            actix_web::error::ErrorInternalServerError("Failed to read image file")
        })?; 
    }

    let userResponse: UsersResponse = UsersResponse {
        id: user.id,
        username: user.username.unwrap_or_default(),
        email: user.email.unwrap_or_default(),
        role: user.role.unwrap_or_default(),
        image: image_file,
    }; 

    RecordLog(claims.id, &pool, format!("Fetch user information")).await?; 
    Ok(HttpResponse::Ok().json(userResponse))
}
/**
 * retrive specified user image, admin only
 * @param pool      alias to Postgres
 * @param request   httprequest
 * @return          user image in `Result`
 */
#[get("/user/image")]
pub async fn GetUserImage(
    pool: web::Data<PgPool>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckUser(&pool, &request).await?; 

    let image = sqlx::query!("SELECT image FROM \"user\" WHERE id = $1", claims.id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err); 
            actix_web::error::ErrorForbidden(format!(
                "Fetch image failed.\nDatabase error: {}",
                err
            ))
        })?; 

    let file_path = image.image.unwrap_or_default(); 
    let image_file = tokio::fs::read(&file_path).await.map_err(|err| {
        println!("Image read error: {:?}", err); 
        actix_web::error::ErrorInternalServerError("Failed to read image file")
    })?; 

    RecordLog(claims.id, &pool, format!("Fetch self image")).await?; 
    Ok(HttpResponse::Ok()
        .content_type("application/png")
        .body(image_file))
}

#[get("/user/info/{id}")]
pub async fn GetInfoByID(
    pool: web::Data<PgPool>,
    userID: web::Path<i64>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?; 

    let user = sqlx::query!(
        "SELECT id, username, email, role, image FROM \"user\" WHERE id = $1",
        *userID
    )
    .fetch_one(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorForbidden(format!("Insert failed.\nDatabase error: {}", err))
    })?; 

    let mut image_file = Vec::default(); 

    if user.image != None {
        let file_path = user.image.unwrap_or_default(); 
        image_file = tokio::fs::read(&file_path).await.map_err(|err| {
            println!("Image read error: {:?}", err); 
            actix_web::error::ErrorInternalServerError("Failed to read image file")
        })?; 
    }

    let userResponse: UsersResponse = UsersResponse {
        id: user.id,
        username: user.username.unwrap_or_default(),
        email: user.email.unwrap_or_default(),
        role: user.role.unwrap_or_default(),
        image: image_file,
    }; 

    RecordLog(
        claims.id,
        &pool,
        format!("Fetch user information of ID {}", *userID),
    )
    .await?; 
    Ok(HttpResponse::Ok().json(userResponse))
}
/**
 * retrive specified user info, admin only
 * @param pool      alias to Postgres
 * @param userID          the specified user
 * @param request   httprequest
 * @return          specified user's image in `Result`
 */
#[get("/user/image/{id}")]
pub async fn GetImage(
    pool: web::Data<PgPool>,
    userID: web::Path<i64>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let selfID: i64 = match UnwrapToken(&pool, &request).await {
        Ok(claims) => claims.id,
        Err(_) => 0,
    }; 

    let image = sqlx::query!("SELECT image FROM \"user\" WHERE id = $1", *userID)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err); 
            actix_web::error::ErrorForbidden(format!(
                "Fetch image failed.\nDatabase error: {}",
                err
            ))
        })?; 

    let file_path = image.image.unwrap_or_default(); 
    let image_file = tokio::fs::read(&file_path).await.map_err(|err| {
        println!("Image read error: {:?}", err); 
        actix_web::error::ErrorInternalServerError("Failed to read image file")
    })?; 

    RecordLog(
        selfID,
        &pool,
        format!("Fetch image of user of ID {}", userID),
    )
    .await?; 
    Ok(HttpResponse::Ok()
        .content_type("application/png")
        .body(image_file))
}
/**
 * change avatar, user permitted
 * @param pool      alias to Postgres
 * @param imageReq  new image in Json format
 * @param request   httprequest
 * @return          success or not in `Result`
 */
#[put("/user/image")]
pub async fn ModifyImage(
    pool: web::Data<PgPool>,
    imageReq: Json<ModifyRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    // 检查用户权限
    let claims = CheckUser(&pool, &request).await?; 

    let file_path = save_file(&imageReq.image, "./uploads/avatar", "png")
        .await
        .map_err(|err| {
            println!("File save error: {:?}", err); 
            actix_web::error::ErrorInternalServerError("Failed to save image file")
        })?; 

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to start transaction.\nDatabase error: {}",
            err
        ))
    })?; 

    let old_file_path = sqlx::query!(
        "
        SELECT image FROM \"user\" WHERE id = $1",
        &claims.id
    )
    .fetch_one(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to fetch old user image path.\nDatabase error: {}",
            err
        ))
    })?
    .image
    .unwrap_or_default(); 

    // 更新用户的图像路径到数据库
    sqlx::query!(
        "UPDATE \"user\" SET image = $1 WHERE id = $2",
        &file_path,
        &claims.id
    )
    .execute(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to update user image.\nDatabase error: {}",
            err
        ))
    })?; 

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to commit transaction.\nDatabase error: {}",
            err
        ))
    })?; 

    // Delete image file (PHYSICAL)
    if !old_file_path.is_empty() {
        tokio::fs::remove_file(&old_file_path)
            .await
            .map_err(|err| {
                println!("File delete error: {:?}", err); 
                actix_web::error::ErrorInternalServerError(
                    "Failed to delete document file from storage",
                )
            })?; 
    }

    RecordLog(claims.id, &pool, "Modify image".to_string()).await?; 
    Ok(HttpResponse::Ok().body("User image modified successfully."))
}
/**
 * change password, user permitted
 * @param pool      alias to Postgres
 * @param passwdReq new password in Json format
 * @param request   httprequest
 * @return          succuess or not in `Result`
 */
#[put("/user/password")]
pub async fn ModifyPasswd(
    pool: web::Data<PgPool>,
    passwdReq: Json<PasswordRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckUser(&pool, &request).await?; 

    sqlx::query!(
        "UPDATE \"user\" SET password_hash = $1 WHERE id = $2 AND password_hash = $3",
        &passwdReq.password_hash,
        &claims.id,
        &passwdReq.old_password_hash
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to update user password.\nDatabase error: {}",
            err
        ))
    })?; 

    RecordLog(claims.id, &pool, format!("Modify password")).await?; 
    Ok(HttpResponse::Ok().body("User password modified success."))
}
/**
 * change user email, user permitted
 * @param pool      alias to Postgres
 * @param emailReq  new email in Json format
 * @param request   httprequest
 * @return          success or not in `Result`
 */
#[put("/user/email")]
pub async fn ModifyEmail(
    pool: web::Data<PgPool>,
    emailReq: Json<EmailRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckUser(&pool, &request).await?; 

    sqlx::query!(
        "UPDATE \"user\" SET email = $1 WHERE id = $2",
        &emailReq.email,
        &claims.id
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to update user email.\nDatabase error: {}",
            err
        ))
    })?; 

    RecordLog(claims.id, &pool, format!("Modify email")).await?; 
    Ok(HttpResponse::Ok().body("User email modified success."))
}
/**
 * chaneg uername, user permitted
 * @param pool      alias to Postgres
 * @usernameReq     new username in Json format
 * @param request   httprequest
 * @return          user info in `Result`
 */
#[put("/user/username")]
pub async fn ModifyUsername(
    pool: web::Data<PgPool>,
    usernameReq: Json<UsernameRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckUser(&pool, &request).await?; 

    sqlx::query!(
        "UPDATE \"user\" SET username = $1 WHERE id = $2",
        &usernameReq.username,
        &claims.id
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to update user username.\nDatabase error: {}",
            err
        ))
    })?; 

    RecordLog(claims.id, &pool, format!("Modify username")).await?; 
    Ok(HttpResponse::Ok().body("User username modified success."))
}

#[delete("/user/cancel")]
pub async fn Cancel(pool: web::Data<PgPool>, request: HttpRequest) -> Result<HttpResponse, Error> {
    let claims = CheckUser(&pool, &request).await?; 

    sqlx::query!("UPDATE \"user\" SET username = NULL, password_hash = NULL, email = NULL, role = NULL, image = NULL WHERE id = $1", claims.id)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err); 
            actix_web::error::ErrorInternalServerError(format!("Insert failed.\nDatabase error: {}", err))
        })?; 

    RecordLog(claims.id, &pool, format!("Self cancelled")).await?; 
    Ok(HttpResponse::Ok().body("Account Cancellation success."))
}

#[delete("/user/delete/{id}")]
pub async fn Delete(
    pool: web::Data<PgPool>,
    UserID: web::Path<i64>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?; 

    sqlx::query!("UPDATE \"user\" SET username = NULL, password_hash = NULL, email = NULL, role = NULL, image = NULL WHERE id = $1", *UserID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err); 
            actix_web::error::ErrorInternalServerError(format!("Insert failed.\nDatabase error: {}", err))
        })?; 

    RecordLog(
        claims.id,
        &pool,
        format!("(Administrator) Delete User fo ID {}", UserID),
    )
    .await?; 
    Ok(HttpResponse::Ok().body("Delete account success."))
}

#[get("/user/all")]
pub async fn Users(pool: web::Data<PgPool>, request: HttpRequest) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?; 

    let mut transaction = pool.begin().await.map(|t| t).map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to start transaction.\nDatabase error: {}",
            err
        ))
    })?; 

    let users =
        sqlx::query!("SELECT id, username, email, role FROM \"user\" WHERE username IS NOT NULL")
            .fetch_all(&mut transaction)
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err); 
                actix_web::error::ErrorForbidden(format!("Insert failed.\nDatabase error: {}", err))
            })?; 

    let usersResponse: Vec<UsersResponse> = users
        .into_iter()
        .map(|user| UsersResponse {
            id: user.id,
            username: user.username.unwrap_or_default(),
            role: user.role.unwrap_or_default(),
            image: Vec::default(),
            email: user.email.unwrap_or_default(),
        })
        .collect(); 

    RecordLog(
        claims.id,
        &pool,
        format!("(Administrator) Request for user list"),
    )
    .await?; 
    Ok(HttpResponse::Ok().json(usersResponse))
}

#[post("/user/upgrade/{id}")]
pub async fn Upgrade(
    pool: web::Data<PgPool>,
    userID: web::Path<i64>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?; 

    sqlx::query!("UPDATE \"user\" SET role = $1 WHERE id = $2", 0, *userID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err); 
            actix_web::error::ErrorInternalServerError(format!(
                "Upgrade user failed.\nDatabase error: {}",
                err
            ))
        })?; 

    RecordLog(
        claims.id,
        &pool,
        format!("(Administrator) Upgrade user of ID {}", *userID),
    )
    .await?; 
    Ok(HttpResponse::Ok().body("Upgrade user successfully."))
}

#[post("/user/register")]
pub async fn Register(
    pool: web::Data<PgPool>,
    usersReq: Json<UsersRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    // 检查管理员权限
    let claims = CheckAdmin(&pool, &request).await?; 

    let file_path = save_file(&usersReq.image, "./uploads/avatar", "png")
        .await
        .map_err(|err| {
            println!("File save error: {:?}", err); 
            actix_web::error::ErrorInternalServerError("Failed to save image file")
        })?; 

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to start transaction.\nDatabase error: {}",
            err
        ))
    })?; 

    // 插入新用户
    sqlx::query!(
        "INSERT INTO \"user\" (username, password_hash, email, role, image) VALUES ($1, $2, $3, $4, $5)",
        &usersReq.username,
        &usersReq.password_hash,
        &usersReq.email,
        &usersReq.role,
        &file_path
    )
    .execute(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!("Insert failed.\nDatabase error: {}", err))
    })?; 

    let user = sqlx::query!(
        "SELECT id FROM \"user\" WHERE username = $1",
        &usersReq.username
    )
    .fetch_one(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorForbidden(format!("Fetch user ID failed.\nDatabase error: {}", err))
    })?; 

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to commit transaction.\nDatabase error: {}",
            err
        ))
    })?; 

    // 记录日志
    RecordLog(
        claims.id,
        &pool,
        format!("(Administrator) Registered user with ID {}", user.id),
    )
    .await?; 

    Ok(HttpResponse::Ok().body("Register success."))
}

// Endpoint for downgrading a user's role (only admins can downgrade others)
#[post("/user/dngrade/{id}")]
pub async fn Dngrade(
    pool: web::Data<PgPool>, // Database pool for database interaction
    userID: web::Path<i64>, // Path parameter for the user ID to downgrade
    request: HttpRequest, // HTTP request containing authentication info
) -> Result<HttpResponse, Error> {
    // Check if the user making the request is an admin
    let claims = CheckAdmin(&pool, &request).await?; 

    // Prevent admins from downgrading their own role
    if claims.id == *userID {
        return Err(actix_web::error::ErrorForbidden(
            "Administrators cannot self-dngrade.",
        )); 
    }

    // Update the role of the user to a lower role (role 1 is likely "user")
    sqlx::query!("UPDATE \"user\" SET role = $1 WHERE id = $2", 1, *userID)
        .execute(pool.get_ref()) // Execute the update query
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err); 
            // Return an internal server error if the query fails
            actix_web::error::ErrorInternalServerError(format!(
                "Degrade user failed.\nDatabase error: {}",
                err
            ))
        })?; 

    // Log the downgrade action by the administrator
    RecordLog(
        claims.id,
        &pool,
        format!("(Administrator) Dngrade user of ID {}", *userID),
    )
    .await?; 
    
    // Return a success response
    Ok(HttpResponse::Ok().body("Dngrade user successfully."))
}

// Helper function to unwrap the token and return claims
pub async fn UnwrapToken(pool: &PgPool, request: &HttpRequest) -> Result<Claims, Error> {
    // Retrieve the secret key for decoding the token from the environment
    let key = std::env::var("ENCODING_KEY").unwrap_or_default(); 

    let validation = Validation::default(); 

    // Check if the Authorization header is present in the request
    if let Some(authorHeader) = request.headers().get("Authorization") {
        if let Ok(authorString) = authorHeader.to_str() {
            if let Some(token) = authorString.strip_prefix("Bearer ") {
                return match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(key.as_ref()), // Decode the token with the secret key
                    &validation,
                ) {
                    Ok(data) => {
                        let claims: Claims = data.claims; 
                        // Verify that the role in the token matches the role in the database
                        let role =
                            sqlx::query!("SELECT role FROM \"user\" WHERE id = $1", &claims.id)
                                .fetch_one(pool)
                                .await
                                .map_err(|err| {
                                    println!("Database error: {:?}", err); 
                                    // Return an error if the user is not found in the database
                                    actix_web::error::ErrorNotFound(format!(
                                        "User not found.\nDatabase error: {}",
                                        err
                                    ))
                                })?; 
                        if claims.role == role.role.unwrap_or_default() {
                            Ok(claims) // Return the claims if the role matches
                        } else {
                            Err(actix_web::error::ErrorUnauthorized(
                                "User role unmatched with database. Please re-login.",
                            ))
                        }
                    }
                    Err(err) => {
                        println!("Decode error: {:?}", err); 
                        // Return an error if the token is invalid or decoding fails
                        Err(actix_web::error::ErrorBadRequest(format!(
                            "Decode failed.\nDecode error: {}",
                            err
                        )))
                    }
                }; 
            }
        }
    }

    // Return an error if the Authorization header is missing or malformed
    Err(actix_web::error::ErrorBadRequest(
        "Failed to fetch and parse token.",
    ))
}

// Check if the request is made by an admin user
pub async fn CheckAdmin(pool: &PgPool, request: &HttpRequest) -> Result<Claims, Error> {
    let claims = UnwrapToken(pool, request).await?; 
    if !CheckIs(&claims, Role::Admin)? {
        // Return an error if the user is not an admin
        return Err(actix_web::error::ErrorUnauthorized(
            "Only admins can perform this action.",
        )); 
    }
    Ok(claims) // Return claims if the user is an admin
}

// Helper function to check if the user has the specified role
pub fn CheckIs(claims: &Claims, roleCheck: Role) -> Result<bool, Error> {
    match Role::toRole(claims.role) {
        Some(role) => {
            if role == roleCheck {
                Ok(true) // Return true if the role matches
            } else {
                Ok(false) // Return false if the role doesn't match
            }
        }
        _ => Err(actix_web::error::ErrorUnauthorized("Role invalid.")), // Return an error if the role is invalid
    }
}

// Check if the request is made by a regular user
pub async fn CheckUser(pool: &PgPool, request: &HttpRequest) -> Result<Claims, Error> {
    let claims = UnwrapToken(pool, &request)
        .await
        .map_err(|_| actix_web::error::ErrorUnauthorized("Only users can perform this action."))?; 
    Ok(claims) // Return claims for a regular user
}

// Struct for user login request
#[derive(serde::Deserialize)]
struct LoginRequest {
    username: String,
    password_hash: String,
}

// Struct for user creation or modification request
#[derive(serde::Deserialize)]
struct UsersRequest {
    username: String,
    password_hash: String,
    email: String,
    role: i16,
    image: Vec<u8>, // Store the image as binary data (Vec<u8>)
}

// Struct for user information response
#[derive(serde::Serialize)]
struct UsersResponse {
    id: i64,
    username: String,
    email: String,
    role: i16,
    image: Vec<u8>,
}

// Struct for modifying a user's image
#[derive(serde::Deserialize)]
struct ModifyRequest {
    image: Vec<u8>, // New image as binary data
}

// Struct for changing user password
#[derive(serde::Deserialize)]
struct PasswordRequest {
    old_password_hash: String,
    password_hash: String,
}

// Struct for updating user email
#[derive(serde::Deserialize)]
struct EmailRequest {
    email: String,
}

// Struct for updating username
#[derive(serde::Deserialize)]
struct UsernameRequest {
    username: String,
}

// Endpoint for user login (authentication)
#[post("/user/login")]
pub async fn Login(
    pool: web::Data<PgPool>, // Database pool for fetching user data
    usersReq: Json<LoginRequest>, // JSON body containing login request data
) -> Result<HttpResponse, Error> {
    // Fetch user information from the database based on the provided username
    let user = sqlx::query!(
        "SELECT id, username, password_hash, role FROM \"user\" WHERE username = $1",
        &usersReq.username
    )
    .fetch_one(pool.get_ref()) // Execute query
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        // Return an error if the user is not found in the database
        actix_web::error::ErrorNotFound(format!("User not found.\nDatabase error: {}", err))
    })?; 

    // Check if the provided password matches the stored password hash
    if let Some(stored_hash) = user.password_hash {
        if usersReq.password_hash != stored_hash {
            return Err(actix_web::error::ErrorUnauthorized("Invalid password."));  // Return an error if passwords don't match
        }
    } else {
        return Err(actix_web::error::ErrorNotFound("Password not found."));  // Return an error if password is not found
    }

    // Set token expiration to 90 minutes
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(90)) // Set token expiration time
        .unwrap_or_default()
        .timestamp() as u64; 

    // Create claims for the user (id, role, and expiration)
    let claims: Claims = Claims {
        id: user.id,
        role: user.role.unwrap_or_default() as i16,
        exp: expiration,
    }; 

    let key = std::env::var("ENCODING_KEY").unwrap_or_default();  // Fetch the secret key from environment

    // Generate JWT token (HS256 algorithm)
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(key.as_ref()), // Encode the token with the secret key
    )
    .map_err(|err| {
        println!("JWT token error: {:?}", err); 
        // Return an error if the token generation fails
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to create Token.\nDatabase error: {}",
            err
        ))
    })?; 

    // Log the user login event
    RecordLog(user.id, &pool, format!("User Login")).await?; 

    // Return the generated JWT token as the response
    Ok(HttpResponse::Ok().body(token))
}
