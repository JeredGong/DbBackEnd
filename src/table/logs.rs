use actix_web::{get, web::{self}, HttpRequest, HttpResponse, Error};
use sqlx::PgPool;
use super::user::CheckAdmin;

/*
 *  PostgreSQL schema 
 * 
 *      logs(
 *          id              bigint PRIMARY KEY,
 *          user_id         bigint,
 *          action          character varying(512)
 *      )
 */

#[derive(serde::Serialize)]
struct LogResponse {
    id: i64,
    userID: i64,
    action: String
}

pub async fn RecordLog(
    userID: i64,
    pool: &web::Data<PgPool>,
    action: String
) -> Result<(), Error> {

    sqlx::query!("INSERT INTO logs (user_id, action) VALUES ($1, $2)", &userID, &action)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to insert log.")
        })?;

    Ok(())
}

#[get("/logs")]
async fn Logs(
    pool: web::Data<PgPool>,
    request: HttpRequest 
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let logs = 
        sqlx::query!("SELECT id, user_id, action FROM logs")
            .fetch_all(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to fetch logs.")
            })?;

    let logResponse: Vec<LogResponse> = logs
            .into_iter()
            .map(|log| LogResponse {
                id: log.id,
                userID: log.user_id.expect("User ID not found."),
                action: log.action.expect("Action not found.")
            }).collect();
    
    RecordLog(claims.id, &pool, format!("(Administrator) Request for logs")).await?;
    Ok(HttpResponse::Ok().json(logResponse))
}
