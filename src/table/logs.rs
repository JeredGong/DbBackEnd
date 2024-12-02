use super::user::CheckAdmin; 
use actix_web::{
    get,
    web::{self},
    Error, HttpRequest, HttpResponse,
}; 
use sqlx::PgPool; 
use time::{OffsetDateTime, UtcOffset}; 

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
    action: String,
    logTime: OffsetDateTime,
}

pub async fn RecordLog(userID: i64, pool: &web::Data<PgPool>, action: String) -> Result<(), Error> {
    sqlx::query!(
        "INSERT INTO logs (user_id, action, log_time) VALUES ($1, $2, NOW())",
        &userID,
        &action
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err); 
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to insert log.\nDatabase error: {}",
            err
        ))
    })?; 

    Ok(())
}

#[get("/logs")]
pub async fn Logs(pool: web::Data<PgPool>, request: HttpRequest) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?; 

    let logs = sqlx::query!("SELECT id, user_id, action, log_time FROM logs")
        .fetch_all(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err); 
            actix_web::error::ErrorInternalServerError(format!(
                "Failed to fetch logs.\nDatabase error: {}",
                err
            ))
        })?; 

    let logResponse: Vec<LogResponse> = logs
        .into_iter()
        .map(|log| LogResponse {
            id: log.id,
            userID: log.user_id.unwrap_or_default(),
            action: log.action.unwrap_or_default(),
            logTime: log
                .log_time
                .unwrap_or(OffsetDateTime::UNIX_EPOCH)
                .to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()),
        })
        .collect(); 

    RecordLog(
        claims.id,
        &pool,
        format!("(Administrator) Request for logs"),
    )
    .await?; 
    Ok(HttpResponse::Ok().json(logResponse))
}
