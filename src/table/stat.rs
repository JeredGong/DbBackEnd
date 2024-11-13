use actix_web::{delete, get, post, put, web::{self, Json}, HttpRequest, HttpResponse, Error};
use time::{ OffsetDateTime, UtcOffset };
use sqlx::PgPool;
use super::user::{CheckIs, CheckAdmin, CheckUser, UnwrapToken, Role};
use super::logs::RecordLog;

#[derive(serde::Serialize)]
struct StatisticsResponse {
    countBook: i64,
    countDocs: i64
}

#[get("/statistics")]
pub async fn Info(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let countBook = 
        sqlx::query!("SELECT COUNT(id) FROM recs")
            .fetch_one(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to get books borrowed count.")
            })?;

    let countDocs = 
        sqlx::query!("SELECT SUM(download_count) FROM docs")
            .fetch_one(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to get documents downloaded count.")
            })?; 

    let statisticsResponse = StatisticsResponse {
        countBook: countBook.count.expect("Failed to fetch count of books borrowed."),
        countDocs: countDocs.sum.expect("Failed to fetch count of documents downloaded.")
    };

    RecordLog(claims.id, &pool, format!("(Administrator) Request for Statistics"));
    Ok(HttpResponse::Ok().json(statisticsResponse))
}