use actix_web::{get, web::{self}, HttpRequest, HttpResponse, Error};
use sqlx::PgPool;
use super::user::CheckAdmin;
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

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to start transaction.")
    })?;
    
    let countBook = 
        sqlx::query!("SELECT COUNT(id) FROM recs")
            .fetch_one(&mut transaction)
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to get books borrowed count.")
            })?;

    let countDocs = 
        sqlx::query!("SELECT SUM(download_count) FROM docs")
            .fetch_one(&mut transaction)
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to get documents downloaded count.")
            })?; 

    let statisticsResponse = StatisticsResponse {
        countBook: countBook.count.expect("Failed to fetch count of books borrowed."),
        countDocs: countDocs.sum.expect("Failed to fetch count of documents downloaded.")
    };

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to commit transaction.")
    })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Request for Statistics")).await?;
    Ok(HttpResponse::Ok().json(statisticsResponse))
}