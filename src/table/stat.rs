use actix_web::{get, web::{self}, HttpRequest, HttpResponse, Error};
use sqlx::PgPool;
use super::user::CheckUser;
use super::logs::RecordLog;

#[derive(serde::Serialize)]
struct StatisticsResponse {
    countBook: i64,
    countDocs: i64
}

#[get("/stat")]
pub async fn Statistics(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&pool, &request).await?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to start transaction.\nDatabase error: {}", err))
    })?;
    
    let countBook = 
        sqlx::query!("SELECT COUNT(id) FROM recs")
            .fetch_one(&mut transaction)
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError(format!("Failed to get books borrowed count.\nDatabase error: {}", err))
            })?;

    let countDocs = 
        sqlx::query!("SELECT SUM(download_count) FROM docs")
            .fetch_one(&mut transaction)
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError(format!("Failed to get documents downloaded count.\nDatabase error: {}", err))
            })?; 

    let statisticsResponse = StatisticsResponse {
        countBook: countBook.count.unwrap_or_default(),
        countDocs: countDocs.sum.unwrap_or_default()
    };

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to commit transaction.\nDatabase error: {}", err))
    })?;

    RecordLog(claims.id, &pool, format!("Request for Statistics")).await?;
    Ok(HttpResponse::Ok().json(statisticsResponse))
}