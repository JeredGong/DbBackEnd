use actix_web::{get, web::{self}, HttpRequest, HttpResponse, Error};
use sqlx::PgPool;
use super::user::UnwrapToken;
use super::logs::RecordLog;

#[derive(serde::Serialize)]
struct StatisticsResponse {
    uploadDocs: i64,
    borrowBook: i64,
    dnloadDocs: i64
}

#[get("/stat")]
pub async fn Statistics(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let userID: i64 = match UnwrapToken(&pool, &request).await {
        Ok(claims) => claims.id,
        Err(_) => 0
    };

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to start transaction.\nDatabase error: {}", err))
    })?;

    let uploadDocs = sqlx::query!("
        SELECT COUNT(*) AS count
        FROM docs
        WHERE upload_time >= NOW() - INTERVAL '30 days';"
    )
    .fetch_one(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to get count of upload documents.\nDatabase error: {}", err))
    })?;
    
    let borrowBook = sqlx::query!("SELECT COUNT(id) AS count FROM recs")
    .fetch_one(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to get books borrowed count.\nDatabase error: {}", err))
    })?;

    let dnloadDocs = sqlx::query!("SELECT SUM(download_count) AS count FROM docs")
    .fetch_one(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to get documents downloaded count.\nDatabase error: {}", err))
    })?; 

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to commit transaction.\nDatabase error: {}", err))
    })?;

    let statisticsResponse = StatisticsResponse {
        uploadDocs: uploadDocs.count.unwrap_or_default(),
        borrowBook: if userID == 0 {0} else {borrowBook.count.unwrap_or_default()},
        dnloadDocs: if userID == 0 {0} else {dnloadDocs.count.unwrap_or_default()}
    };

    RecordLog(userID, &pool, format!("{} Request for Statistics", if userID == 0 {"(Guest)"} else {""})).await?;
    Ok(HttpResponse::Ok().json(statisticsResponse))
}