use actix_web::{delete, get, post, put, web::{self, Json}, Error, HttpRequest, HttpResponse};
use time::{OffsetDateTime, UtcOffset, Date, Month};
use sqlx::PgPool;
use super::user::{CheckAdmin, CheckUser};
use super::logs::RecordLog;

/*
 *  PostgreSQL schema 
 * 
 *      book(
 *          id              bigint PRIMARY KEY,
 *          title           character varying(256),
 *          author          character varying(128),
 *          book_type       character varying(128),
 *          publish_date    date,
 *          available       bool
 *      )
 *
 *      recs(
 *          id              bigint PRIMARY KEY,
 *          user_id         bigint,
 *          book_id         bigint,
 *          borrowed_at     timestamp with time zone,
 *          returned_at     timestamp with time zone
 *      )
 */

#[derive(serde::Deserialize)]
struct BookRequest {
    title: String,
    author: String,
    bookType: String,
    publishDate: Date
}

#[derive(serde::Serialize)]
struct BookResponse {
    id: i64,
    title: String,
    author: String,
    bookType: String,
    publishDate: Date,
    available: bool
}

#[derive(serde::Serialize)]
struct SearchResponse {
    idList: Vec<i64>,
    title: String,
    author: String,
    bookType: String,
    publishDate: Date,
    remain: i64
}

#[derive(serde::Serialize)]
struct RecordResponse {
    id: i64, 
    userID: i64, 
    bookID: i64, 
    borrowedAt: OffsetDateTime, 
    returnedAt: OffsetDateTime
}

#[post("/books")]
async fn Add(
    pool: web::Data<PgPool>,
    bookReq: Json<BookRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to start transaction.")
    })?;

    sqlx::query!(
        "INSERT INTO book (title, author, book_type, publish_date, available) VALUES ($1, $2, $3, $4, true)",
        &bookReq.title, 
        &bookReq.author,
        &bookReq.bookType,
        &bookReq.publishDate
    )
    .execute(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to add book.")
    })?;
    
    let bookIDs =
        sqlx::query!("SELECT id FROM book WHERE title = $1 and author = $2 and book_type = $3 and publish_date = $4", 
            &bookReq.title, &bookReq.author, &bookReq.bookType, &bookReq.publishDate)
                .fetch_all(&mut transaction)
                .await
                .map_err(|err| {
                    println!("Database error: {:?}", err);
                    actix_web::error::ErrorInternalServerError("Failed to fetch book id.")
                })?;
    
    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to commit transaction.")
    })?;
    
    let curBookID = || -> i64 {
        bookIDs
            .iter()
            .map(|item| item.id)
            .max()
            .unwrap_or(0)
    } ();

    RecordLog(claims.id, &pool, format!("(Administrator) Add book of ID {}", curBookID)).await?;
    Ok(HttpResponse::Ok().body("Book added successfully."))
}

#[get("/books/all")]
async fn List(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error>  {

    let claims = CheckAdmin(&request)?;

    let books = sqlx::query!("SELECT id, title, author, book_type, publish_date, available FROM book")
        .fetch_all(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to retrieve books.")
        })?;

    let bookResponse: Vec<BookResponse> = books
        .into_iter()
        .map(|book| BookResponse {
            id: book.id,
            title: book.title.unwrap_or_default(),
            author: book.author.unwrap_or_default(),
            bookType: book.book_type.unwrap_or_default(),
            publishDate: book.publish_date.unwrap_or(Date::from_calendar_date(0, Month::January, 1).unwrap()),
            available: book.available.unwrap_or_default()
        }).collect();

    RecordLog(claims.id, &pool, format!("(Admininstrator) Request for book list")).await?;
    Ok(HttpResponse::Ok().json(bookResponse))
}

#[get("/books/{title}")]
async fn Search(
    pool: web::Data<PgPool>,
    bookTitle: web::Path<String>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    let books = sqlx::query!(
        "SELECT 
            ARRAY_AGG(id) AS id_list,
            title, 
            author, 
            book_type, 
            publish_date, 
            COUNT(*) AS remain
        FROM book 
        WHERE title LIKE $1 AND available = true
        GROUP BY title, author, book_type, publish_date", 
        format!("%{}%", *bookTitle)
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to retrieve books.")
    })?;
    
    let searchResponse: Vec<SearchResponse> = books
        .into_iter()
        .map(|record| SearchResponse {
            idList: record.id_list.unwrap_or_default(), 
            title: record.title.unwrap_or_default(),    
            author: record.author.unwrap_or_default(),  
            bookType: record.book_type.unwrap_or_default(),
            publishDate: record.publish_date.unwrap_or(Date::from_calendar_date(0, Month::January, 1).unwrap()),     
            remain: record.remain.unwrap_or(0),
        }).collect();

    RecordLog(claims.id, &pool, format!("Search book of title \"{}\"", *bookTitle)).await?;
    Ok(HttpResponse::Ok().json(searchResponse))
}

#[put("/books/{id}")]
async fn Edit(
    pool: web::Data<PgPool>,
    bookID: web::Path<i64>,
    bookReq: Json<BookRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    sqlx::query!(
        "UPDATE book SET title = $1, author = $2, book_type = $3, publish_date = $4 WHERE id = $5",
        &bookReq.title,
        &bookReq.author,
        &bookReq.bookType,
        &bookReq.publishDate,
        *bookID
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to edit book.")
    })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Edit book of ID {}", bookID)).await?;
    Ok(HttpResponse::Ok().body("Book updated successfully."))
}

#[delete("/books/{id}")]
async fn Delete(
    pool: web::Data<PgPool>,
    bookID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    sqlx::query!("UPDATE book SET available = NULL WHERE id = $1", *bookID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to delete book.")
        })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Delete book of ID {}", bookID)).await?;
    Ok(HttpResponse::Ok().body("Book deleted successfully."))
}

#[post("/borrow/{id}")]
async fn Borrow(
    pool: web::Data<PgPool>,
    bookID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to start transaction.")
    })?;

    sqlx::query!("UPDATE book SET available = false WHERE id = $1 and available = true", *bookID)
        .execute(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to borrow book.")
        })?;

    sqlx::query!("INSERT INTO recs (user_id, book_id, borrowed_at, returned_at) 
        VALUES ($1, $2, NOW(), NULL)", 
        &claims.id,
        *bookID
    )
    .execute(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to insert borrowing record.")
    })?;
    
    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to commit transaction.")
    })?;

    RecordLog(claims.id, &pool, format!("Borrow book of ID {}", bookID)).await?;
    Ok(HttpResponse::Ok().body("Book borrowed successfully."))
}

#[post("/return/{id}")]
async fn Return(
    pool: web::Data<PgPool>,
    bookID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to start transaction.")
    })?;

    sqlx::query!("UPDATE recs SET returned_at = NOW() WHERE returned_at IS NULL and user_id = $1 and book_id = $2",
        &claims.id,
        *bookID
    )
    .execute(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to update borrowing record.")
    })?;

    sqlx::query!("UPDATE book SET available = true WHERE id = $1 and available = false", *bookID)
        .execute(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to return book.")
        })?;
        
    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to commit transaction.")
    })?;
    
    RecordLog(claims.id, &pool, format!("Return book of ID {}", bookID)).await?;
    Ok(HttpResponse::Ok().body("Book returned successfully."))
}

#[get("/borrowings/all")]
async fn Records(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let records = 
        sqlx::query!("SELECT id, user_id, book_id, borrowed_at, returned_at FROM recs")
            .fetch_all(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to fetch borrowing records.")
            })?;
    
    let recordResponse: Vec<RecordResponse> = records
        .into_iter()
        .map(|rec| RecordResponse {
            id: rec.id,
            userID: rec.user_id,
            bookID: rec.book_id,
            borrowedAt: rec.borrowed_at.unwrap_or(OffsetDateTime::UNIX_EPOCH).to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()),
            returnedAt: rec.returned_at.unwrap_or(OffsetDateTime::UNIX_EPOCH).to_offset(UtcOffset::from_hms(8, 0, 0).unwrap())
        }).collect();
    
    RecordLog(claims.id, &pool, format!("(Administrator) Request for all borrowing records")).await?;
    Ok(HttpResponse::Ok().json(recordResponse))
}

#[get("/borrowings")]
async fn UserRecords(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    let records = 
        sqlx::query!("SELECT id, user_id, book_id, borrowed_at, returned_at FROM recs WHERE user_id = $1", claims.id)
            .fetch_all(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to fetch borrowing records.")
            })?;

    let recordResponse: Vec<RecordResponse> = records
        .into_iter()
        .map(|rec| RecordResponse {
            id: rec.id,
            userID: rec.user_id,
            bookID: rec.book_id,
            borrowedAt: rec.borrowed_at.unwrap_or(OffsetDateTime::UNIX_EPOCH).to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()),
            returnedAt: rec.returned_at.unwrap_or(OffsetDateTime::UNIX_EPOCH).to_offset(UtcOffset::from_hms(8, 0, 0).unwrap())
        }).collect();
    
    RecordLog(claims.id, &pool, format!("Request for book self borrowed")).await?;
    Ok(HttpResponse::Ok().json(recordResponse))
}
