use actix_web::{delete, get, post, put, web::{self, Json}, HttpRequest, HttpResponse, Error};
use time::{ OffsetDateTime, UtcOffset };
use sqlx::PgPool;
use super::user::{CheckIs, CheckAdmin, CheckUser, UnwrapToken, Role};
use super::logs::RecordLog;

/*
 *  PostgreSQL schema 
 * 
 *      book(
 *          id              bigint PRIMARY KEY,
 *          title           character varying(256),
 *          author          character varying(256),
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
    author: String
}

#[derive(serde::Serialize)]
struct BookResponse {
    id: i64,
    title: String,
    author: String,
    available: bool
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

    sqlx::query!(
        "INSERT INTO book (title, author, available) 
            VALUES ($1, $2, true)",
        &bookReq.title, 
        &bookReq.author    
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to add book.")
    })?;
    
    let bookIDs =
        sqlx::query!("SELECT id FROM book WHERE title = $1 and author = $2", &bookReq.title, &bookReq.author)
            .fetch_all(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to fetch book id.")
            })?;
    
    let curBookID = || -> i64 {
        bookIDs
            .iter()
            .map(|item| item.id)
            .max()
            .unwrap_or(0) as i64
    } ();

    RecordLog(claims.id, &pool, format!("(Administrator) Add book of ID {}", curBookID));
    Ok(HttpResponse::Ok().body("Book added successfully."))
}

#[get("books")]
async fn List(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error>  {

    let userID: i64 = match UnwrapToken(&request) {
        Ok(claims) => claims.id,
        Err(err) => 0
    };

    let books = sqlx::query!("SELECT id, title, author, available FROM book")
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
            title: book.title.expect("Book title is missing."),
            author: book.author.expect("Book author is missing."),
            available: book.available.expect("Book whether avaiable is unknown.")
        }).collect();

    RecordLog(userID, &pool, format!("(Administrator) Request for book list"));
    Ok(HttpResponse::Ok().json(bookResponse))
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
        "UPDATE book SET title = $1, author = $2 WHERE id = $3",
        &bookReq.title,
        &bookReq.author,
        *bookID
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to edit book.")
    })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Edit book of ID {}", bookID));
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

    RecordLog(claims.id, &pool, format!("(Administrator) Delete book of ID {}", bookID));
    Ok(HttpResponse::Ok().body("Book deleted successfully."))
}

#[post("/borrow/{id}")]
async fn Borrow(
    pool: web::Data<PgPool>,
    bookID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    sqlx::query!("UPDATE book SET available = false WHERE id = $1 and available = true", *bookID)
        .execute(pool.get_ref())
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
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to insert borrowing record.")
    })?;
    
    RecordLog(claims.id, &pool, format!("Borrow book of ID {}", bookID));
    Ok(HttpResponse::Ok().body("Book borrowed successfully."))
}

#[post("/return/{id}")]
async fn Return(
    pool: web::Data<PgPool>,
    bookID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    sqlx::query!("UPDATE recs SET returned_at = NOW() WHERE returned_at IS NULL and user_id = $1 and book_id = $2",
        &claims.id,
        *bookID
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to update borrowing record.")
    })?;

    sqlx::query!("UPDATE book SET available = true WHERE id = $1 and available = false", *bookID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to return book.")
        })?;
    
    RecordLog(claims.id, &pool, format!("Return book of ID {}", bookID));
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
            borrowedAt: rec.borrowed_at.expect("Borrowed time is missing").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()),
            returnedAt: rec.returned_at.expect("Returned time is missing").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap())
        }).collect();
    
    RecordLog(claims.id, &pool, format!("(Administrator) Request for all borrowing records"));
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
            borrowedAt: rec.borrowed_at.expect("Borrowed time is missing").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()),
            returnedAt: rec.returned_at.expect("Returned time is missing").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap())
        }).collect();
    
    RecordLog(claims.id, &pool, format!("Request for book self borrowed"));
    Ok(HttpResponse::Ok().json(recordResponse))
}
