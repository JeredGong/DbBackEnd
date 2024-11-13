use actix_web::{delete, get, post, put, web::{self, Json}, HttpRequest, HttpResponse, Error};
use time::{ OffsetDateTime, UtcOffset };
use sqlx::PgPool;
use super::user::{CheckIs, CheckAdmin, CheckUser, UnwrapToken, Role};
use super::logs::RecordLog;

/*
 *  PostgreSQL schema 
 * 
 *      docs(
 *          id              bigint PRIMARY KEY,
 *          title           character varying(256),
 *          pdf_content     bytea,
 *          uploaded_by     bigint,
 *          download_count  integer,
 *          upload_date     timestamp with time zone
 *      )
 */

#[derive(serde::Deserialize)]
struct DocumentRequest {
    title: String,
    pdf_content: Vec<u8>
}

#[derive(serde::Serialize)]
struct DocumentResponse {
    id: i64,
    title: String,
    upload_date: OffsetDateTime,
    download_count: i32
}

#[post("/documents")]
async fn Add(
    pool: web::Data<PgPool>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    sqlx::query!(
        "INSERT INTO docs (title, pdf_content, uploaded_by, download_count, upload_date) 
            VALUES ($1, $2, $3, 0, NOW())",
        &docsReq.title,
        &docsReq.pdf_content,
        UnwrapToken(&request)?.id
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to add document.")
    })?;

    let document = 
        sqlx::query!("SELECT id FROM docs WHERE title = $1 and pdf_content = $2", 
            &docsReq.title, &docsReq.pdf_content)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to fetch document id.")
        })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Add document of ID {}", document.id));
    Ok(HttpResponse::Ok().body("Document added successfully."))
}

#[get("/documents")]
async fn List(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {
    
    let userID: i64 = match UnwrapToken(&request) {
        Ok(claims) => claims.id,
        Err(err) => 0
    };

    let documents = sqlx::query!("SELECT id, title, upload_date, download_count FROM docs")
        .fetch_all(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to retrieve documents.")
        })?;

    let docsResponse: Vec<DocumentResponse> = documents
        .into_iter()
        .map(|doc| DocumentResponse {
            id: doc.id,
            title: doc.title.expect("Document title is missing"),
            upload_date: doc.upload_date.expect("Upload date is missing").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    RecordLog(userID, &pool, format!("{} Request for document list", if userID == 0 {"(Guest)"} else {""}));
    Ok(HttpResponse::Ok().json(docsResponse))
}

#[get("/documents/download/{id}")]
async fn Download(
    pool: web::Data<PgPool>,
    docsID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to start transaction.")
    })?;

    let document = sqlx::query!("SELECT pdf_content FROM docs WHERE id = $1", *docsID)
        .fetch_one(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound("Document not found.")
        })?;

    sqlx::query!("UPDATE docs SET download_count = download_count + 1 WHERE id = $1", *docsID)
        .execute(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to update download count.")
        })?;

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to commit transaction.")
    })?;

    RecordLog(claims.id, &pool, format!("Download document of ID {}", docsID));
    if let Some(pdf_bytes) = document.pdf_content {
        Ok(HttpResponse::Ok()
            .content_type("application/pdf")
            .body(pdf_bytes))
    } else {
        Err(actix_web::error::ErrorInternalServerError("Document content is empty."))
    }
}

#[put("/documents/{id}")]
async fn Edit(
    pool: web::Data<PgPool>,
    docsID: web::Path<i64>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    sqlx::query!(
        "UPDATE docs SET title = $1, pdf_content = $2 WHERE id = $3",
        &docsReq.title,
        &docsReq.pdf_content,
        *docsID
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to edit document.")
    })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Edit document of ID {}", docsID));
    Ok(HttpResponse::Ok().body("Document updated successfully."))
}

#[delete("/documents/{id}")]
async fn Delete(
    pool: web::Data<PgPool>,
    docsID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    sqlx::query!("DELETE FROM docs WHERE id = $1", *docsID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to delete document.")
        })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Delete document of ID {}", docsID));
    Ok(HttpResponse::Ok().body("Document deleted successfully."))
}
