use actix_web::{ delete, get, post, put, web, HttpRequest, HttpResponse, Error };
use sqlx::PgPool;
use actix_web::web::Json;
use time::{ OffsetDateTime, UtcOffset };
use super::users::{ CheckIs, UnwrapToken, Role };

/*
 *  PostgreSQL schema 
 *      document(
 *          id              bigint PRIMARY KEY,
 *          title           character varying(256),
 *          pdf_content     bytea,
 *          uploaded_by     bigint,
 *          download_count  integer,
 *          upload_date     timestamp with time zone,
 *          type            character varying(256),
 *          author          character varying(256),
 *          published_date  timestamp with time zone
 *      )
 */

#[derive(serde::Deserialize)]
struct DocumentRequest {
    title: String,
    pdf_content: Vec<u8>,
    TYPE: Option<String>,
    author: Option<String>,
    published_date: Option<Date>
}

#[derive(serde::Serialize)]
struct DocumentResponse {
    id: i64,
    title: String,
    upload_date: OffsetDateTime,
    download_count: i32,
}

fn check_admin(request: &HttpRequest) -> Result<(), Error> {
    if !CheckIs(&UnwrapToken(request)?, Role::Admin)? {
        return Err(actix_web::error::ErrorUnauthorized("Only admins can perform this action."));
    }
    Ok(())
}

// 上传文档
#[post("/documents")]
async fn add_document(
    pool: web::Data<PgPool>,
    document_req: Json<DocumentRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    check_admin(&request)?;

    sqlx::query!(
        "INSERT INTO document (title, pdf_content, uploaded_by, download_count, upload_date, type, author, published_date) VALUES ($1, $2, $3, 0, $4, $5, $6,NOW())",
        &document_req.title,
        &document_req.pdf_content,
        UnwrapToken(&request)?.id.parse::<i64>().map_err(|_| actix_web::error::ErrorBadRequest("Invalid user ID"))?,
        &document_req.TYPE.unwrap_or(""),
        &document_req.author.unwrap_or(""),
        &document_req.published_date.unwrap_or("")
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to add document.")
    })?;

    Ok(HttpResponse::Ok().body("Document added successfully."))
}

// 列出所有文档
#[get("/documents")]
async fn list_documents(pool: web::Data<PgPool>) -> Result<HttpResponse, Error> {
    let documents = sqlx::query!("SELECT id, title, upload_date, download_count FROM document")
        .fetch_all(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to retrieve documents.")
        })?;

    let documents_response: Vec<DocumentResponse> = documents
        .into_iter()
        .map(|doc| DocumentResponse {
            id: doc.id,
            title: doc.title.expect("Document title is missing"),
            upload_date: doc.upload_date.expect("Upload date is missing").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    Ok(HttpResponse::Ok().json(documents_response))
}

#[get("/documents/download/{id}")]
async fn download_document(
    pool: web::Data<PgPool>,
    document_id: web::Path<i64>,
) -> Result<HttpResponse, Error> {
    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to start transaction.")
    })?;

    let document = sqlx::query!("SELECT pdf_content FROM document WHERE id = $1", *document_id)
        .fetch_one(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound("Document not found.")
        })?;

    sqlx::query!("UPDATE document SET download_count = download_count + 1 WHERE id = $1", *document_id)
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

    if let Some(pdf_bytes) = document.pdf_content {
        Ok(HttpResponse::Ok()
            .content_type("application/pdf")
            .body(pdf_bytes))
    } else {
        Err(actix_web::error::ErrorInternalServerError("Document content is empty."))
    }
}

// 编辑文档
#[put("/documents/{id}")]
async fn edit_document(
    pool: web::Data<PgPool>,
    document_id: web::Path<i64>,
    document_req: Json<DocumentRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    check_admin(&request)?;

    sqlx::query!(
        "UPDATE document SET title = $1, pdf_content = $2 WHERE id = $3",
        &document_req.title,
        &document_req.pdf_content,
        *document_id
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to edit document.")
    })?;

    Ok(HttpResponse::Ok().body("Document updated successfully."))
}

#[delete("/documents/{id}")]
async fn delete_document(
    pool: web::Data<PgPool>,
    document_id: web::Path<i64>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    check_admin(&request)?;

    sqlx::query!("DELETE FROM document WHERE id = $1", *document_id)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to delete document.")
        })?;

    Ok(HttpResponse::Ok().body("Document deleted successfully."))
}

#[get("/Search/{title}")]
async fn search_document(
    pool: web::Data<PgPool>,
    title: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let documents = sqlx::query!("SELECT id, title, upload_date, download_count FROM document WHERE title LIKE $1", format!("%{}%", title))
        .fetch_all(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to retrieve documents.")
        })?;

    let documents_response: Vec<DocumentResponse> = documents
        .into_iter()
        .map(|doc| DocumentResponse {
            id: doc.id,
            title: doc.title.expect("Document title is missing"),
            upload_date: doc.upload_date.expect("Upload date is missing").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    Ok(HttpResponse::Ok().json(documents_response))
}