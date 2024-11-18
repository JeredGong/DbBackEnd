use actix_web::{delete, get, post, put, web::{self, Json}, HttpRequest, HttpResponse, Error};
use time::{Date, OffsetDateTime, UtcOffset};
use sqlx::PgPool;
use super::user::{CheckAdmin, CheckUser, Role, UnwrapToken};
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
 *          upload_date     timestamp with time zone,
 *          doc_type        character varying(128),
 *          author          character varying(128),
 *          publish_date    timestamp with time zone
 *      )
 * 
 *      buff(
 *          id              bigint PRIMARY KEY,
 *          title           character varying(256),
 *          pdf_content     bytea,
 *          uploaded_by     bigint,
 *          download_count  integer,
 *          upload_date     timestamp with time zone,
 *          doc_type        character varying(128),
 *          author          character varying(128),
 *          publish_date    timestamp with time zone       
 *      )
 */

#[derive(serde::Deserialize)]
struct DocumentRequest {
    title: String,
    author: String,
    docType: String,
    pdfContent: Vec<u8>,
    publishDate: Date
}

#[derive(serde::Serialize)]
struct DocumentResponse {
    id: i64,
    title: String,
    author: String,
    docType: String,
    publishDate: Date,
    upload_date: OffsetDateTime,
    download_count: i32
}

#[post("/documents")]
async fn Add(
    pool: web::Data<PgPool>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&request)?;

    if Role::toRole(claims.role).unwrap() == Role::Admin {              // Administrator can upload documents directly.
        
        sqlx::query!(
            "INSERT INTO docs (title, author, doc_type, pdf_content, publish_date, uploaded_by, download_count, upload_time) 
                VALUES ($1, $2, $3, $4, $5, $6, 0, NOW())",
            &docsReq.title,
            &docsReq.author,
            &docsReq.docType,
            &docsReq.pdfContent,
            &docsReq.publishDate,
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
                &docsReq.title, &docsReq.pdfContent)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError("Failed to fetch document id.")
            })?;
    
        RecordLog(claims.id, &pool, format!("(Administrator) Add document of ID {}", document.id)).await?;
        Ok(HttpResponse::Ok().body("Document added successfully."))

    } else /* if Role::toRole(claims.role).unwrap() == Role::User */ {  // Users should upload documents and wait for examination

        sqlx::query!(
            "INSERT INTO buff (title, author, doc_type, pdf_content, publish_date, uploaded_by, download_count, upload_time) 
                VALUES ($1, $2, $3, $4, $5, $6, 0, NOW())",
            &docsReq.title,
            &docsReq.author,
            &docsReq.docType,
            &docsReq.pdfContent,
            &docsReq.publishDate,
            UnwrapToken(&request)?.id
        )
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to push document into buffer.")
        })?;
    
        RecordLog(claims.id, &pool, format!("(User) Push document into buffer")).await?;
        Ok(HttpResponse::Ok().body("Document pushed into buffer successfully."))

    } 
}

#[get("/documents/all")]
async fn List(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let userID: i64 = match UnwrapToken(&request) {
        Ok(claims) => claims.id,
        Err(_) => 0
    };

    let documents = sqlx::query!("SELECT id, title, author, doc_type, publish_date, upload_time, download_count FROM docs")
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
            title: doc.title.expect("Document title is missing."),
            author: doc.author.expect("Document author is missing."),
            docType: doc.doc_type.expect("Document type is missing."),
            publishDate: doc.publish_date.expect("Document publish time is missing."),
            upload_date: doc.upload_time.expect("Upload date is missing.").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    RecordLog(userID, &pool, format!("{} Request for document list", if userID == 0 {"(Guest)"} else {""})).await?;
    Ok(HttpResponse::Ok().json(docsResponse))
}

#[get("/documents/buffer")]
async fn GetBuffer(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let documents = sqlx::query!("SELECT id, title, author, doc_type, publish_date, upload_time, download_count FROM buff")
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
            title: doc.title.expect("Document title is missing."),
            author: doc.author.expect("Document author is missing."),
            docType: doc.doc_type.expect("Document type is missing."),
            publishDate: doc.publish_date.expect("Document publish time is missing."),
            upload_date: doc.upload_time.expect("Upload date is missing.").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    RecordLog(claims.id, &pool, format!("(Admininstrator) Request for documents in buffer")).await?;
    Ok(HttpResponse::Ok().json(docsResponse))
}

#[get("/documents/buffer/{id}")]
async fn DownloadBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let document = sqlx::query!("SELECT pdf_content FROM buff WHERE id = $1", *buffID)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound("Document not found.")
        })?;

    RecordLog(claims.id, &pool, format!("(Admininstrator) Download document in buffer of ID {}", *buffID)).await?;
    if let Some(pdf_bytes) = document.pdf_content {
        Ok(HttpResponse::Ok()
            .content_type("application/pdf")
            .body(pdf_bytes))
    } else {
        Err(actix_web::error::ErrorInternalServerError("Document content is empty."))
    }
}

#[post("/documents/buffer/{id}")]
async fn ConfirmBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&request)?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to start transaction.")
    })?;

    let document = sqlx::query!("SELECT id, title, author, doc_type, publish_date, upload_time, download_count, pdf_content FROM buff WHERE id = $1", *buffID)
        .fetch_one(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound("Document not found.")
        })?;

    sqlx::query!("INSERT INTO docs (title, author, doc_type, publish_date, upload_time, download_count, pdf_content) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &document.title.unwrap_or_default(), 
        &document.author.unwrap_or_default(), 
        &document.doc_type.unwrap_or_default(), 
        &document.publish_date.unwrap(), 
        &document.upload_time.unwrap(), 
        &document.download_count.unwrap_or_default(), 
        &document.pdf_content.clone().unwrap_or_default()
    )
    .fetch_one(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorNotFound("Document cannot be inserted.")
    })?;

    sqlx::query!("DELETE FROM buff WHERE id = $1", *buffID)
        .fetch_one(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound("Document cannot be deleted.")
        })?;

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to commit transaction.")
    })?;

    RecordLog(claims.id, &pool, format!("(Admininstrator) Confirm document in buffer of ID {}", *buffID)).await?;
    Ok(HttpResponse::Ok().body("Confirm document successfully."))
}

#[get("/documents/{title}")]
async fn Search(
    pool: web::Data<PgPool>,
    docsTitle: web::Path<String>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let userID: i64 = match UnwrapToken(&request) {
        Ok(claims) => claims.id,
        Err(_) => 0
    };

    let documents = sqlx::query!(
        "SELECT id, title, author, doc_type, publish_date, upload_time, download_count FROM docs WHERE title LIKE $1",
        format!("%{}%", *docsTitle)
    )
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
            title: doc.title.expect("Document title is missing."),
            author: doc.author.expect("Document author is missing."),
            docType: doc.doc_type.expect("Document type is missing."),
            publishDate: doc.publish_date.expect("Document publish time is missing."),
            upload_date: doc.upload_time.expect("Upload date is missing.").to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    RecordLog(userID, &pool, format!("{} Request for document list", if userID == 0 {"(Guest)"} else {""})).await?;
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

    RecordLog(claims.id, &pool, format!("Download document of ID {}", docsID)).await?;
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
        "UPDATE docs SET title = $1, author = $2, doc_type = $3, pdf_content = $4, publish_date = $5 WHERE id = $6",
        &docsReq.title,
        &docsReq.author,
        &docsReq.docType,
        &docsReq.pdfContent,
        &docsReq.publishDate,
        *docsID
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to edit document.")
    })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Edit document of ID {}", docsID)).await?;
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

    RecordLog(claims.id, &pool, format!("(Administrator) Delete document of ID {}", docsID)).await?;
    Ok(HttpResponse::Ok().body("Document deleted successfully."))
}
