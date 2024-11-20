use actix_web::{delete, get, post, put, web::{self, Json}, HttpRequest, HttpResponse, Error};
use time::{Date, Month, OffsetDateTime, UtcOffset};
use sqlx::PgPool;
use super::user::{CheckAdmin, CheckUser, Role, UnwrapToken};
use super::logs::RecordLog;

/*
 *  PostgreSQL schema 
 * 
 *      docs(
 *          id              bigint PRIMARY KEY,
 *          title           character varying(256),
 *          pdf_content     text,
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
 *          pdf_content     text,
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
    pdfContent: String,
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

#[post("/docs")]
async fn Add(
    pool: web::Data<PgPool>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&pool, &request).await?;

    if Role::toRole(claims.role).unwrap() == Role::Admin {              // Administrator can upload documents directly.
        
        sqlx::query!(
            "INSERT INTO docs (title, author, doc_type, pdf_content, publish_date, uploaded_by, download_count, upload_time) 
                VALUES ($1, $2, $3, $4, $5, $6, 0, NOW())",
            &docsReq.title,
            &docsReq.author,
            &docsReq.docType,
            &docsReq.pdfContent,
            &docsReq.publishDate,
            UnwrapToken(&pool, &request).await?.id
        )
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError(format!("Failed to add document.\nDatabase error: {}", err))
        })?;
    
        let document = 
            sqlx::query!("SELECT id FROM docs WHERE title = $1 and pdf_content = $2", 
                &docsReq.title, &docsReq.pdfContent)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|err| {
                println!("Database error: {:?}", err);
                actix_web::error::ErrorInternalServerError(format!("Failed to fetch document id.\nDatabase error: {}", err))
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
            UnwrapToken(&pool, &request).await?.id
        )
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError(format!("Failed to push document into buffer.\nDatabase error: {}", err))
        })?;
    
        RecordLog(claims.id, &pool, format!("(User) Push document into buffer")).await?;
        Ok(HttpResponse::Ok().body("Document pushed into buffer successfully."))

    } 
}

#[get("/docs/all")]
async fn List(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let userID: i64 = match UnwrapToken(&pool, &request).await {
        Ok(claims) => claims.id,
        Err(_) => 0
    };

    let documents = sqlx::query!("SELECT id, title, author, doc_type, publish_date, upload_time, download_count FROM docs")
        .fetch_all(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError(format!("Failed to retrieve documents.\nDatabase error: {}", err))
        })?;

    let docsResponse: Vec<DocumentResponse> = documents
        .into_iter()
        .map(|doc| DocumentResponse {
            id: doc.id,
            title: doc.title.unwrap_or_default(),
            author: doc.author.unwrap_or_default(),
            docType: doc.doc_type.unwrap_or_default(),
            publishDate: doc.publish_date.unwrap_or(Date::from_calendar_date(0, Month::January, 1).unwrap()),
            upload_date: doc.upload_time.unwrap_or(OffsetDateTime::UNIX_EPOCH).to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    RecordLog(userID, &pool, format!("{} Request for document list", if userID == 0 {"(Guest)"} else {""})).await?;
    Ok(HttpResponse::Ok().json(docsResponse))
}

#[get("/docs/buffer")]
async fn GetBuffer(
    pool: web::Data<PgPool>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&pool, &request).await?;

    let documents = sqlx::query!("SELECT id, title, author, doc_type, publish_date, upload_time, download_count FROM buff")
        .fetch_all(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError(format!("Failed to retrieve documents.\nDatabase error: {}", err))
        })?;

    let docsResponse: Vec<DocumentResponse> = documents
        .into_iter()
        .map(|doc| DocumentResponse {
            id: doc.id,
            title: doc.title.unwrap_or_default(),
            author: doc.author.unwrap_or_default(),
            docType: doc.doc_type.unwrap_or_default(),
            publishDate: doc.publish_date.unwrap_or(Date::from_calendar_date(0, Month::January, 1).unwrap()),
            upload_date: doc.upload_time.unwrap_or(OffsetDateTime::UNIX_EPOCH).to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    RecordLog(claims.id, &pool, format!("(Admininstrator) Request for documents in buffer")).await?;
    Ok(HttpResponse::Ok().json(docsResponse))
}

#[get("/docs/buffer/{id}")]
async fn DownloadBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&pool, &request).await?;

    let document = sqlx::query!("SELECT pdf_content FROM buff WHERE id = $1", *buffID)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound(format!("Document not found.\nDatabase error: {}", err))
        })?;

    RecordLog(claims.id, &pool, format!("(Admininstrator) Download document in buffer of ID {}", *buffID)).await?;
    Ok(HttpResponse::Ok().body(document.pdf_content.unwrap_or_default()))
}

#[put("/docs/buffer/{id}")]
async fn EditBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&pool, &request).await?;

    sqlx::query!("UPDATE buff SET title = $1, author = $2, doc_type = $3, pdf_content = $4, publish_date = $5 WHERE id = $6", 
        &docsReq.title,
        &docsReq.author,
        &docsReq.docType,
        &docsReq.pdfContent,
        &docsReq.publishDate,
        *buffID
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorNotFound(format!("Edit document failed.\nDatabase error: {}", err))
    })?;

    RecordLog(claims.id, &pool, format!("(Admininstrator) Edit document in buffer of ID {}", *buffID)).await?;
    Ok(HttpResponse::Ok().body("Edit document successfully."))
}

#[post("/docs/buffer/{id}")]
async fn ConfirmBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&pool, &request).await?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to start transaction.\nDatabase error: {}", err))
    })?;

    let document = sqlx::query!("SELECT id, title, author, doc_type, publish_date, upload_time, download_count, pdf_content FROM buff WHERE id = $1", *buffID)
        .fetch_one(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound(format!("Document not found.\nDatabase error: {}", err))
        })?;

    sqlx::query!("INSERT INTO docs (title, author, doc_type, publish_date, upload_time, download_count, pdf_content) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &document.title.unwrap_or_default(), 
        &document.author.unwrap_or_default(), 
        &document.doc_type.unwrap_or_default(), 
        &document.publish_date.unwrap_or(Date::from_calendar_date(0, Month::January, 1).unwrap()), 
        &document.upload_time.unwrap_or(OffsetDateTime::UNIX_EPOCH), 
        &document.download_count.unwrap_or_default(), 
        &document.pdf_content.clone().unwrap_or_default()
    )
    .execute(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorNotFound(format!("Document cannot be inserted.\nDatabase error: {}", err))
    })?;

    sqlx::query!("DELETE FROM buff WHERE id = $1", *buffID)
        .execute(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound(format!("Document cannot be deleted.\nDatabase error: {}", err))
        })?;

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to commit transaction.\nDatabase error: {}", err))
    })?;

    RecordLog(claims.id, &pool, format!("(Admininstrator) Confirm document in buffer of ID {}", *buffID)).await?;
    Ok(HttpResponse::Ok().body("Confirm document successfully."))
}

#[delete("/docs/buffer/{id}")]
async fn RefuseBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&pool, &request).await?;

    sqlx::query!("DELETE FROM buff WHERE id = $1", *buffID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound(format!("Delete document failed.\nDatabase error: {}", err))
        })?;

    RecordLog(claims.id, &pool, format!("(Admininstrator) Refuse document in buffer of ID {}", *buffID)).await?;
    Ok(HttpResponse::Ok().body("Refuse document successfully."))
}


#[get("/docs/search/{title}")]
async fn Search(
    pool: web::Data<PgPool>,
    docsTitle: web::Path<String>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let userID: i64 = match UnwrapToken(&pool, &request).await {
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
        actix_web::error::ErrorInternalServerError(format!("Failed to retrieve documents.\nDatabase error: {}", err))
    })?;

    let docsResponse: Vec<DocumentResponse> = documents
        .into_iter()
        .map(|doc| DocumentResponse {
            id: doc.id,
            title: doc.title.unwrap_or_default(),
            author: doc.author.unwrap_or_default(),
            docType: doc.doc_type.unwrap_or_default(),
            publishDate: doc.publish_date.unwrap_or(Date::from_calendar_date(0, Month::January, 1).unwrap()),
            upload_date: doc.upload_time.unwrap_or(OffsetDateTime::UNIX_EPOCH).to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()), 
            download_count: doc.download_count.unwrap_or(0),
        }).collect();

    RecordLog(userID, &pool, format!("{} Request for document list", if userID == 0 {"(Guest)"} else {""})).await?;
    Ok(HttpResponse::Ok().json(docsResponse))
}

#[get("/docs/{id}")]
async fn Download(
    pool: web::Data<PgPool>,
    docsID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckUser(&pool, &request).await?;

    let mut transaction = pool.begin().await.map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to start transaction.\nDatabase error: {}", err))
    })?;

    let document = sqlx::query!("SELECT pdf_content FROM docs WHERE id = $1", *docsID)
        .fetch_one(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound(format!("Document not found.\nDatabase error: {}", err))
        })?;

    sqlx::query!("UPDATE docs SET download_count = download_count + 1 WHERE id = $1", *docsID)
        .execute(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError(format!("Failed to update download count.\nDatabase error: {}", err))
        })?;

    transaction.commit().await.map_err(|err| {
        println!("Transaction error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to commit transaction.\nDatabase error: {}", err))
    })?;

    RecordLog(claims.id, &pool, format!("Download document of ID {}", docsID)).await?;
    Ok(HttpResponse::Ok().body(document.pdf_content.unwrap_or_default()))
}

#[put("/docs/{id}")]
async fn Edit(
    pool: web::Data<PgPool>,
    docsID: web::Path<i64>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&pool, &request).await?;

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
        actix_web::error::ErrorInternalServerError(format!("Failed to edit document.\nDatabase error: {}", err))
    })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Edit document of ID {}", docsID)).await?;
    Ok(HttpResponse::Ok().body("Document updated successfully."))
}

#[delete("/docs/{id}")]
async fn Delete(
    pool: web::Data<PgPool>,
    docsID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&pool, &request).await?;

    sqlx::query!("DELETE FROM docs WHERE id = $1", *docsID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError(format!("Failed to delete document.\nDatabase error: {}", err))
        })?;

    RecordLog(claims.id, &pool, format!("(Administrator) Delete document of ID {}", docsID)).await?;
    Ok(HttpResponse::Ok().body("Document deleted successfully."))
}
