use actix_web::{delete, get, post, put, web::{self, Json}, HttpRequest, HttpResponse, Error};
use time::{Date, Month, OffsetDateTime, UtcOffset};
use sqlx::PgPool;
use super::user::{CheckAdmin, CheckUser, Role, UnwrapToken};
use super::logs::RecordLog;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
// use base64::{engine::general_purpose, Engine}; // 引入 Engine 模块
/*
 *  PostgreSQL schema 
 * 
 *      docs(
 *          id              bigint PRIMARY KEY,
 *          title           character varying(256),
 *          file_path       text,
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
 *          file_path       text,
 *          uploaded_by     bigint,
 *          download_count  integer,
 *          upload_date     timestamp with time zone,
 *          doc_type        character varying(128),
 *          author          character varying(128),
 *          publish_date    timestamp with time zone       
 *      )
 */

// 保存文件并返回路径
pub async fn save_file(content: &Vec<u8>, upload_dir: &str, file_type: &str) -> Result<String, std::io::Error> {
    // 确保上传目录存在
    fs::create_dir_all(upload_dir).await?;

    // 生成唯一文件名
    let file_name = format!("{}.{}", Uuid::new_v4(), file_type);
    let file_path = format!("{}/{}", upload_dir, file_name);

    // 将内容写入文件
    let mut file = File::create(&file_path).await?;
    file.write_all(content).await?;

    Ok(file_path)
}

// fn base64_to_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
// where
//     D: serde::Deserializer<'de>,
// {
//     let base64_str = String::deserialize(deserializer)?; // 获取 Base64 字符串
//     general_purpose::STANDARD
//         .decode(&base64_str) // 使用新的 Engine API
//         .map_err(serde::de::Error::custom) // 解码错误处理
// }

#[derive(Serialize, Deserialize)]
struct DocumentRequest {
    title: String,
    author: String,
    docType: String,
    // #[serde(deserialize_with = "base64_to_vec")] 
    // 取消 pdfContent base64_to_vec Trait
    pdfContent: Vec<u8>,
    publishDate: Date
}

#[derive(serde::Serialize)]
struct DocumentResponse {
    id: i64,
    title: String,
    author: String,
    uploadedBy: String,
    docType: String,
    publishDate: Date,
    upload_date: OffsetDateTime,
    download_count: i32
}

#[post("/docs")]
async fn Add(
    pool: web::Data<PgPool>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = CheckUser(&pool, &request).await?;

    // 保存文件到服务器并获取文件路径
    let file_path = save_file(&docsReq.pdfContent, "./uploads/docs", "pdf")
        .await
        .map_err(|err| {
            println!("File save error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to save PDF file")
        })?;

    if Role::toRole(claims.role).unwrap() == Role::Admin {
        // 管理员直接保存到 docs 表
        sqlx::query!(
            "INSERT INTO docs (title, author, doc_type, file_path, publish_date, uploaded_by, download_count, upload_time) 
                VALUES ($1, $2, $3, $4, $5, $6, 0, NOW())",
            &docsReq.title,
            &docsReq.author,
            &docsReq.docType,
            &file_path,
            &docsReq.publishDate,
            claims.id
        )
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to insert into docs table")
        })?;
    } else {
        // 普通用户保存到 buff 表
        sqlx::query!(
            "INSERT INTO buff (title, author, doc_type, file_path, publish_date, uploaded_by, download_count, upload_time) 
                VALUES ($1, $2, $3, $4, $5, $6, 0, NOW())",
            &docsReq.title,
            &docsReq.author,
            &docsReq.docType,
            &file_path,
            &docsReq.publishDate,
            claims.id
        )
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to insert into buff table")
        })?;
    }

    RecordLog(claims.id, &pool, format!("Upload document '{}'", docsReq.title))
    .await
    .map_err(|err| {
        println!("Log record error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to record log")
    })?;

    Ok(HttpResponse::Ok().body("Document uploaded successfully."))
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

    let documents = sqlx::query!("
        SELECT docs.id, docs.title, docs.author, \"user\".username AS uploaded_by, docs.doc_type, docs.publish_date, docs.upload_time, docs.download_count
        FROM docs
        JOIN \"user\" ON \"user\".id = docs.uploaded_by"
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
            uploadedBy: doc.uploaded_by.unwrap_or_default(),
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

    let documents = sqlx::query!("
        SELECT buff.id, buff.title, buff.author, \"user\".username AS uploaded_by, buff.doc_type, buff.publish_date, buff.upload_time, buff.download_count
        FROM buff
        JOIN \"user\" ON \"user\".id = buff.uploaded_by"
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
            uploadedBy: doc.uploaded_by.unwrap_or_default(),
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
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?;

    // 查询文件路径
    let document = sqlx::query!("SELECT file_path FROM buff WHERE id = $1", *buffID)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound("Document not found")
        })?;

    let file_path = document.file_path.unwrap_or_default();

    // 读取文件内容
    let pdf_content = tokio::fs::read(&file_path).await.map_err(|err| {
        println!("File read error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to read PDF file")
    })?;

    RecordLog(claims.id, &pool, format!("Download buffer document ID {}", buffID)).await?;
    Ok(HttpResponse::Ok().content_type("application/pdf").body(pdf_content))
}

#[put("/docs/buffer/{id}")]
async fn EditBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?;

    // 保存新的文件内容
    let new_file_path = save_file(&docsReq.pdfContent, "./uploads/docs", "pdf")
    .await
    .map_err(|err| {
        println!("File save error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to save PDF file")
    })?;

    // 更新数据库记录
    sqlx::query!(
        "UPDATE buff SET title = $1, author = $2, doc_type = $3, file_path = $4, publish_date = $5 WHERE id = $6",
        &docsReq.title,
        &docsReq.author,
        &docsReq.docType,
        &new_file_path,
        &docsReq.publishDate,
        *buffID
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to edit buffer document")
    })?;

    RecordLog(claims.id, &pool, format!("Edit buffer document ID {}", buffID)).await?;
    Ok(HttpResponse::Ok().body("Buffer document updated successfully."))
}

#[post("/docs/buffer/{id}")]
async fn ConfirmBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?;

    let mut transaction = pool.begin().await.map(|t| t).map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to start transaction.\nDatabase error: {}", err))
    })?;

    // 查询缓冲区文档
    let document = sqlx::query!(
        "SELECT id, title, author, doc_type, publish_date, upload_time, uploaded_by, download_count, file_path FROM buff WHERE id = $1",
        *buffID
    )
    .fetch_one(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorNotFound(format!("Document not found in buffer.\nDatabase error: {}", err))
    })?;

    // 将文档插入到 docs 表
    sqlx::query!(
        "INSERT INTO docs (title, author, doc_type, publish_date, upload_time, uploaded_by, download_count, file_path) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &document.title.unwrap_or_default(),
        &document.author.unwrap_or_default(),
        &document.doc_type.unwrap_or_default(),
        &document.publish_date.unwrap_or(Date::from_calendar_date(0, Month::January, 1).unwrap()),
        &document.upload_time.unwrap_or(OffsetDateTime::UNIX_EPOCH),
        &document.uploaded_by.unwrap_or_default(),
        &document.download_count.unwrap_or_default(),
        &document.file_path.unwrap_or_default()
    )
    .execute(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to insert document into docs table.\nDatabase error: {}", err))
    })?;

    // 删除缓冲区中的文档
    sqlx::query!("DELETE FROM buff WHERE id = $1", *buffID)
        .execute(&mut transaction)
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorInternalServerError(format!("Failed to delete document from buffer.\nDatabase error: {}", err))
        })?;

    transaction.commit().await.map(|_| ()).map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to commit transaction.\nDatabase error: {}", err))
    })?;

    RecordLog(claims.id, &pool, format!("Confirm buffer document ID {}", buffID)).await?;
    Ok(HttpResponse::Ok().body("Buffer document confirmed successfully."))
}

#[delete("/docs/buffer/{id}")]
async fn RefuseBuffer(
    pool: web::Data<PgPool>,
    buffID: web::Path<i64>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?;

    // 查询文档的文件路径
    let document = sqlx::query!("SELECT file_path FROM buff WHERE id = $1", *buffID)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound(format!("Document not found in buffer.\nDatabase error: {}", err))
        })?;

    let file_path = document.file_path.unwrap_or_default();

    // 删除数据库记录
    sqlx::query!("DELETE FROM buff WHERE id = $1", *buffID)
        .execute(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound(format!("Delete document failed.\nDatabase error: {}", err))
        })?;

    // 删除文件系统中的文件
    if !file_path.is_empty() {
        tokio::fs::remove_file(&file_path).await.map_err(|err| {
            println!("File delete error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to delete document file from storage")
        })?;
    }

    RecordLog(claims.id, &pool, format!("(Administrator) Refuse document in buffer of ID {}", *buffID)).await?;
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

    let documents = sqlx::query!("
        SELECT docs.id, title, author, \"user\".username AS uploaded_by, doc_type, publish_date, upload_time, download_count 
        FROM docs JOIN \"user\" ON \"user\".id = docs.uploaded_by
        WHERE title LIKE $1",
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
            uploadedBy: doc.uploaded_by.unwrap_or_default(),
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
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckUser(&pool, &request).await?;

    // 查询文件路径
    let document = sqlx::query!("SELECT file_path FROM docs WHERE id = $1", *docsID)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|err| {
            println!("Database error: {:?}", err);
            actix_web::error::ErrorNotFound(format!("Document not found.\nDatabase error: {}", err))
        })?;

    let file_path = document.file_path.unwrap_or_default();

    // 读取文件内容
    let pdf_content = tokio::fs::read(&file_path).await.map_err(|err| {
        println!("File read error: {:?}", err);
        actix_web::error::ErrorInternalServerError("Failed to read PDF file")
    })?;

    // 更新下载次数
    sqlx::query!("UPDATE docs SET download_count = download_count + 1 WHERE id = $1", *docsID)
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to update download count.\nDatabase error: {}", err))
    })?;

    RecordLog(claims.id, &pool, format!("Download document ID {}", docsID)).await?;
    Ok(HttpResponse::Ok().content_type("application/pdf").body(pdf_content))
}


#[put("/docs/{id}")]
async fn Edit(
    pool: web::Data<PgPool>,
    docsID: web::Path<i64>,
    docsReq: Json<DocumentRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, Error> {
    let claims = CheckAdmin(&pool, &request).await?;

    // 保存新的文件内容
    let new_file_path = save_file(&docsReq.pdfContent, "./uploads/docs", "pdf")
        .await
        .map_err(|err| {
            println!("File save error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to save PDF file")
        })?;

    // 更新数据库记录
    sqlx::query!(
        "UPDATE docs SET title = $1, author = $2, doc_type = $3, file_path = $4, publish_date = $5 WHERE id = $6",
        &docsReq.title,
        &docsReq.author,
        &docsReq.docType,
        &new_file_path,
        &docsReq.publishDate,
        *docsID
    )
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to edit document.\nDatabase error: {}", err))
    })?;

    RecordLog(claims.id, &pool, format!("Edit document ID {}", docsID)).await?;
    Ok(HttpResponse::Ok().body("Document updated successfully."))
}


#[delete("/docs/{id}")]
async fn Delete(
    pool: web::Data<PgPool>,
    docsID: web::Path<i64>,
    request: HttpRequest
) -> Result<HttpResponse, Error> {

    let claims = CheckAdmin(&pool, &request).await?;

    let mut transaction = pool.begin().await.map(|t| t).map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to start transaction.\nDatabase error: {}", err))
    })?;

    // Find file_path
    let file_path = sqlx::query!("SELECT file_path FROM docs WHERE id = $1", *docsID)
    .fetch_one(&mut transaction)
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to find document path.\nDatabase error: {}", err))
    })?.file_path.unwrap_or_default();

    // Delete file path from table
    sqlx::query!("DELETE FROM docs WHERE id = $1", *docsID)
    .execute(pool.get_ref())
    .await
    .map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to delete document.\nDatabase error: {}", err))
    })?;

    transaction.commit().await.map(|_| ()).map_err(|err| {
        println!("Database error: {:?}", err);
        actix_web::error::ErrorInternalServerError(format!("Failed to commit transaction.\nDatabase error: {}", err))
    })?;

    // Delete file (PHYSICAL)
    if !file_path.is_empty() {
        tokio::fs::remove_file(&file_path).await.map_err(|err| {
            println!("File delete error: {:?}", err);
            actix_web::error::ErrorInternalServerError("Failed to delete document file from storage")
        })?;
    }

    RecordLog(claims.id, &pool, format!("(Administrator) Delete document of ID {}", docsID)).await?;
    Ok(HttpResponse::Ok().body("Document deleted successfully."))
}
