#![allow(non_snake_case)]

use actix_cors::Cors;
use actix_web::{middleware::Logger, web::{self}, App, HttpResponse, HttpServer};
use sqlx::PgPool;
use table::{book::{self}, docs, logs, stat, user};
pub mod table;

async fn index() -> HttpResponse {
    HttpResponse::Ok().body("Hello, world")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let databaseURL = std::env::var("DATABASE_URL").expect("Database URL undefined.");
    let pool = PgPool::connect(&databaseURL).await.unwrap();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));    // Enable logger

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Cors::permissive())   // Open CORS permission
            // .wrap(Cors::default().allowed_origin("http://localhost:52330"))
            .app_data(web::Data::new(pool.clone()))
            .route("/", web::get().to(index))
            .service(user::Login)           // POST     /user/login             User login
            .service(user::Register)        // POST     /user/register          User Register (Admin)
            .service(user::GetInfo)         // GET      /user/info              Fetch user info
            .service(user::GetImage)        // GET      /user/image             Fetch user image
            .service(user::ModifyImage)     // PUT      /user/image             Modify user image
            .service(user::ModifyPasswd)    // PUT      /user/password          Modify user password
            .service(user::ModifyEmail)     // PUT      /user/email             Modify user email
            .service(user::Cancel)          // DELETE   /user/cancel            Cancel user account
            .service(user::Delete)          // DELETE   /user/delete/{id}       Delete user account (Admin)
            .service(user::Users)           // GET      /user/all               Fetch user list (Admin)
            .service(user::Upgrade)         // POST     /user/upgrade/{id}      Upgrade user (Admin)
            .service(user::Dngrade)         // POST     /user/dngrade/{id}      Dngrade user (Admin)
            .service(docs::Add)             // POST     /docs                   Upload a document
            .service(docs::List)            // GET      /docs/all               Fetch all documents
            .service(docs::GetBuffer)       // GET      /docs/buffer            Fetch documents in buffer (Admin)
            .service(docs::DownloadBuffer)  // GET      /docs/buffer/{id}       Download a document in buffer for exam (Admin)
            .service(docs::EditBuffer)      // PUT      /docs/buffer/{id}       Edit a document in buffer (Admin)
            .service(docs::ConfirmBuffer)   // POST     /docs/buffer/{id}       Confirm a document upload is valid (Admin)
            .service(docs::RefuseBuffer)    // DELETE   /docs/buffer/{id}       Refuse a document upload is valid (Admin)
            .service(docs::Search)          // GET      /docs/search/{title}    Search documents by title
            .service(docs::Download)        // GET      /docs/{id}              Download a document
            .service(docs::Edit)            // PUT      /docs/{id}              Edit documents information (Admin)
            .service(docs::Delete)          // DELETE   /docs/{id}              Delete a document (Admin)
            .service(book::Add)             // POST     /book                   Add a book (Admin)
            .service(book::List)            // GET      /book/all               Fetch all books (Admin)
            .service(book::Search)          // GET      /book/search/{title}    Search books by title
            .service(book::Edit)            // PUT      /book/{id}              Edit books information (Admin)
            .service(book::Delete)          // DELETE   /book/{id}              Delete a book (Admin)
            .service(book::Borrow)          // POST     /book/borrow/{id}       Borrow a book
            .service(book::Return)          // POST     /book/return/{id}       Return a book
            .service(book::Records)         // GET      /book/borrowings/all    Fetch all borrowing records (Admin)
            .service(book::GetBookById)     // GET      /book/{id}              Fetch all borrowing records (Admin)
            .service(book::UserRecords)     // GET      /book/borrowings        Fetch user borrowing records
            .service(stat::Statistics)      // GET      /stat                   Fetch statistics (Admin)
            .service(logs::Logs)            // GET      /logs                   Fetch logs (Admin)
    })
    .bind("localhost:9876")?
    .run()
    .await
}
