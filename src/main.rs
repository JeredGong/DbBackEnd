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
            .service(user::Login)           // POST     /login                      User login
            .service(user::Register)        // POST     /register                   User Register (Admin)
            .service(user::GetInfo)         // GET      /info                       Fetch user info
            .service(user::GetImage)        // GET      /image                      Fetch user image
            .service(user::ModifyImage)     // PUT      /image                      Modify user image
            .service(user::ModifyPasswd)    // PUT      /password                   Modify user password
            .service(user::ModifyEmail)     // PUT      /email                      Modify user email
            .service(user::Cancel)          // DELETE   /cancel                     Cancel user account
            .service(user::Delete)          // DELETE   /delete/{id}                Delete user account (Admin)
            .service(user::Users)           // GET      /users                      Fetch user list (Admin)
            .service(docs::Add)             // POST     /documents                  Upload a document
            .service(docs::List)            // GET      /documents/all              Fetch all documents
            .service(docs::GetBuffer)       // GET      /documents/buffer           Fetch documents in buffer (Admin)
            .service(docs::DownloadBuffer)  // GET      /documents/buffer/{id}      Download a document in buffer for exam (Admin)
            .service(docs::ConfirmBuffer)   // POST     /documents/buffer/{id}      Confirm a document upload is valid (Admin)
            .service(docs::Search)          // GET      /documents/{title}          Search documents by title
            .service(docs::Download)        // GET      /documents/download/{id}    Download a document
            .service(docs::Edit)            // PUT      /documents/{id}             Edit documents information (Admin)
            .service(docs::Delete)          // DELETE   /documents/{id}             Delete a document (Admin)
            .service(book::Add)             // POST     /books                      Add a book (Admin)
            .service(book::List)            // GET      /books/all                  Fetch all books (Admin)
            .service(book::Search)          // GET      /books/{title}              Search books by title
            .service(book::Edit)            // PUT      /books/{id}                 Edit books information (Admin)
            .service(book::Delete)          // DELETE   /books/{id}                 Delete a book (Admin)
            .service(book::Borrow)          // POST     /borrow/{id}                Borrow a book
            .service(book::Return)          // POST     /return/{id}                Return a book
            .service(book::Records)         // GET      /borrowings/all             Fetch all borrowing records (Admin)
            .service(book::UserRecords)     // GET      /borrowings                 Fetch user borrowing records
            .service(stat::Info)            // GET      /statistics                 Fetch statistics (Admin)
            .service(logs::Logs)            // GET      /logs                       Fetch logs (Admin)
    })
    .bind("localhost:9876")?
    .run()
    .await
}
