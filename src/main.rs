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
            .service(user::Login)
            .service(user::Register)
            .service(user::GetImage)
            .service(user::ModifyImage)
            .service(user::ModifyPasswd)
            .service(user::Cancel)
            .service(user::Delete)
            .service(user::Users)
            .service(docs::Add)
            .service(docs::List)
            .service(docs::GetBuffer)
            .service(docs::DownloadBuffer)
            .service(docs::ConfirmBuffer)
            .service(docs::Search)
            .service(docs::Download)
            .service(docs::Delete)
            .service(docs::Edit)
            .service(book::Add)
            .service(book::List)
            .service(book::Search)
            .service(book::Delete)
            .service(book::Edit)
            .service(book::Borrow)
            .service(book::Return)
            .service(book::Records)
            .service(book::UserRecords)
            .service(stat::Info)
            .service(logs::Logs)
    })
    .bind("localhost:9876")?
    .run()
    .await
}
