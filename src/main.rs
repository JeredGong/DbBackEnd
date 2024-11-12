// #![allow(unused)]
#![allow(non_snake_case)]

use actix_cors::Cors;
use actix_web::{ middleware::Logger, web::{ self }, App, HttpResponse, HttpServer };
use sqlx::PgPool;
use table::{docs, users};
pub mod table;

async fn index() -> HttpResponse {
    println!("Require for index");
    HttpResponse::Ok().body("Hello, world")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let databaseURL = std::env::var("DATABASE_URL").expect("Database URL undefined.");
    let pool = PgPool::connect(&databaseURL).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Cors::permissive())
            // .wrap(Cors::default().allowed_origin("http://localhost:52330"))
            .app_data(web::Data::new(pool.clone()))
            .route("/", web::get().to(index))
            .service(users::Login)
            .service(users::Register)
            .service(users::Cancel)
            .service(users::Delete)
            .service(users::Users)
            .service(docs::add_document)
            .service(docs::list_documents)
            .service(docs::download_document)
            .service(docs::delete_document)
            .service(docs::edit_document)
    })
    .bind("localhost:9876")?
    .run()
    .await
}
