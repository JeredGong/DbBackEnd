#![allow(unused)]
#![allow(non_snake_case)]

use std::any::Any;

use actix_cors::Cors;
use actix_web::{ middleware::Logger, web::{ self, service }, App, HttpResponse, HttpServer };
use sqlx::PgPool;
use table::users;
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
            .service(users::Delete)
    })
    .bind("localhost:9876")?
    .run()
    .await
}
