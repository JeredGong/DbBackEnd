use actix_web::{ delete, get, post, put, web, HttpRequest, HttpResponse, Error };
use sqlx::PgPool;
use actix_web::web::Json;
use time::{ OffsetDateTime, UtcOffset };
use super::users::{ CheckIs, UnwrapToken, Role };
/*
 *  PostgreSQL schema 
 *      books(
 *          id              bigint PRIMARY KEY,
 *          title           character varying(256),
 *          published_date  timestamp with time zone,
 *          author          character varying(256),
 *          status          (0: available, 1: borrowed, 2: lost)
 *      )
 */
#[derive(serde::Deserialize)]
struct Bookrequest {
    title: String
}