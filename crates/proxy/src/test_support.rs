//! Shared scaffolding for DB-backed integration-style unit tests.
//!
//! These tests exercise real handlers against a real Postgres so the SQL,
//! the migrations, and the request/response wiring are covered end-to-end
//! (the proxy is a binary-only crate, so `crates/proxy/tests/` can't reach
//! these internals — in-module `#[cfg(test)]` tests are the only way to drive
//! private handlers directly).
//!
//! They are **opt-in**: a test calls [`pool`] and returns early when
//! `PROXILION_TEST_DATABASE_URL` is unset, so the default `cargo test` run
//! (and CI, which has no Postgres service today) simply skips them and stays
//! green. To run them:
//!
//! ```sh
//! docker run -d --name pg -e POSTGRES_USER=proxilion -e POSTGRES_PASSWORD=proxilion \
//!     -e POSTGRES_DB=proxilion_test -p 55432:5432 postgres:16-alpine
//! PROXILION_TEST_DATABASE_URL=postgres://proxilion:proxilion@localhost:55432/proxilion_test \
//!     cargo test -p proxy --  --include-ignored db_backed
//! ```

#![cfg(test)]

use sqlx::PgPool;

/// The env var that opts a process into DB-backed tests.
pub const TEST_DB_ENV: &str = "PROXILION_TEST_DATABASE_URL";

/// Connect to the test database (if configured) and apply all migrations,
/// returning a ready pool. Returns `None` — so the caller `return`s and the
/// test is skipped — when `PROXILION_TEST_DATABASE_URL` is unset.
///
/// `sqlx::migrate!` is idempotent and takes an advisory lock, so concurrent
/// test tasks sharing one database apply migrations safely.
pub async fn pool() -> Option<PgPool> {
    let url = std::env::var(TEST_DB_ENV).ok().filter(|u| !u.is_empty())?;
    let pool = PgPool::connect(&url)
        .await
        .unwrap_or_else(|e| panic!("connect {TEST_DB_ENV}: {e}"));
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations to the test database");
    Some(pool)
}
