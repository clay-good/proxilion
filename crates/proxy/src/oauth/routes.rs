//! OAuth route handlers.

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Duration, Utc};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use shared_types::provenance::pca::ExecutorBinding;
use sqlx::types::Json as SqlxJson;
use tracing::{info, instrument};
use uuid::Uuid;

use super::bridge::validate_federation_token;
use super::error::OAuthError;
use super::state::OAuthState;
use crate::crypto::{Bearer, Ciphertext, verify_pkce_s256};
use crate::pic::CachedPca;

pub fn router(state: OAuthState) -> Router {
    Router::new()
        .route("/oauth/google/authorize", get(authorize))
        .route("/oauth/bridge/callback", get(bridge_callback))
        .route("/oauth/google/callback", get(google_callback))
        .route("/oauth/google/token", post(token))
        .with_state(state)
}

fn pct(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

// ---------- 1. GET /oauth/google/authorize ----------

#[derive(Debug, Deserialize)]
struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    scope: String,
}

#[instrument(skip(state), fields(client_id = %params.client_id))]
async fn authorize(
    State(state): State<OAuthState>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Redirect, OAuthError> {
    let result = authorize_inner(state, params).await;
    // spec.md §3.2 — `proxilion_oauth_authorize_total{result="ok|denied|error"}`.
    // `denied` covers auth-level failures (bad_request, unknown_client,
    // session_gone, bridge_rejected, pkce_fail, bad_auth_code, pic_invariant);
    // `error` covers system failures (upstream, db, crypto, internal).
    let label = match &result {
        Ok(_) => "ok",
        Err(e) => oauth_error_class(e),
    };
    metrics::counter!("proxilion_oauth_authorize_total", "result" => label).increment(1);
    result
}

fn oauth_error_class(e: &OAuthError) -> &'static str {
    match e {
        OAuthError::BadRequest(_)
        | OAuthError::UnknownClient
        | OAuthError::SessionGone
        | OAuthError::BridgeRejected(_)
        | OAuthError::PkceFail
        | OAuthError::BadAuthCode
        | OAuthError::PicInvariant(_) => "denied",
        OAuthError::Upstream(_)
        | OAuthError::Db(_)
        | OAuthError::Crypto
        | OAuthError::Internal(_) => "error",
    }
}

async fn authorize_inner(
    state: OAuthState,
    params: AuthorizeParams,
) -> Result<Redirect, OAuthError> {
    if params.response_type != "code" {
        return Err(OAuthError::BadRequest("unsupported response_type".into()));
    }
    if params.code_challenge_method != "S256" {
        return Err(OAuthError::BadRequest("only S256 PKCE is supported".into()));
    }

    // 0013_oauth_client_revocation.sql — revoked clients are refused
    // here. They stay in the table so historical sessions / audit rows
    // referencing the id continue to resolve.
    let allowed: Option<(Vec<String>,)> = sqlx::query_as(
        "SELECT redirect_uris FROM oauth_clients
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(&params.client_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((redirect_uris,)) = allowed else {
        return Err(OAuthError::UnknownClient);
    };
    if !redirect_uris.iter().any(|u| u == &params.redirect_uri) {
        return Err(OAuthError::BadRequest("redirect_uri not allowed".into()));
    }

    let session_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(10);
    sqlx::query(
        r#"
        INSERT INTO oauth_sessions (id, client_id, agent_redirect_uri, agent_state,
            agent_code_challenge, agent_code_challenge_method, agent_requested_scope, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(session_id)
    .bind(&params.client_id)
    .bind(&params.redirect_uri)
    .bind(&params.state)
    .bind(&params.code_challenge)
    .bind("S256")
    .bind(&params.scope)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    let url = format!(
        "{}?client_id=proxilion&redirect_uri={}/oauth/bridge/callback&state={}",
        state.federation_bridge_authorize_url,
        pct(&state.proxy_base_url),
        session_id
    );
    Ok(Redirect::temporary(&url))
}

// ---------- 2. GET /oauth/bridge/callback ----------

#[derive(Debug, Deserialize)]
struct BridgeCallback {
    state: Uuid,
    federation_token: String,
}

#[instrument(skip(state, params), fields(session = %params.state))]
async fn bridge_callback(
    State(state): State<OAuthState>,
    Query(params): Query<BridgeCallback>,
) -> Result<Redirect, OAuthError> {
    let result = bridge_callback_inner(state, params).await;
    // spec.md §3.2 — `proxilion_oauth_callback_total{idp,result}` for the
    // bridge leg. `idp` is inferred from the JWT iss claim when present
    // (`okta | azure | google | oidc | unknown`); production bridges
    // always emit iss, the stub-friendly fallback is `unknown`. Same
    // result classifier as the Google leg.
    let (idp, label) = match &result {
        Ok((_, idp)) => (*idp, "ok"),
        Err((e, idp)) => (*idp, oauth_error_class(e)),
    };
    metrics::counter!(
        "proxilion_oauth_callback_total",
        "idp" => idp,
        "result" => label,
    )
    .increment(1);
    result.map(|(r, _)| r).map_err(|(e, _)| e)
}

async fn bridge_callback_inner(
    state: OAuthState,
    params: BridgeCallback,
) -> Result<(Redirect, &'static str), (OAuthError, &'static str)> {
    let claims = match validate_federation_token(&params.federation_token) {
        Ok(c) => c,
        Err(e) => return Err((e, "unknown")),
    };
    let idp = super::bridge::infer_idp(claims.iss.as_deref());
    let res = bridge_callback_body(state, params, claims).await;
    match res {
        Ok(r) => Ok((r, idp)),
        Err(e) => Err((e, idp)),
    }
}

async fn bridge_callback_body(
    state: OAuthState,
    params: BridgeCallback,
    claims: super::bridge::FederationClaims,
) -> Result<Redirect, OAuthError> {

    if let Some(b64) = claims.pca_0_cbor_b64.as_deref() {
        let cbor = B64
            .decode(b64)
            .map_err(|_| OAuthError::BridgeRejected("bad pca_0 CBOR base64".into()))?;
        crate::pic::PcaCache::new(state.db.clone())
            .insert(&CachedPca {
                pca_id: claims.pca_0_id,
                cbor,
                p_0: claims.p_0.clone(),
                ops: claims.ops.clone(),
                hop: 0,
                predecessor_id: None,
                signature: vec![],
                pic_profile: crate::pic::cache::CURRENT_PIC_PROFILE.to_string(),
            })
            .await
            .map_err(|e| OAuthError::Internal(e.to_string()))?;
    }

    let session = sqlx::query_as::<_, (String,)>(
        "UPDATE oauth_sessions
            SET pca_0_id = $1, p_0 = $2, granted_ops = $3
          WHERE id = $4 AND expires_at > now()
        RETURNING agent_requested_scope",
    )
    .bind(claims.pca_0_id)
    .bind(&claims.p_0)
    .bind(SqlxJson(serde_json::to_value(&claims.ops).unwrap()))
    .bind(params.state)
    .fetch_optional(&state.db)
    .await?;
    let Some((agent_requested_scope,)) = session else {
        return Err(OAuthError::SessionGone);
    };

    let google_scope = intersect_scope_with_ops(&agent_requested_scope, &claims.ops);

    let url = format!(
        "{}?client_id={}&redirect_uri={}/oauth/google/callback&response_type=code&scope={}&state={}&access_type=offline&prompt=consent",
        state.google.auth_url,
        pct(&state.google.client_id),
        pct(&state.proxy_base_url),
        pct(&google_scope),
        params.state,
    );
    Ok(Redirect::temporary(&url))
}

/// Conservative pre-filter: only keep Google scopes whose ops scheme is
/// represented in PCA_0.ops. Authority for the final intersection is the
/// Trust Plane at PCA_1 issuance.
fn intersect_scope_with_ops(scope: &str, ops: &[String]) -> String {
    fn scope_implies(s: &str, ops: &[String]) -> bool {
        let scheme = match s {
            "https://www.googleapis.com/auth/drive.readonly"
            | "https://www.googleapis.com/auth/drive" => "drive:",
            "https://www.googleapis.com/auth/gmail.readonly" => "gmail:read:",
            "https://www.googleapis.com/auth/gmail.send" => "gmail:send:",
            "https://www.googleapis.com/auth/calendar.readonly" => "calendar:read:",
            "https://www.googleapis.com/auth/calendar" => "calendar:",
            "openid" | "email" | "profile" => return true,
            _ => return false,
        };
        ops.iter().any(|o| o.starts_with(scheme))
    }
    scope
        .split_whitespace()
        .filter(|s| scope_implies(s, ops))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------- 3. GET /oauth/google/callback ----------

#[derive(Debug, Deserialize)]
struct GoogleCallback {
    state: Uuid,
    code: String,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: i64,
    scope: String,
}

#[instrument(skip(state, params), fields(session = %params.state))]
async fn google_callback(
    State(state): State<OAuthState>,
    Query(params): Query<GoogleCallback>,
) -> Result<Redirect, OAuthError> {
    let result = google_callback_inner(state, params).await;
    // spec.md §3.2 — `proxilion_oauth_callback_total{idp,result}`.
    // `idp="google"` here (the other handler `bridge_callback` carries the
    // upstream IdP claim and could ride the same metric with idp="okta|azure|…"
    // once federation-bridge-bin ships; today the bridge callback is a thin
    // pass-through and skipped for metric simplicity).
    let label = match &result {
        Ok(_) => "ok",
        Err(e) => oauth_error_class(e),
    };
    metrics::counter!(
        "proxilion_oauth_callback_total",
        "idp" => "google",
        "result" => label,
    )
    .increment(1);
    result
}

async fn google_callback_inner(
    state: OAuthState,
    params: GoogleCallback,
) -> Result<Redirect, OAuthError> {
    let session: Option<(String, String, Uuid, String, SqlxJson<serde_json::Value>)> =
        sqlx::query_as(
            "SELECT agent_redirect_uri, agent_state, pca_0_id, p_0, granted_ops
               FROM oauth_sessions
              WHERE id = $1 AND pca_0_id IS NOT NULL AND expires_at > now()",
        )
        .bind(params.state)
        .fetch_optional(&state.db)
        .await?;
    let Some((agent_redirect_uri, agent_state, pca_0_id, p_0, ops_json)) = session else {
        return Err(OAuthError::SessionGone);
    };
    let pca0_ops: Vec<String> = serde_json::from_value(ops_json.0).unwrap_or_default();

    // Exchange Google authorization code for tokens.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(OAuthError::Upstream)?;
    let token_resp: GoogleTokenResponse = http
        .post(&state.google.token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &params.code),
            (
                "redirect_uri",
                &format!("{}/oauth/google/callback", state.proxy_base_url),
            ),
            ("client_id", &state.google.client_id),
            ("client_secret", &state.google.client_secret),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    // Encrypt + persist Google tokens.
    let access_ct = state
        .cipher
        .encrypt(token_resp.access_token.as_bytes())
        .map_err(|_| OAuthError::Crypto)?;
    let refresh_ct = token_resp
        .refresh_token
        .as_deref()
        .map(|t| state.cipher.encrypt(t.as_bytes()))
        .transpose()
        .map_err(|_| OAuthError::Crypto)?;
    let google_tokens_id = persist_google_tokens(
        &state.db,
        params.state,
        &access_ct,
        refresh_ct.as_ref(),
        &token_resp.scope,
        Utc::now() + Duration::seconds(token_resp.expires_in.max(0)),
    )
    .await?;

    // Load PCA_0 CBOR from cache and mint PCA_1.
    let cache = crate::pic::PcaCache::new(state.db.clone());
    let pca0 = cache
        .get(pca_0_id)
        .await
        .map_err(|e| OAuthError::Internal(e.to_string()))?
        .ok_or_else(|| OAuthError::Internal("PCA_0 not in cache".into()))?;
    let pca1_ops = narrowed_ops_for_pca1(&pca0_ops, &token_resp.scope);
    if pca1_ops.is_empty() {
        return Err(OAuthError::PicInvariant(
            "no Google scope intersected with PCA_0 ops".into(),
        ));
    }
    let binding = ExecutorBinding::new()
        .with("service", "proxilion-proxy")
        .with("session", params.state.to_string());
    let resp = state
        .pic
        .mint_successor(pca0.cbor.clone(), pca1_ops, binding)
        .await
        .map_err(|e| match e {
            crate::pic::ExecutorError::Invariant(msg) => OAuthError::PicInvariant(msg),
            other => OAuthError::Internal(other.to_string()),
        })?;

    let pca_1_cbor = B64
        .decode(&resp.pca)
        .map_err(|_| OAuthError::Internal("bad PCA_1 base64".into()))?;
    let pca_1_id = Uuid::new_v4();
    cache
        .insert(&CachedPca {
            pca_id: pca_1_id,
            cbor: pca_1_cbor,
            p_0: resp.p_0.clone(),
            ops: resp.ops.clone(),
            hop: resp.hop as i32,
            predecessor_id: Some(pca_0_id),
            signature: vec![],
                pic_profile: crate::pic::cache::CURRENT_PIC_PROFILE.to_string(),
        })
        .await
        .map_err(|e| OAuthError::Internal(e.to_string()))?;

    // Mint bearer + register in agent_bearers, then stash the plaintext
    // (encrypted) in auth_codes for the immediate /token exchange.
    let bearer = Bearer::generate();
    let bearer_hash = bearer.hash();
    let bearer_ct = state
        .cipher
        .encrypt(bearer.as_str().as_bytes())
        .map_err(|_| OAuthError::Crypto)?;
    let scope = token_resp.scope.clone();

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO agent_bearers
            (bearer_sha256, session_id, pca_1_id, google_tokens_id, scope)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(bearer_hash.as_bytes())
    .bind(params.state)
    .bind(pca_1_id)
    .bind(google_tokens_id)
    .bind(&scope)
    .execute(&mut *tx)
    .await?;

    let auth_code = new_auth_code();
    sqlx::query(
        "INSERT INTO auth_codes
            (code, bearer_sha256_pending, session_id,
             code_challenge, code_challenge_method,
             bearer_ciphertext, bearer_nonce, expires_at)
         SELECT $1, $2, id, agent_code_challenge, agent_code_challenge_method,
                $3, $4, now() + interval '30 seconds'
           FROM oauth_sessions WHERE id = $5",
    )
    .bind(&auth_code)
    .bind(bearer_hash.as_bytes())
    .bind(&bearer_ct.bytes)
    .bind(&bearer_ct.nonce)
    .bind(params.state)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    info!(p_0 = %p_0, pca_1_id = %pca_1_id, "issued bearer + auth code");

    let url = format!(
        "{}?code={}&state={}",
        agent_redirect_uri,
        pct(&auth_code),
        pct(&agent_state),
    );
    Ok(Redirect::temporary(&url))
}

fn narrowed_ops_for_pca1(pca0_ops: &[String], granted_scope: &str) -> Vec<String> {
    let prefixes: Vec<&'static str> = granted_scope
        .split_whitespace()
        .filter_map(|s| match s {
            "https://www.googleapis.com/auth/drive.readonly"
            | "https://www.googleapis.com/auth/drive" => Some("drive:"),
            "https://www.googleapis.com/auth/gmail.readonly" => Some("gmail:read:"),
            "https://www.googleapis.com/auth/gmail.send" => Some("gmail:send:"),
            "https://www.googleapis.com/auth/calendar.readonly" => Some("calendar:read:"),
            "https://www.googleapis.com/auth/calendar" => Some("calendar:"),
            _ => None,
        })
        .collect();
    pca0_ops
        .iter()
        .filter(|op| prefixes.iter().any(|p| op.starts_with(p)))
        .cloned()
        .collect()
}

async fn persist_google_tokens(
    db: &sqlx::PgPool,
    session_id: Uuid,
    access: &Ciphertext,
    refresh: Option<&Ciphertext>,
    scope: &str,
    expires_at: DateTime<Utc>,
) -> Result<Uuid, OAuthError> {
    let (refresh_bytes, refresh_nonce) = match refresh {
        Some(c) => (Some(c.bytes.as_slice()), Some(c.nonce.as_slice())),
        None => (None, None),
    };
    let row: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO google_tokens
            (session_id, access_token_ciphertext, access_token_nonce,
             refresh_token_ciphertext, refresh_token_nonce, scope, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
    )
    .bind(session_id)
    .bind(&access.bytes)
    .bind(&access.nonce)
    .bind(refresh_bytes)
    .bind(refresh_nonce)
    .bind(scope)
    .bind(expires_at)
    .fetch_one(db)
    .await?;
    Ok(row.0)
}

fn new_auth_code() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf)
}

// ---------- 4. POST /oauth/google/token ----------

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    #[allow(dead_code)]
    redirect_uri: String,
    #[allow(dead_code)]
    client_id: String,
    code_verifier: String,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
}

#[instrument(skip(state, form))]
async fn token(
    State(state): State<OAuthState>,
    Form(form): Form<TokenForm>,
) -> Result<Response, OAuthError> {
    if form.grant_type != "authorization_code" {
        return Err(OAuthError::BadRequest("unsupported grant_type".into()));
    }

    let mut tx = state.db.begin().await?;
    let row: Option<(Vec<u8>, Uuid, String, String, Vec<u8>, Vec<u8>, DateTime<Utc>, Option<DateTime<Utc>>)> =
        sqlx::query_as(
            "SELECT bearer_sha256_pending, session_id, code_challenge, code_challenge_method,
                    bearer_ciphertext, bearer_nonce, expires_at, consumed_at
               FROM auth_codes
              WHERE code = $1
              FOR UPDATE",
        )
        .bind(&form.code)
        .fetch_optional(&mut *tx)
        .await?;
    let Some((bearer_sha, session_id, challenge, method, bearer_ct, bearer_nonce, expires_at, consumed_at)) = row
    else {
        return Err(OAuthError::BadAuthCode);
    };
    if consumed_at.is_some() || expires_at < Utc::now() || method != "S256" {
        return Err(OAuthError::BadAuthCode);
    }
    verify_pkce_s256(&form.code_verifier, &challenge).map_err(|_| OAuthError::PkceFail)?;

    sqlx::query("UPDATE auth_codes SET consumed_at = now() WHERE code = $1")
        .bind(&form.code)
        .execute(&mut *tx)
        .await?;

    let (scope,): (String,) = sqlx::query_as(
        "SELECT scope FROM agent_bearers
          WHERE bearer_sha256 = $1 AND session_id = $2 AND revoked_at IS NULL",
    )
    .bind(&bearer_sha)
    .bind(session_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(OAuthError::BadAuthCode)?;

    tx.commit().await?;

    let bearer_plaintext = state
        .cipher
        .decrypt(&Ciphertext {
            nonce: bearer_nonce,
            bytes: bearer_ct,
        })
        .map_err(|_| OAuthError::Crypto)?;
    let access_token = String::from_utf8(bearer_plaintext).map_err(|_| OAuthError::Crypto)?;

    let body = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: 3600,
        scope,
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}
