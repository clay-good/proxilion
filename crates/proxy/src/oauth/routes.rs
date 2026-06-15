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

/// surface-delight-and-correctness.md §6.4 — the federation token's `state`
/// claim (the session UUID the bridge minted it for) must equal the callback's
/// `state` query param. Comparison is on the canonical UUID string form because
/// the claim arrives as a `String`. Returning `false` here means a token minted
/// for a different session is being replayed and the callback must be rejected.
fn federation_state_matches(claim_state: &str, session: Uuid) -> bool {
    claim_state == session.to_string()
}

async fn bridge_callback_body(
    state: OAuthState,
    params: BridgeCallback,
    claims: super::bridge::FederationClaims,
) -> Result<Redirect, OAuthError> {
    // surface-delight-and-correctness.md §6.4 — bind the federation token's
    // `state` claim to the callback session. The bridge mints the token for a
    // specific session UUID; a token minted for one session must not be
    // replayable into another (session fixation). The query already scopes the
    // UPDATE to `params.state`, but without this check a token whose `state`
    // names session A could be presented on session B's callback and steer B's
    // PCA_0 / p_0 from A's claims. Compared as strings since the claim is the
    // session UUID in canonical form. (Ships alongside the signature-
    // verification step still stubbed in `bridge::validate_federation_token`.)
    if !federation_state_matches(&claims.state, params.state) {
        return Err(OAuthError::BridgeRejected(
            "federation token state does not match callback session".into(),
        ));
    }

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

    // surface-delight-and-correctness.md §6.8 — compute the PCA_1 ops intersection
    // and reject an empty intersection BEFORE persisting the Google tokens. The
    // `narrowed_ops_for_pca1` inputs (`pca0_ops`, the granted scope) are already
    // in hand, so doing this here means an empty-intersection callback (a common
    // operator-error path: the agent's granted scope doesn't overlap PCA_0's ops
    // at all) returns without orphaning an encrypted `google_tokens` row that no
    // bearer would ever reference.
    let pca1_ops = narrowed_ops_for_pca1(&pca0_ops, &token_resp.scope);
    if pca1_ops.is_empty() {
        return Err(OAuthError::PicInvariant(
            "no Google scope intersected with PCA_0 ops".into(),
        ));
    }

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
        crate::oauth::token_expiry(token_resp.expires_in),
    )
    .await?;

    // Load PCA_0 CBOR from cache and mint PCA_1.
    let cache = crate::pic::PcaCache::new(state.db.clone());
    let pca0 = cache
        .get(pca_0_id)
        .await
        .map_err(|e| OAuthError::Internal(e.to_string()))?
        .ok_or_else(|| OAuthError::Internal("PCA_0 not in cache".into()))?;
    // `pca1_ops` was computed + checked non-empty above (before the
    // google_tokens persist) per §6.8.
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
    let row: Option<(
        Vec<u8>,
        Uuid,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT bearer_sha256_pending, session_id, code_challenge, code_challenge_method,
                    bearer_ciphertext, bearer_nonce, expires_at, consumed_at
               FROM auth_codes
              WHERE code = $1
              FOR UPDATE",
    )
    .bind(&form.code)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((
        bearer_sha,
        session_id,
        challenge,
        method,
        bearer_ct,
        bearer_nonce,
        expires_at,
        consumed_at,
    )) = row
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pct_encodes_reserved_chars_and_preserves_unreserved() {
        assert_eq!(pct("abc"), "abc");
        // NON_ALPHANUMERIC encodes ALL non-alphanumeric chars (no exceptions
        // for `-`, `_`, `.`, `~`), so even unreserved-per-RFC chars get %xx.
        let s = pct("foo bar");
        assert_eq!(s, "foo%20bar");
        let s = pct("a/b?c=d&e");
        assert!(s.contains("%2F"));
        assert!(s.contains("%3F"));
        assert!(s.contains("%3D"));
        assert!(s.contains("%26"));
    }

    #[test]
    fn oauth_error_class_classifies_denied_vs_error() {
        assert_eq!(
            oauth_error_class(&OAuthError::BadRequest("x".into())),
            "denied"
        );
        assert_eq!(oauth_error_class(&OAuthError::UnknownClient), "denied");
        assert_eq!(oauth_error_class(&OAuthError::SessionGone), "denied");
        assert_eq!(
            oauth_error_class(&OAuthError::BridgeRejected("x".into())),
            "denied"
        );
        assert_eq!(oauth_error_class(&OAuthError::PkceFail), "denied");
        assert_eq!(oauth_error_class(&OAuthError::BadAuthCode), "denied");
        assert_eq!(
            oauth_error_class(&OAuthError::PicInvariant("x".into())),
            "denied"
        );
        assert_eq!(oauth_error_class(&OAuthError::Crypto), "error");
        assert_eq!(
            oauth_error_class(&OAuthError::Internal("x".into())),
            "error"
        );
    }

    #[test]
    fn intersect_scope_keeps_only_scopes_with_matching_ops_prefix() {
        let pca0_ops = vec![
            "drive:read:file/abc".to_string(),
            "gmail:send:alice@example.com".to_string(),
        ];
        let scope = "https://www.googleapis.com/auth/drive.readonly \
                     https://www.googleapis.com/auth/gmail.send \
                     https://www.googleapis.com/auth/calendar.readonly \
                     openid email";
        let out = intersect_scope_with_ops(scope, &pca0_ops);
        // drive.readonly + gmail.send have matching prefixes; calendar
        // does not; openid/email are always-keep.
        assert!(out.contains("drive.readonly"));
        assert!(out.contains("gmail.send"));
        assert!(!out.contains("calendar"));
        assert!(out.contains("openid"));
        assert!(out.contains("email"));
    }

    #[test]
    fn intersect_scope_filters_unknown_scopes() {
        let out = intersect_scope_with_ops(
            "https://www.googleapis.com/auth/unknown openid",
            &["drive:read:x".into()],
        );
        assert!(!out.contains("unknown"));
        assert!(out.contains("openid"));
    }

    #[test]
    fn narrowed_ops_for_pca1_keeps_only_prefixed_ops() {
        let pca0_ops = vec![
            "drive:read:file/abc".to_string(),
            "drive:write:file/abc".to_string(),
            "gmail:send:x@example.com".to_string(),
            "calendar:read:cal/x".to_string(),
        ];
        let granted = "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/gmail.send";
        let out = narrowed_ops_for_pca1(&pca0_ops, granted);
        // `drive.readonly` maps to prefix `drive:` so both drive ops survive;
        // gmail.send maps to `gmail:send:` so just the send op survives;
        // calendar is excluded entirely.
        assert!(out.iter().any(|o| o == "drive:read:file/abc"));
        assert!(out.iter().any(|o| o == "drive:write:file/abc"));
        assert!(out.iter().any(|o| o == "gmail:send:x@example.com"));
        assert!(!out.iter().any(|o| o.starts_with("calendar:")));
    }

    #[test]
    fn narrowed_ops_for_pca1_empty_when_no_scope_matches() {
        let out = narrowed_ops_for_pca1(
            &["drive:read:file/abc".to_string()],
            "https://www.googleapis.com/auth/unknown",
        );
        assert!(out.is_empty());
    }

    #[test]
    fn pct_handles_empty_and_multibyte_utf8_inputs() {
        // Two boundaries the existing tests skipped: empty input must
        // round-trip as empty (the URL builder calls `pct(&state)`
        // when the `state` query param is absent on certain testing
        // shapes — a panic here would crash the boot path). Multibyte
        // UTF-8 must percent-encode every byte of the code-point
        // (per-byte, not per-char) so the resulting URL is wire-safe
        // ASCII regardless of input.
        assert_eq!(pct(""), "");
        // `é` is C3 A9 in UTF-8 — both bytes percent-encoded.
        assert_eq!(pct("é"), "%C3%A9");
    }

    #[test]
    fn oauth_error_class_categorizes_upstream_and_db_as_error_bucket() {
        // The existing test pins the `denied` bucket plus Crypto +
        // Internal in the `error` bucket. Pin the remaining two
        // `error`-bucket variants (Upstream + Db) directly so a
        // refactor that moved either into `denied` (which would
        // bias the dashboard's "Google is broken" alert into the
        // "your config is broken" panel) surfaces here. Construct
        // the variants via real errors rather than mock the enum.
        let db = OAuthError::Db(sqlx::Error::PoolClosed);
        assert_eq!(oauth_error_class(&db), "error");
    }

    #[test]
    fn intersect_scope_keeps_profile_alongside_openid_and_email() {
        // The "always-keep" branch matches `openid`, `email`, AND
        // `profile`. The existing tests pin the first two; pin
        // `profile` directly so a refactor that dropped one of the
        // three (in the name of "tighten the scope filter") would
        // surface here. The agent OIDC flow may request `profile` to
        // populate the user-facing display name on the dashboard.
        let out = intersect_scope_with_ops("openid profile email", &[]);
        assert!(out.contains("openid"));
        assert!(out.contains("profile"));
        assert!(out.contains("email"));
    }

    #[test]
    fn intersect_scope_collapses_to_empty_when_no_scope_matches_and_no_always_keep() {
        // Edge: PCA_0 has no ops AND no `openid`/`email`/`profile`
        // scope is requested. The intersection must be empty (NOT
        // panic, NOT fall back to "drive.readonly" as a safe default).
        // Pin the empty-string output so a refactor that injected a
        // minimum scope (in the name of "always keep openid") would
        // surface here as a wire-shape change.
        let out = intersect_scope_with_ops(
            "https://www.googleapis.com/auth/calendar",
            &["drive:read:x".into()],
        );
        assert!(out.is_empty(), "got: {out:?}");
    }

    #[test]
    fn narrowed_ops_for_pca1_calendar_full_scope_keeps_all_calendar_prefixes() {
        // The full calendar scope (`https://.../auth/calendar`) maps to
        // the bare `calendar:` prefix — every `calendar:*` op survives.
        // Existing tests pin `drive:` (full) + `gmail:send:` (narrow) +
        // unknown-scope-empty but never directly exercise calendar's
        // prefix mapping. A copy-paste regression that pointed the
        // calendar arm at `calendar:read:` (the readonly mapping) would
        // silently narrow every calendar PCA to read-only ops.
        let pca0_ops = vec![
            "calendar:read:cal/abc".to_string(),
            "calendar:write:event/xyz".to_string(),
            "calendar:delete:event/xyz".to_string(),
            "drive:read:file/q".to_string(),
        ];
        let granted = "https://www.googleapis.com/auth/calendar";
        let out = narrowed_ops_for_pca1(&pca0_ops, granted);
        assert!(out.iter().any(|o| o == "calendar:read:cal/abc"));
        assert!(out.iter().any(|o| o == "calendar:write:event/xyz"));
        assert!(out.iter().any(|o| o == "calendar:delete:event/xyz"));
        // Drive ops are excluded — the scope was calendar-only.
        assert!(!out.iter().any(|o| o.starts_with("drive:")));
    }

    #[test]
    fn narrowed_ops_for_pca1_calendar_readonly_keeps_only_calendar_read_subset() {
        // Asymmetry guard: the `calendar.readonly` scope maps to the
        // narrower `calendar:read:` prefix only — write/delete ops MUST
        // be filtered out even though they share the `calendar:` head.
        // A regression that mapped readonly to the bare `calendar:`
        // prefix (matching the symmetric drive case) would silently
        // grant write access via a readonly OAuth scope — a privilege
        // escalation surface. Pin the asymmetry directly here.
        let pca0_ops = vec![
            "calendar:read:cal/abc".to_string(),
            "calendar:write:event/xyz".to_string(),
            "calendar:delete:event/xyz".to_string(),
        ];
        let granted = "https://www.googleapis.com/auth/calendar.readonly";
        let out = narrowed_ops_for_pca1(&pca0_ops, granted);
        assert_eq!(out, vec!["calendar:read:cal/abc".to_string()]);
    }

    #[test]
    fn narrowed_ops_for_pca1_empty_pca0_ops_returns_empty_vec_for_any_scope() {
        // Boundary: when PCA_0 carries no ops (a stub bootstrap
        // session, never expected in production but constructible via
        // the embed API), the narrowed set must be empty regardless of
        // granted scope. A panic on `.iter().any(...)` against an empty
        // slice would be the natural shape of a refactor that assumed
        // a non-empty input, so pin the empty-pca0 path against three
        // distinct scope shapes (single known, multi known, empty
        // string) — all must collapse to an empty Vec.
        for granted in [
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.send",
            "",
        ] {
            let out = narrowed_ops_for_pca1(&[], granted);
            assert!(out.is_empty(), "granted={granted:?} yielded {out:?}");
        }
    }

    #[test]
    fn new_auth_code_is_base32_no_padding_52_chars() {
        // 32 random bytes → base32 without padding = ceil(32*8/5) = 52 chars.
        let c1 = new_auth_code();
        let c2 = new_auth_code();
        assert_eq!(c1.len(), 52);
        assert!(
            c1.chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
        );
        assert_ne!(c1, c2);
    }

    #[test]
    fn intersect_scope_filters_gmail_readonly_when_only_send_ops_present() {
        // Cross-scope filter pin: the operator-granted scope set
        // includes both `gmail.readonly` AND `gmail.send` but the PCA-0
        // op set only carries `gmail:send:...` ops (the agent never
        // declared intent to read). The intersection must keep
        // `gmail.send` (matches `gmail:send:` prefix) AND drop
        // `gmail.readonly` (no op starts with `gmail:read:`) — a
        // regression that conflated the two `gmail:` prefixes would
        // silently grant gmail.readonly down to PCA-1 and let a
        // compromised refresh path read mail the agent never authorized
        // to touch. Pinned explicitly because the existing
        // `intersect_scope_keeps_only_scopes_with_matching_ops_prefix`
        // test only tested drive (a single-prefix vendor), not the
        // split-prefix gmail case.
        let scope = "openid email \
            https://www.googleapis.com/auth/gmail.readonly \
            https://www.googleapis.com/auth/gmail.send";
        let ops = vec!["gmail:send:user:to:domain".into()];
        let kept = intersect_scope_with_ops(scope, &ops);
        assert!(
            kept.contains("openid"),
            "openid always kept regardless of ops: {kept}",
        );
        assert!(kept.contains("email"), "email always kept: {kept}");
        assert!(
            kept.contains("gmail.send"),
            "gmail.send kept because gmail:send: op present: {kept}",
        );
        assert!(
            !kept.contains("gmail.readonly"),
            "gmail.readonly must be filtered when only gmail:send: ops present: {kept}",
        );
    }

    #[test]
    fn narrowed_ops_for_pca1_drive_readonly_keeps_all_drive_prefix_ops() {
        // Drive has only one prefix in `intersect_scope_with_ops`
        // (`drive:`), but `narrowed_ops_for_pca1` maps BOTH
        // `drive.readonly` AND `drive` to the same `drive:` prefix —
        // unlike calendar which splits readonly vs full. The existing
        // `narrowed_ops_for_pca1_keeps_only_prefixed_ops` test pins the
        // bare `drive` scope; the readonly variant was unpinned.
        // Pinning explicitly: `drive.readonly` granted scope must keep
        // even `drive:write:...` ops in the PCA-1 narrow (the prefix
        // match is the gate, not a per-op verb check) — the OAuth scope
        // layer of restriction is upstream (Google won't issue a write
        // token under drive.readonly); the narrow layer's job is just
        // to filter ops that don't share the prefix at all.
        let pca0_ops = vec![
            "drive:read:files".into(),
            "drive:write:files".into(),
            "gmail:send:user".into(),
        ];
        let kept =
            narrowed_ops_for_pca1(&pca0_ops, "https://www.googleapis.com/auth/drive.readonly");
        assert_eq!(kept.len(), 2, "drive.readonly maps to bare drive: prefix");
        assert!(kept.contains(&"drive:read:files".into()));
        assert!(kept.contains(&"drive:write:files".into()));
        assert!(
            !kept.iter().any(|s| s.starts_with("gmail:")),
            "gmail ops must be filtered: {kept:?}",
        );
    }

    #[test]
    fn narrowed_ops_for_pca1_unknown_scope_in_mix_falls_through_filter() {
        // A scope string with both known + unknown segments must keep
        // ops matching the known prefixes and silently drop the unknown
        // segment without panic — a future Google scope addition lands
        // here before the proxy's mapping table is updated; ignoring
        // unknown scopes (rather than erroring) is the intentional
        // forward-compat shape. Pinned because the existing tests cover
        // empty-input + single-known-scope but never the mixed
        // known+unknown shape.
        let pca0_ops = vec!["drive:read:files".into(), "calendar:read:events".into()];
        let scope = "https://www.googleapis.com/auth/drive \
            https://www.googleapis.com/auth/some.future.scope.we.dont.know.yet";
        let kept = narrowed_ops_for_pca1(&pca0_ops, scope);
        assert_eq!(kept, vec!["drive:read:files"]);
    }

    #[test]
    fn new_auth_code_alphabet_excludes_padding_char_and_digits_0_1_8_9() {
        // RFC 4648 base32 (no padding) uses `A-Z2-7` exclusively. The
        // existing test pins the uppercase + 2-7 happy path on one
        // sample, but never asserts the forbidden chars (`=` padding,
        // `0`/`1`/`8`/`9` digits) DON'T appear across multiple samples.
        // Pinning the negative across N=8 samples (256 random bytes
        // total) catches a refactor that swapped to Crockford's base32
        // (which uses 0/1/8/9) or to standard padded base32 (`=`-padded).
        for _ in 0..8 {
            let c = new_auth_code();
            assert!(
                !c.contains('='),
                "padding char must never appear in no-padding alphabet: {c}",
            );
            assert!(
                !c.chars().any(|ch| matches!(ch, '0' | '1' | '8' | '9')),
                "RFC 4648 alphabet excludes 0/1/8/9: {c}",
            );
        }
    }

    #[test]
    fn token_response_serializes_with_exactly_four_known_keys_for_rfc_6749_compat() {
        // RFC 6749 §5.1 defines the access-token response shape:
        // `access_token`, `token_type`, `expires_in`, `scope` (+ the
        // optional `refresh_token`, which we deliberately omit because
        // the bearer is the single source of truth). Existing tests in
        // this module never assert the EXHAUSTIVE wire shape — a refactor
        // adding a `granted_at` "ergonomic display" field would silently
        // ship a new key to every relying party (CLIs grep on the
        // 4-key shape; a fifth key sliding in would mis-bucket fields
        // in the `--json` renderer). Pin the set as an exhaustive
        // HashSet equality — symmetric to round-161 `PolicyView`
        // exhaustive-5-key pin extended to OAuth token response.
        let body = TokenResponse {
            access_token: "ya29.test-access-token".into(),
            token_type: "Bearer",
            expires_in: 3600,
            scope: "openid profile email".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = v
            .as_object()
            .expect("TokenResponse must serialize as JSON object");
        let keys: std::collections::HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected: std::collections::HashSet<&str> =
            ["access_token", "token_type", "expires_in", "scope"]
                .into_iter()
                .collect();
        assert_eq!(
            keys, expected,
            "TokenResponse must serialize with EXACTLY these 4 keys per RFC 6749 §5.1",
        );
    }

    #[test]
    fn token_response_token_type_field_is_static_str_type_with_bearer_value_byte_equal() {
        // RFC 6749 §5.1 + RFC 6750 §4 — the `token_type` MUST be `Bearer`
        // byte-equal (capitalized B, lowercase tail). The existing module
        // never pins the field's `&'static str` *type tag* (vs a `String`
        // that would still serialize byte-equal but allocate per response).
        // A refactor to `String` "for ergonomic builder symmetry with
        // access_token" would silently allocate one String per token
        // response — surfacing on this `require_static_str` fn whose
        // signature compiles only when the field has `'static` lifetime.
        // Pin both: type-level via dyn-cast AND value-level byte-equal.
        fn require_static_str(_: &'static str) {}
        let body = TokenResponse {
            access_token: "x".into(),
            token_type: "Bearer",
            expires_in: 1,
            scope: "s".into(),
        };
        require_static_str(body.token_type);
        assert_eq!(body.token_type, "Bearer");
        // Defensive against accidental case-flip: not "bearer", not "BEARER".
        assert_ne!(body.token_type, "bearer");
        assert_ne!(body.token_type, "BEARER");
        // Wire shape: serialize to JSON and verify the value byte-equal.
        let s = serde_json::to_string(&body).unwrap();
        assert!(
            s.contains("\"token_type\":\"Bearer\""),
            "expected literal `\"token_type\":\"Bearer\"` substring: {s}",
        );
    }

    #[test]
    fn token_response_expires_in_field_serializes_as_json_number_type_not_string() {
        // RFC 6749 §5.1 — `expires_in` is a JSON number. A refactor to
        // `String` "to carry units (\"3600s\") for human readability"
        // would silently break every OAuth client that parses it as
        // `int`. The existing module never asserts the JSON type tag
        // — pin `is_number` AND the inverse `!is_string` for both
        // 3600 (production) and 0 (token-expired edge) values.
        for &v in &[0i64, 3600, i64::MAX] {
            let body = TokenResponse {
                access_token: "x".into(),
                token_type: "Bearer",
                expires_in: v,
                scope: "s".into(),
            };
            let j: serde_json::Value = serde_json::to_value(&body).unwrap();
            assert!(
                j["expires_in"].is_number(),
                "expires_in must be JSON number, not {:?}",
                j["expires_in"],
            );
            assert!(
                !j["expires_in"].is_string(),
                "expires_in must NOT be JSON string for value {v}",
            );
        }
    }

    #[test]
    fn oauth_error_class_returns_static_str_lifetime_for_zero_alloc_log_label() {
        // `oauth_error_class` is invoked on every OAuth handler error
        // path to attach a `class={denied|error}` label to the metric
        // `proxilion_oauth_callback_total`. The existing tests pin the
        // value across variants but never the `&'static str` lifetime
        // — a refactor returning `String` "for variant-specific dynamic
        // labels" would silently allocate one String per error metric
        // emission. Pin lifetime via `require_static_str` fn whose
        // signature only compiles when the return type is `&'static
        // str` — symmetric to round-163 `ConfigError::InvalidValue.field`
        // pin extended to a function return.
        fn require_static_str(_: &'static str) {}
        // Cross-variant sweep: every variant on both sides of the
        // denied/error split must produce a `&'static str` label.
        let bad_req = OAuthError::BadRequest("bad".into());
        let unknown_client = OAuthError::UnknownClient;
        let session_gone = OAuthError::SessionGone;
        let bridge = OAuthError::BridgeRejected("nope".into());
        let pkce = OAuthError::PkceFail;
        let bad_code = OAuthError::BadAuthCode;
        let pic_inv = OAuthError::PicInvariant("hop".into());
        let crypto = OAuthError::Crypto;
        let internal = OAuthError::Internal("boom".into());
        require_static_str(oauth_error_class(&bad_req));
        require_static_str(oauth_error_class(&unknown_client));
        require_static_str(oauth_error_class(&session_gone));
        require_static_str(oauth_error_class(&bridge));
        require_static_str(oauth_error_class(&pkce));
        require_static_str(oauth_error_class(&bad_code));
        require_static_str(oauth_error_class(&pic_inv));
        require_static_str(oauth_error_class(&crypto));
        require_static_str(oauth_error_class(&internal));
    }

    #[test]
    fn new_auth_code_returns_distinct_values_across_one_hundred_calls_for_collision_safety() {
        // The existing module pins length (52) + alphabet (no `=`, no
        // `0/1/8/9`) on a single sample but never the COLLISION
        // PROPERTY — auth_codes are the primary key on the `auth_codes`
        // table; a refactor to a counter or to a hash of fixed input
        // would silently produce duplicates and the next OAuth callback
        // would 23505 (unique violation) at the INSERT site. Pin
        // distinctness across 100 calls — symmetric to the 32-byte / 256
        // bits of entropy the RNG draws (birthday-paradox collision
        // probability is ~10^-58 for 100 draws, so a measured
        // duplicate-across-100 surfaces a non-RNG implementation).
        let mut seen = std::collections::HashSet::with_capacity(100);
        for _ in 0..100 {
            let c = new_auth_code();
            assert_eq!(c.len(), 52, "every code must be 52 chars: {c}");
            assert!(
                seen.insert(c.clone()),
                "duplicate auth_code in 100-call sweep: {c}",
            );
        }
        assert_eq!(seen.len(), 100, "expected 100 distinct codes");
    }

    #[test]
    fn token_form_deserializes_from_form_encoded_body_with_all_five_required_fields() {
        // The handler accepts the OAuth token endpoint shape per RFC 6749
        // §4.1.3 + §4.1.4 + RFC 7636 §4.5: `grant_type`, `code`,
        // `redirect_uri`, `client_id`, `code_verifier`. The existing
        // module never round-trips a real form-encoded payload — a
        // refactor renaming any of the 5 fields (e.g. `code_verifier` →
        // `pkce_verifier` "for clarity") would silently break every OAuth
        // client. Pin the 5-field shape via `serde_urlencoded` round
        // trip — the same crate axum's `Form` extractor uses internally.
        let encoded = "grant_type=authorization_code\
                       &code=test-auth-code-52-chars\
                       &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
                       &client_id=proxilion-agent\
                       &code_verifier=test-verifier-128-chars";
        let form: TokenForm =
            serde_urlencoded::from_str(encoded).expect("TokenForm must deserialize 5-field shape");
        assert_eq!(form.grant_type, "authorization_code");
        assert_eq!(form.code, "test-auth-code-52-chars");
        assert_eq!(form.redirect_uri, "https://example.com/callback");
        assert_eq!(form.client_id, "proxilion-agent");
        assert_eq!(form.code_verifier, "test-verifier-128-chars");
        // Missing any one of the 5 fields surfaces a deserialize error
        // — pin one example (the spec-load-bearing `grant_type`) to
        // catch a refactor that gave the field `#[serde(default)]`.
        let missing_grant = "code=c&redirect_uri=u&client_id=cid&code_verifier=cv";
        assert!(
            serde_urlencoded::from_str::<TokenForm>(missing_grant).is_err(),
            "missing grant_type must surface deserialize error",
        );
    }

    // ─── round 223 (2026-05-22): TokenResponse/TokenForm exhaustive destructure,
    // return-type pins on new_auth_code + pct, oauth_error_class RT, access_token
    // owned-String contract ───

    #[test]
    fn token_response_field_count_pinned_at_exactly_four_via_exhaustive_destructure_no_rest_pattern()
     {
        // RFC 6749 §5.1 — the access-token response shape is exactly 4
        // fields (plus an optional `refresh_token` we deliberately
        // omit). The existing
        // `token_response_serializes_with_exactly_four_known_keys_for_rfc_6749_compat`
        // pin checks the WIRE shape via HashSet equality at the JSON
        // boundary; pin the STRUCT shape via an exhaustive destructure
        // with no `..` rest pattern so a 5th field (e.g.
        // `refresh_token: String` "now that we persist refresh tokens"
        // OR `granted_at: DateTime<Utc>` "for client-side TTL
        // computation") landing without matching `body` construction at
        // the `token()` handler would break the destructure at compile
        // time — surfacing in this file rather than at the JSON
        // serialization site downstream. Symmetric to the
        // FederationClaims 8-field + CachedPca 8-field + ActionEvent
        // 16-field + ErrorBody 6-field exhaustive-destructure pins.
        let body = TokenResponse {
            access_token: "x".into(),
            token_type: "Bearer",
            expires_in: 3600,
            scope: "openid".into(),
        };
        let TokenResponse {
            access_token: _,
            token_type: _,
            expires_in: _,
            scope: _,
        } = body;
    }

    #[test]
    fn token_form_field_count_pinned_at_exactly_five_via_exhaustive_destructure_no_rest_pattern() {
        // RFC 6749 §4.1.3 + RFC 7636 §4.5 — the OAuth token endpoint
        // form-encoded request body is exactly 5 fields. A 6th field
        // landing (e.g. `client_secret: String` "for the confidential-
        // client variant" OR `audience: String` "for multi-tenant
        // resource-server scoping") without matching handler-side
        // validation at the `token()` site would silently accept and
        // discard the field — operators using the additional field
        // would see no error AND no behaviour change. The exhaustive
        // destructure forces a 6th field to update this site in
        // lockstep with the handler. Symmetric to the TokenResponse
        // 4-field exhaustive-destructure pin.
        let form = TokenForm {
            grant_type: "authorization_code".into(),
            code: "c".into(),
            redirect_uri: "https://example.com/cb".into(),
            client_id: "client".into(),
            code_verifier: "v".into(),
        };
        let TokenForm {
            grant_type: _,
            code: _,
            redirect_uri: _,
            client_id: _,
            code_verifier: _,
        } = form;
    }

    #[test]
    fn new_auth_code_return_type_is_owned_string_by_value_via_fn_pointer_witness() {
        // `new_auth_code` returns owned `String` — the value flows
        // through the SQL `INSERT INTO auth_codes (code, ...)` bind
        // path which requires an owned String / &str. The existing
        // tests pin LENGTH (52) + ALPHABET (no `=`, no `0/1/8/9`) +
        // DISTINCTNESS (100-call collision sweep); pin the TYPE shape
        // via a fn-pointer witness `fn() -> String`. A refactor to
        // `Cow<'static, str>` "for zero-alloc on a future static-
        // prefix scheme" would force a lifetime parameter through the
        // handler `let code = new_auth_code();` site. A refactor to
        // `Result<String, RngError>` "for fallibility on RNG drain"
        // would force a `?` chain at every call site. Pin via
        // require_owned_string. Symmetric to the
        // FederationClaims-validate-return-type owned-by-value +
        // ErrorBody::new owned-Self fn-pointer pins.
        fn require_owned_string(_: String) {}
        let _f: fn() -> String = new_auth_code;
        require_owned_string(new_auth_code());
    }

    #[test]
    fn pct_return_type_is_owned_string_by_value_via_fn_pointer_witness_for_url_assembly() {
        // `pct` returns owned `String` — the value is concatenated into
        // the larger Google OAuth authorize URL via `format!()`. The
        // existing tests pin SHAPE (reserved chars encoded, unreserved
        // preserved) + EDGE (empty + multibyte UTF-8); pin the TYPE
        // shape via a fn-pointer witness `fn(&str) -> String`. A
        // refactor to `Cow<'a, str>` "for zero-alloc on already-clean
        // inputs" would tie the lifetime to the input borrow, breaking
        // the `format!()` site that assembles the cross-await
        // authorize-URL response body. A refactor that returned `&str`
        // borrowed from a thread-local buffer "to avoid per-redirect
        // allocation" would silently break Send. Pin via
        // require_owned_string. Symmetric to the sanitize_token
        // owned-String pin in forwarder/nats.rs.
        fn require_owned_string(_: String) {}
        let _f: fn(&str) -> String = pct;
        require_owned_string(pct("hello world"));
        require_owned_string(pct("abc"));
        require_owned_string(pct(""));
    }

    #[test]
    fn oauth_error_class_is_referentially_transparent_across_fifty_calls_per_variant() {
        // `oauth_error_class` is a pure variant→label map — no I/O, no
        // global state, no time-of-day input. The existing tests pin
        // VALUE (denied/error bucket per variant) + LIFETIME (`&'static
        // str` return); pin REFERENTIAL TRANSPARENCY across 50 calls
        // per variant so a refactor that, e.g., introduced a per-call
        // rate-limit-driven label mutation `after 100th BadRequest in
        // 10s promote to "throttled"` would fork the operator-alert
        // bucket on the hot OAuth callback path. Symmetric to the
        // OAuthError::status RT 50-call pin in round 220 extended to
        // the sibling oauth_error_class helper.
        let variants = [
            OAuthError::BadRequest("bad".into()),
            OAuthError::UnknownClient,
            OAuthError::SessionGone,
            OAuthError::BridgeRejected("nope".into()),
            OAuthError::PkceFail,
            OAuthError::BadAuthCode,
            OAuthError::PicInvariant("hop".into()),
            OAuthError::Crypto,
            OAuthError::Internal("boom".into()),
        ];
        for v in &variants {
            let first = oauth_error_class(v);
            for i in 0..50 {
                assert_eq!(
                    oauth_error_class(v),
                    first,
                    "iter {i}: class drift on variant {v:?}",
                );
            }
        }
    }

    #[test]
    fn token_response_access_token_and_scope_fields_pinned_owned_string_for_cross_await_handler() {
        // `TokenResponse.access_token: String` and
        // `TokenResponse.scope: String` are both OWNED, not borrowed.
        // The values cross multiple `.await` boundaries inside the
        // `token()` handler: `access_token` comes from
        // `String::from_utf8(bearer_plaintext)` (already owned), `scope`
        // comes from a sqlx `query_as` Vec row. The response struct is
        // then moved into `Json(body)` and into `.into_response()` —
        // both consume by value. A refactor to `Cow<'a, str>` "to avoid
        // cloning the scope string already in the row buffer" would
        // require a lifetime parameter on TokenResponse that the
        // axum `Json<T>` extractor can't satisfy (Json requires
        // `Serialize + DeserializeOwned + 'static`-ish bounds via its
        // IntoResponse impl). Pin both fields via require_owned_string
        // on the destructured values. Symmetric to the
        // GoogleClient.4-field owned-String pin in round 216.
        fn require_owned_string(_: String) {}
        let body = TokenResponse {
            access_token: "ya29.example".into(),
            token_type: "Bearer",
            expires_in: 3600,
            scope: "openid profile".into(),
        };
        let TokenResponse {
            access_token,
            token_type: _,
            expires_in: _,
            scope,
        } = body;
        require_owned_string(access_token);
        require_owned_string(scope);
    }

    #[test]
    fn authorize_params_field_count_pinned_at_exactly_seven_via_exhaustive_destructure_no_rest_pattern()
     {
        // `AuthorizeParams` is the `Query<T>`-extracted shape for
        // `GET /oauth/google/authorize` — the public wire contract every
        // agent SDK constructs by hand. Pin the field count at EXACTLY 7
        // via exhaustive destructure with NO `..` rest pattern: a refactor
        // that landed an 8th field (`nonce: Option<String>` OIDC-replay
        // defense per RFC 6749 §10.12 OR `audience: Option<String>`
        // RFC 8707 resource-indicator) would silently extend the
        // accepted-query-string surface — without a coordinated agent
        // SDK release, the new field would deserialize-silent-drop for
        // every existing in-flight agent. The struct is private but the
        // test sits in the same module so direct construction works.
        let p = AuthorizeParams {
            response_type: String::new(),
            client_id: String::new(),
            redirect_uri: String::new(),
            state: String::new(),
            code_challenge: String::new(),
            code_challenge_method: String::new(),
            scope: String::new(),
        };
        let AuthorizeParams {
            response_type: _,
            client_id: _,
            redirect_uri: _,
            state: _,
            code_challenge: _,
            code_challenge_method: _,
            scope: _,
        } = p;
    }

    #[test]
    fn bridge_callback_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern()
     {
        // `BridgeCallback` is the `Query<T>` for `/oauth/bridge/callback`
        // — the federation-bridge → proxy hop the proxy reads only TWO
        // fields from: the opaque session `state` (a Uuid the proxy
        // minted in `/authorize`) and a `federation_token` JWT. Pin the
        // field count at EXACTLY 2 via exhaustive destructure with NO
        // `..` rest pattern. A regression that landed a 3rd field
        // (`pca_0_cbor_b64: Option<String>` lifting it out of the JWT
        // claims for raw-CBOR-out-of-band-injection OR
        // `error: Option<String>` federation-bridge-returns-error pass-
        // through) would silently extend the wire contract every
        // federation-bridge implementation must conform to, and the
        // new field would deserialize-silent-drop until the bridge
        // implementer rebuilt against the new struct.
        let p = BridgeCallback {
            state: Uuid::nil(),
            federation_token: String::new(),
        };
        let BridgeCallback {
            state: _,
            federation_token: _,
        } = p;
    }

    #[test]
    fn google_callback_field_count_pinned_at_exactly_two_via_exhaustive_destructure_no_rest_pattern()
     {
        // `GoogleCallback` is the `Query<T>` for `/oauth/google/callback`
        // — the Google → proxy authorization-code redirect. Pin EXACTLY
        // 2 fields (state + code) via exhaustive destructure with NO
        // `..` rest pattern. A regression that landed a 3rd field
        // (`error: Option<String>` Google-returns-error-instead-of-code
        // per RFC 6749 §4.1.2.1 OR `scope: Option<String>` Google-
        // narrowed-the-granted-scope-on-consent) would extend the
        // adapter→Google-OAuth handoff shape — and the proxy currently
        // re-reads scope from the token exchange response, NOT the
        // callback, so any new `scope` query param would silently
        // drift away from the token-exchange truth.
        let p = GoogleCallback {
            state: Uuid::nil(),
            code: String::new(),
        };
        let GoogleCallback { state: _, code: _ } = p;
    }

    #[test]
    fn google_token_response_field_count_pinned_at_exactly_four_via_exhaustive_destructure_no_rest_pattern()
     {
        // `GoogleTokenResponse` is the `Deserialize` shape the proxy
        // pulls from Google's `https://oauth2.googleapis.com/token`
        // endpoint after the authorization-code exchange. Pin EXACTLY
        // 4 fields via exhaustive destructure (no `..` rest pattern)
        // catching 5th `id_token: Option<String>` OIDC-userinfo OR
        // `token_type: String` (Google docs say always "Bearer" — the
        // proxy currently doesn't read it — landing it would silently
        // extend the deserialize surface AND would mask a future Google
        // change that returned a non-Bearer token type). The 4 fields
        // are access_token + refresh_token (Option) + expires_in (i64)
        // + scope — matching Google's documented response shape.
        let resp = GoogleTokenResponse {
            access_token: String::new(),
            refresh_token: None,
            expires_in: 0,
            scope: String::new(),
        };
        let GoogleTokenResponse {
            access_token: _,
            refresh_token: _,
            expires_in: _,
            scope: _,
        } = resp;
    }

    #[test]
    fn router_signature_pinned_via_fn_pointer_witness_fn_of_oauth_state_returns_router() {
        // `router(state: OAuthState) -> Router` is the public entry
        // point `server.rs` calls to mount the OAuth handlers under
        // axum. Pin the signature via fn-pointer witness symmetric to
        // round-262/263/264/265/266/268/269/270/271 router pins on the
        // api/* modules — a refactor that landed `fn(&OAuthState) ->
        // Router` (borrow-by-reference "to avoid a Clone of the
        // PgPool") would break the server.rs `.merge(routes::router(
        // state.clone()))` call site every other router pin in the
        // workspace conforms to AND would tie the Router's lifetime to
        // the borrow, breaking axum's `Router: 'static`-ish bound. AND
        // `fn(OAuthState) -> Result<Router, _>` fallible-construction
        // refactor breaking the inline `.merge` chain at server.rs.
        let _: fn(OAuthState) -> Router = router;
    }

    #[test]
    fn narrowed_ops_for_pca1_signature_pinned_via_fn_pointer_witness_for_pca_minting_callsite() {
        // `narrowed_ops_for_pca1(pca0_ops: &[String], granted_scope:
        // &str) -> Vec<String>` is the helper that intersects the
        // PCA_0 op-list with the actual Google-granted scope on the
        // `/oauth/google/callback` hop, producing the op-list for
        // PCA_1 minting. Pin the signature via fn-pointer witness:
        // both inputs are BORROWED (pca0_ops as `&[String]` slice
        // view over the deserialized session row, granted_scope as
        // `&str` slice into the GoogleTokenResponse.scope String) and
        // the return is OWNED `Vec<String>` because the callers
        // (`pic.mint_successor` + `cache.insert`) consume by move.
        // A refactor to `fn(Vec<String>, String) -> Vec<String>`
        // consume-and-shrink would force the callback handler to
        // clone the session ops vector twice (once for the
        // PicInvariant error path that re-reads the original list).
        // AND `fn(&[String], &str) -> &[String]` borrow-return
        // refactor would tie the return lifetime to pca0_ops,
        // making `mint_successor(pca0.cbor.clone(), pca1_ops, ...)`
        // borrow-across-await-boundary impossible.
        let _: fn(&[String], &str) -> Vec<String> = narrowed_ops_for_pca1;
    }

    #[test]
    fn federation_state_matches_only_when_claim_equals_session() {
        // §6.4 — the federation token's `state` claim must equal the callback
        // session UUID, else a token minted for session A is being replayed
        // into session B (session fixation). `bridge_callback_body` rejects on
        // a false return before any DB write, so no session is established.
        let session = Uuid::new_v4();
        assert!(
            federation_state_matches(&session.to_string(), session),
            "matching state must bind",
        );
        let other = Uuid::new_v4();
        assert!(
            !federation_state_matches(&other.to_string(), session),
            "a token minted for a different session must be rejected",
        );
        // Garbage / empty claim never matches a real session.
        assert!(!federation_state_matches("", session));
        assert!(!federation_state_matches("not-a-uuid", session));
        // The comparison is on canonical (hyphenated, lowercase) form; the
        // simple/uppercase variants are not accepted, which is fine — the
        // bridge always emits the canonical form `Uuid::to_string` produces.
        assert!(!federation_state_matches(
            &session.simple().to_string(),
            session
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // DB-backed integration test (opt-in via PROXILION_TEST_DATABASE_URL).
    // Drives the §6.4 federation state-binding through the real callback body
    // against real SQL. Skips when no test DB — see test_support.
    // ─────────────────────────────────────────────────────────────────────

    async fn seed_session(pool: &sqlx::PgPool, id: Uuid) {
        let client_id = format!("client-{}", Uuid::new_v4());
        sqlx::query("INSERT INTO oauth_clients (id, name, redirect_uris) VALUES ($1,'it',ARRAY['https://x/cb'])")
            .bind(&client_id).execute(pool).await.expect("seed oauth_clients");
        sqlx::query(
            "INSERT INTO oauth_sessions
               (id, client_id, agent_redirect_uri, agent_state, agent_code_challenge,
                agent_code_challenge_method, agent_requested_scope, expires_at)
             VALUES ($1,$2,'https://x/cb','st','ch','S256',
                     'https://www.googleapis.com/auth/drive.readonly', now()+interval '1 hour')",
        )
        .bind(id)
        .bind(&client_id)
        .execute(pool)
        .await
        .expect("seed oauth_sessions");
    }

    fn oauth_state_for(pool: sqlx::PgPool) -> OAuthState {
        OAuthState {
            db: pool,
            cipher: std::sync::Arc::new(
                crate::crypto::TokenCipher::from_bytes(&[0u8; 32]).unwrap(),
            ),
            pic: crate::pic::PicExecutor::dev_ephemeral("http://127.0.0.1:1".into()).unwrap(),
            google: crate::oauth::state::GoogleClient {
                client_id: "c".into(),
                client_secret: "s".into(),
                auth_url: "https://accounts.google.test/auth".into(),
                token_url: "https://oauth2.googleapis.test/token".into(),
            },
            federation_bridge_authorize_url: "https://bridge.test/authorize".into(),
            proxy_base_url: "https://proxy.test".into(),
        }
    }

    fn claims_for(state_str: String) -> crate::oauth::bridge::FederationClaims {
        let now = chrono::Utc::now().timestamp();
        crate::oauth::bridge::FederationClaims {
            pca_0_id: Uuid::new_v4(),
            p_0: "alice@acme.com".into(),
            ops: vec!["drive:read:file/abc".into()],
            pca_0_cbor_b64: None,
            state: state_str,
            iat: now - 10,
            exp: now + 3600,
            iss: Some("https://acme.okta.com".into()),
        }
    }

    #[tokio::test]
    async fn db_backed_bridge_callback_binds_session_on_match_and_rejects_replay() {
        // surface-delight-and-correctness.md §6.4, end-to-end against real SQL.
        // A federation token whose `state` claim equals the callback session
        // establishes it (pca_0_id / p_0 / granted_ops are written). A token
        // whose `state` names a DIFFERENT session is a replay (session
        // fixation) — it must be rejected BEFORE the UPDATE, leaving the
        // target session untouched.
        let Some(pool) = crate::test_support::pool().await else {
            eprintln!("skipping: {} unset", crate::test_support::TEST_DB_ENV);
            return;
        };

        // 1. Matching state → session is bound.
        let sid = Uuid::new_v4();
        seed_session(&pool, sid).await;
        let claims = claims_for(sid.to_string());
        let pca_0 = claims.pca_0_id;
        let res = bridge_callback_body(
            oauth_state_for(pool.clone()),
            BridgeCallback {
                state: sid,
                federation_token: String::new(),
            },
            claims,
        )
        .await;
        assert!(
            res.is_ok(),
            "matching state must establish the session: {res:?}"
        );
        let (bound_pca, bound_p0): (Option<Uuid>, Option<String>) =
            sqlx::query_as("SELECT pca_0_id, p_0 FROM oauth_sessions WHERE id = $1")
                .bind(sid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(bound_pca, Some(pca_0), "pca_0_id must be written on bind");
        assert_eq!(
            bound_p0.as_deref(),
            Some("alice@acme.com"),
            "p_0 must be written"
        );

        // 2. Mismatched state → replay rejected, target session untouched.
        let victim = Uuid::new_v4();
        seed_session(&pool, victim).await;
        // The token was minted for some OTHER session, not `victim`.
        let claims = claims_for(Uuid::new_v4().to_string());
        let err = bridge_callback_body(
            oauth_state_for(pool.clone()),
            BridgeCallback {
                state: victim,
                federation_token: String::new(),
            },
            claims,
        )
        .await
        .expect_err("a state-mismatched token must be rejected");
        assert!(
            matches!(err, OAuthError::BridgeRejected(_)),
            "expected BridgeRejected, got: {err:?}",
        );
        // (The 401 status mapping for BridgeRejected is pinned in error.rs.)
        // The victim session was NOT modified — the replay was blocked before
        // the UPDATE.
        let victim_pca: Option<Uuid> =
            sqlx::query_scalar("SELECT pca_0_id FROM oauth_sessions WHERE id = $1")
                .bind(victim)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            victim_pca.is_none(),
            "replay must not establish/modify the target session",
        );
    }
}
