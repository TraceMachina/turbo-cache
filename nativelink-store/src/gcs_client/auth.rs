// Copyright 2024 The NativeLink Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use nativelink_config::stores::GcsSpec;
use nativelink_error::{make_err, Code, Error};
use rand::Rng;
use serde::Serialize;
use tokio::sync::{Mutex, RwLock};

const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const AUDIENCE: &str = "https://storage.googleapis.com/";
const TOKEN_LIFETIME: Duration = Duration::from_secs(3600); // 1 hour
const REFRESH_WINDOW: Duration = Duration::from_secs(300); // 5 minutes
const MAX_REFRESH_ATTEMPTS: u32 = 3;
const RETRY_DELAY_BASE: Duration = Duration::from_secs(1);

const ENV_PRIVATE_KEY: &str = "GCS_PRIVATE_KEY";
const ENV_AUTH_TOKEN: &str = "GOOGLE_AUTH_TOKEN";

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    scope: String,
}

#[derive(Clone)]
struct TokenInfo {
    token: String,
    refresh_at: u64, // Timestamp when token should be refreshed
}

pub struct GcsAuth {
    token_cache: RwLock<Option<TokenInfo>>,
    refresh_lock: Mutex<()>,
    service_email: String,
    private_key: String,
}

impl GcsAuth {
    pub async fn new(spec: &GcsSpec) -> Result<Self, Error> {
        // First try to get direct token from environment
        if let Ok(token) = std::env::var(ENV_AUTH_TOKEN) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| make_err!(Code::Internal, "Failed to get system time: {}", e))?
                .as_secs();

            return Ok(Self {
                token_cache: RwLock::new(Some(TokenInfo {
                    token,
                    refresh_at: now + TOKEN_LIFETIME.as_secs() - REFRESH_WINDOW.as_secs(),
                })),
                refresh_lock: Mutex::new(()),
                service_email: String::new(),
                private_key: String::new(),
            });
        }

        let service_email = spec.service_email.clone();

        // Get private key from environment
        let private_key = std::env::var(ENV_PRIVATE_KEY).map_err(|_| {
            make_err!(
                Code::NotFound,
                "Environment variable {} not found",
                ENV_PRIVATE_KEY
            )
        })?;

        Ok(Self {
            token_cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            service_email,
            private_key,
        })
    }

    fn add_jitter(duration: Duration) -> Duration {
        let jitter = rand::thread_rng().gen_range(-5..=5);
        duration.saturating_add(Duration::from_secs_f64(f64::from(jitter) * 0.1))
    }

    async fn generate_token(&self) -> Result<TokenInfo, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| make_err!(Code::Internal, "Failed to get system time: {}", e))?
            .as_secs();

        let expiry = now + TOKEN_LIFETIME.as_secs();
        let refresh_at = expiry - REFRESH_WINDOW.as_secs();

        let claims = JwtClaims {
            iss: self.service_email.clone(),
            sub: self.service_email.clone(),
            aud: AUDIENCE.to_string(),
            iat: now,
            exp: expiry,
            scope: SCOPE.to_string(),
        };

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(self.private_key.as_bytes())
            .map_err(|e| make_err!(Code::Internal, "Failed to create encoding key: {}", e))?;

        let token = encode(&header, &claims, &key)
            .map_err(|e| make_err!(Code::Internal, "Failed to encode JWT: {}", e))?;

        Ok(TokenInfo { token, refresh_at })
    }

    async fn refresh_token(&self) -> Result<TokenInfo, Error> {
        let mut attempt = 0;
        loop {
            match self.generate_token().await {
                Ok(token_info) => return Ok(token_info),
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_REFRESH_ATTEMPTS {
                        return Err(make_err!(
                            Code::Internal,
                            "Failed to refresh token after {} attempts: {}",
                            MAX_REFRESH_ATTEMPTS,
                            e
                        ));
                    }
                    let delay = Self::add_jitter(RETRY_DELAY_BASE * (2_u32.pow(attempt - 1)));
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    pub async fn get_valid_token(&self) -> Result<String, Error> {
        if let Some(token_info) = self.token_cache.read().await.as_ref() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| make_err!(Code::Internal, "Failed to get system time: {}", e))?
                .as_secs();

            if now < token_info.refresh_at {
                return Ok(token_info.token.clone());
            }
        }

        let _refresh_guard = self.refresh_lock.lock().await;

        if let Some(token_info) = self.token_cache.read().await.as_ref() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| make_err!(Code::Internal, "Failed to get system time: {}", e))?
                .as_secs();

            if now < token_info.refresh_at {
                return Ok(token_info.token.clone());
            }
        }

        let token_info = if self.private_key.is_empty() {
            if let Ok(token) = std::env::var(ENV_AUTH_TOKEN) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| make_err!(Code::Internal, "Failed to get system time: {}", e))?
                    .as_secs();

                TokenInfo {
                    token,
                    refresh_at: now + TOKEN_LIFETIME.as_secs() - REFRESH_WINDOW.as_secs(),
                }
            } else {
                return Err(make_err!(
                    Code::Unauthenticated,
                    "No valid authentication method available"
                ));
            }
        } else {
            self.refresh_token().await?
        };

        *self.token_cache.write().await = Some(token_info.clone());

        Ok(token_info.token)
    }
}
