use std::sync::Arc;

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{Path, State},
    http::{header, Response, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde_json::json;

use crate::{
    email::Email,
    model::{
        ForgotPasswordSchema, LoginUserSchema, RegisterUserSchema, ResetPasswordSchema,
        TokenClaims, User,
    },
    response::{ErrorResponse, FilteredUser},
    AppState,
};

pub async fn health_checker_handler() -> impl IntoResponse {
    const MESSAGE: &str =
        "Rust - User Registration and Email Verification using Axum, Postgres, and SQLX";

    let json_response = serde_json::json!({
        "status": "success",
        "message": MESSAGE
    });

    Json(json_response)
}

pub async fn register_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let user_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(body.email.to_owned().to_ascii_lowercase())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                let error_response = ErrorResponse {
                    status: "fail",
                    message: format!("Database error: {}", e),
                };
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

    if let Some(exists) = user_exists {
        if exists {
            let error_response = ErrorResponse {
                status: "fail",
                message: "User with that email already exists".to_string(),
            };
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "fail",
                message: format!("Error while hashing password: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    let verification_code = generate_random_string(20);
    let email = body.email.to_owned().to_ascii_lowercase();
    let id = uuid::Uuid::new_v4().to_string();
    let verification_url = format!(
        "{}/verifyemail/{}",
        data.config.frontend_origin.to_owned(),
        verification_code
    );

    let user: User = sqlx::query_as(
        "INSERT INTO users (id,name,email,password) VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(id.clone())
    .bind(body.name.to_owned())
    .bind(email.clone())
    .bind(hashed_password)
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        let error_response = ErrorResponse {
            status: "fail",
            message: format!("Database error: {}", e),
        };
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_response.into()),
        )
    })?;

    //  Create an Email instance
    let email_instance = Email::new(user, verification_url, data.config.clone());
    if let Err(_) = email_instance.send_verification_code().await {
        let json_error = ErrorResponse {
            status: "fail",
            message: "Something bad happended while sending the verification code".to_string(),
        };
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json_error)));
    }

    sqlx::query("UPDATE users SET verification_code = $1 WHERE id = $2")
        .bind(verification_code)
        .bind(id)
        .execute(&data.db)
        .await
        .map_err(|e| {
            let json_error = ErrorResponse {
                status: "fail",
                message: format!("Error updating user: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
        })?;

    let user_response = serde_json::json!({"status": "success","message": format!("We sent an email with a verification code to {}", email)});

    Ok(Json(user_response))
}

pub async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let email = body.email.to_ascii_lowercase();
    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "error",
                message: format!("Database error: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .ok_or_else(|| {
            let error_response = ErrorResponse {
                status: "fail",
                message: "Invalid email or password".to_string(),
            };
            (StatusCode::BAD_REQUEST, Json(error_response))
        })?;

    if !user.verified {
        let error_response = ErrorResponse {
            status: "fail",
            message: "Please verify your email before you can log in".to_string(),
        };
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let is_valid = match PasswordHash::new(&user.password) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true),
        Err(_) => false,
    };

    if !is_valid {
        let error_response = ErrorResponse {
            status: "fail",
            message: "Invalid email or password".to_string(),
        };
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let now = chrono::Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + chrono::Duration::minutes(60)).timestamp() as usize;
    let claims: TokenClaims = TokenClaims {
        sub: user.id.to_string(),
        exp,
        iat,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(data.config.jwt_secret.as_ref()),
    )
    .unwrap();

    let cookie = Cookie::build("token", token.to_owned())
        .path("/")
        .max_age(time::Duration::hours(1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(json!({"status": "success", "token": token}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn verify_email_handler(
    State(data): State<Arc<AppState>>,
    Path(verification_code): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE verification_code = $1")
        .bind(&verification_code)
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "error",
                message: format!("Database error: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .ok_or_else(|| {
            let error_response = ErrorResponse {
                status: "fail",
                message: "Invalid verification code or user doesn't exist".to_string(),
            };
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;

    if user.verified {
        let error_response = ErrorResponse {
            status: "fail",
            message: "User already verified".to_string(),
        };
        return Err((StatusCode::CONFLICT, Json(error_response)));
    }

    sqlx::query(
        "UPDATE users SET verification_code = $1, verified = $2 WHERE verification_code = $3",
    )
    .bind(Option::<String>::None)
    .bind(true)
    .bind(&verification_code)
    .execute(&data.db)
    .await
    .map_err(|e| {
        let json_error = ErrorResponse {
            status: "fail",
            message: format!("Error updating user: {}", e),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
    })?;

    let response = serde_json::json!({
            "status": "success",
            "message": "Email verified successfully"
        }
    );

    Ok(Json(response))
}

pub async fn forgot_password_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let err_message = "You will receive a password reset email if user with that email exist";

    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = $1")
        .bind(&body.email.to_owned().to_ascii_lowercase())
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "error",
                message: format!("Database error: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .ok_or_else(|| {
            let error_response = ErrorResponse {
                status: "fail",
                message: err_message.to_string(),
            };
            (StatusCode::OK, Json(error_response))
        })?;

    if !user.verified {
        let error_response = ErrorResponse {
            status: "fail",
            message: "Account not verified".to_string(),
        };
        return Err((StatusCode::FORBIDDEN, Json(error_response)));
    }

    let password_reset_token = generate_random_string(20);
    let password_token_expires_in = 10; // 10 minutes
    let password_reset_at =
        chrono::Utc::now() + chrono::Duration::minutes(password_token_expires_in);
    let password_reset_url = format!(
        "{}/resetpassword/{}",
        data.config.frontend_origin.to_owned(),
        password_reset_token
    );

    sqlx::query(
        "UPDATE users SET password_reset_token = $1, password_reset_at = $2 WHERE email = $3",
    )
    .bind(password_reset_token)
    .bind(password_reset_at)
    .bind(&user.email.clone().to_ascii_lowercase())
    .execute(&data.db)
    .await
    .map_err(|e| {
        let json_error = ErrorResponse {
            status: "fail",
            message: format!("Error updating user: {}", e),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
    })?;

    let email_instance = Email::new(user, password_reset_url, data.config.clone());
    if let Err(_) = email_instance
        .send_password_reset_token(password_token_expires_in)
        .await
    {
        let json_error = ErrorResponse {
            status: "fail",
            message: "Something bad happended while sending the password reset code".to_string(),
        };
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json_error)));
    }

    let response = serde_json::json!({
            "status": "success",
            "message": err_message
        }
    );

    Ok(Json(response))
}

pub async fn reset_password_handler(
    State(data): State<Arc<AppState>>,
    Path(password_reset_token): Path<String>,
    Json(body): Json<ResetPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    if body.password != body.password_confirm {
        let error_response = ErrorResponse {
            status: "fail",
            message: "Passwords do not match".to_string(),
        };
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let user: User = sqlx::query_as(
        "SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_at > $2",
    )
    .bind(password_reset_token)
    .bind(chrono::Utc::now())
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = ErrorResponse {
            status: "error",
            message: format!("Database error: {}", e),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = ErrorResponse {
            status: "fail",
            message: "The password reset token is invalid or has expired".to_string(),
        };
        (StatusCode::FORBIDDEN, Json(error_response))
    })?;

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "fail",
                message: format!("Error while hashing password: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    sqlx::query(
        "UPDATE users SET password = $1, password_reset_token = $2, password_reset_at = $3 WHERE email = $4",
    )
    .bind(hashed_password)
    .bind(Option::<String>::None)
    .bind(Option::<String>::None)
    .bind(&user.email.clone().to_ascii_lowercase())
    .execute(&data.db)
    .await
    .map_err(|e| {
        let json_error = ErrorResponse {
            status: "fail",
            message: format!("Error updating user: {}", e),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
    })?;

    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(
        json!({"status": "success", "message": "Password data updated successfully"}).to_string(),
    );
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn logout_handler() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(time::Duration::hours(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(json!({"status": "success"}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn get_me_handler(
    Extension(user): Extension<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let filtered_user = FilteredUser::new_user(&user);

    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filtered_user
        })
    });

    Ok(Json(json_response))
}

fn generate_random_string(length: usize) -> String {
    let rng = rand::thread_rng();
    let random_string: String = rng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();

    random_string
}
