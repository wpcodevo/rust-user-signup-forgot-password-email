init-migrations:
	sqlx migrate add -r "initial migration"

create-db:
	sqlx database create

migrate-up:
	sqlx migrate run

migrate-down:
	sqlx migrate revert

start-server:
	cargo watch -q -c -w src/ -x run

install-crates:
	cargo add axum
	cargo add axum-extra -F cookie
	cargo add time
	cargo add tokio -F full
	cargo add tower-http -F "cors"
	cargo add serde_json
	cargo add serde -F derive
	cargo add chrono -F serde
	cargo add dotenv
	cargo add uuid -F "serde v4"
	cargo add sqlx -F "runtime-async-std-native-tls sqlite chrono uuid"
	cargo add jsonwebtoken
	cargo add argon2
	cargo add rand
	cargo add handlebars
	cargo add lettre -F "tokio1, tokio1-native-tls" 
	# HotReload
	cargo install cargo-watch
	# SQLX-CLI
	cargo install sqlx-cli