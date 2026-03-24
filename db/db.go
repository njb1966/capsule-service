package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("db migrate: %w", err)
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		username        TEXT    UNIQUE NOT NULL,
		email           TEXT    UNIQUE NOT NULL,
		password_hash   TEXT    NOT NULL,
		email_verified  INTEGER NOT NULL DEFAULT 0,
		storage_bytes   INTEGER NOT NULL DEFAULT 0,
		created_at      INTEGER NOT NULL DEFAULT (unixepoch())
	);

	CREATE TABLE IF NOT EXISTS email_verifications (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT    NOT NULL,
		expires_at INTEGER NOT NULL,
		used       INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL DEFAULT (unixepoch())
	);

	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT    NOT NULL,
		expires_at INTEGER NOT NULL,
		used       INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL DEFAULT (unixepoch())
	);
	`)
	return err
}
