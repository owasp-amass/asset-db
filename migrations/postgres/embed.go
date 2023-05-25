package postgres

import (
	"embed"
)

//go:embed *.sql
var postgresMigrations embed.FS

// Migrations returns the migrations for the postgres database.
func Migrations() embed.FS {
	return postgresMigrations
}
