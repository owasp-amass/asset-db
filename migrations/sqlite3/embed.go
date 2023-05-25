package sqlite3

import (
	"embed"
)

//go:embed *.sql
var sqlite3Migrations embed.FS

func Migrations() embed.FS {
	return sqlite3Migrations
}
