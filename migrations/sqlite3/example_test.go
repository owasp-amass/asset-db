package sqlite3_test

import (
	"fmt"
	"os"

	"github.com/owasp-amass/asset-db/migrations/sqlite3"
	migrate "github.com/rubenv/sql-migrate"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func ExampleMigrations() {
	dns := os.Getenv("SQLITE3_DB")

	db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	sqlDb, _ := db.DB()

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: sqlite3.Migrations(),
		Root:       "/",
	}

	_, err = migrate.Exec(sqlDb, "sqlite3", migrationsSource, migrate.Up)
	if err != nil {
		panic(err)
	}

	tables := []string{"assets", "relations"}
	for _, table := range tables {
		fmt.Println(db.Migrator().HasTable(table))
	}

	err = os.Remove("./" + dns)
	if err != nil {
		panic(err)
	}

	// Output:
	// true
	// true
}
