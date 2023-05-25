package postgres_test

import (
	"fmt"
	"os"

	"github.com/owasp-amass/asset-db/migrations/postgres"
	migrate "github.com/rubenv/sql-migrate"
	pg "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ExampleMigrations() {
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	dbname := os.Getenv("POSTGRES_DB")

	dsn := fmt.Sprintf("postgresql://localhost/%s?user=%s&password=%s", dbname, user, password)

	db, err := gorm.Open(pg.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	sqlDb, _ := db.DB()

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: postgres.Migrations(),
		Root:       "/",
	}

	_, err = migrate.Exec(sqlDb, "postgres", migrationsSource, migrate.Up)
	if err != nil {
		panic(err)
	}

	tables := []string{"assets", "relations"}
	for _, table := range tables {
		fmt.Println(db.Migrator().HasTable(table))
	}

	// Output:
	// true
	// true
}
