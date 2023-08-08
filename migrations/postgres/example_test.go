package postgres_test

import (
	"fmt"
	"log"
	"os"

	"github.com/owasp-amass/asset-db/migrations/postgres"
	migrate "github.com/rubenv/sql-migrate"
	pg "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ExampleMigrations() {

	user := "postgres"
	if u, ok := os.LookupEnv("POSTGRES_USER"); ok {
		user = u
	}

	password := "postgres"
	if p, ok := os.LookupEnv("POSTGRES_PASSWORD"); ok {
		password = p
	}

	dbname := "postgres"
	if db, ok := os.LookupEnv("POSTGRES_DB"); ok {
		dbname = db
	}

	log.Printf("DSN: %s", fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s", user, password, dbname))

	dsn := fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s", user, password, dbname)
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
