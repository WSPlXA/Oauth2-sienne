package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/short_url_repository/*.sql
var shortURLRepositorySQLFS embed.FS

type shortURLRepositorySQLSet struct {
	create           string
	findActiveByCode string
	incrementClick   string
}

var shortURLRepositorySQL = mustLoadShortURLRepositorySQL()

func mustLoadShortURLRepositorySQL() shortURLRepositorySQLSet {
	return shortURLRepositorySQLSet{
		create:           mustReadShortURLRepositorySQL("create.sql"),
		findActiveByCode: mustReadShortURLRepositorySQL("find_active_by_code.sql"),
		incrementClick:   mustReadShortURLRepositorySQL("increment_click.sql"),
	}
}

func mustReadShortURLRepositorySQL(fileName string) string {
	data, err := shortURLRepositorySQLFS.ReadFile(path.Join("sql/short_url_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load short url repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
