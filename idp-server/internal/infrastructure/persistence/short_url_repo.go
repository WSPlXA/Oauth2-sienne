package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"

	shorturldomain "idp-server/internal/domain/shorturl"
	"idp-server/internal/ports/repository"
)

type ShortURLRepository struct {
	db dbRouter
}

func NewShortURLRepository(db *sql.DB) *ShortURLRepository {
	return NewShortURLRepositoryRW(db, nil)
}

func NewShortURLRepositoryRW(writeDB, readDB *sql.DB) *ShortURLRepository {
	return &ShortURLRepository{db: newDBRouter(writeDB, readDB)}
}

func (r *ShortURLRepository) Create(ctx context.Context, link *shorturldomain.Link) error {
	result, err := r.db.writer().ExecContext(ctx, shortURLRepositorySQL.create, link.Code, link.TargetURL, nullTimePtr(link.ExpiresAt))
	if err != nil {
		if isDuplicateMySQLError(err) {
			return repository.ErrDuplicate
		}
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	link.ID = id
	return nil
}

func (r *ShortURLRepository) FindActiveByCode(ctx context.Context, code string) (*shorturldomain.Link, error) {
	var link shorturldomain.Link
	var expiresAt sql.NullTime
	var lastAccessAt sql.NullTime
	err := r.db.reader().QueryRowContext(ctx, shortURLRepositorySQL.findActiveByCode, code).Scan(
		&link.ID,
		&link.Code,
		&link.TargetURL,
		&link.ClickCount,
		&expiresAt,
		&lastAccessAt,
		&link.CreatedAt,
		&link.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if expiresAt.Valid {
		link.ExpiresAt = &expiresAt.Time
	}
	if lastAccessAt.Valid {
		link.LastAccessAt = &lastAccessAt.Time
	}
	return &link, nil
}

func (r *ShortURLRepository) IncrementClick(ctx context.Context, id int64) error {
	_, err := r.db.writer().ExecContext(ctx, shortURLRepositorySQL.incrementClick, id)
	return err
}

func nullTimePtr(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}

func isDuplicateMySQLError(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1062
}
