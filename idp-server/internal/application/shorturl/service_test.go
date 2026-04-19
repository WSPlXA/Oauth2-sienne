package shorturl

import (
	"context"
	"testing"
	"time"

	shorturldomain "idp-server/internal/domain/shorturl"
	"idp-server/internal/ports/repository"
)

type stubShortURLRepository struct {
	created           *shorturldomain.Link
	createErr         error
	link              *shorturldomain.Link
	incrementedID     int64
	incrementClickErr error
}

func (s *stubShortURLRepository) Create(_ context.Context, link *shorturldomain.Link) error {
	if s.createErr != nil {
		return s.createErr
	}
	copied := *link
	s.created = &copied
	link.ID = 7
	return nil
}

func (s *stubShortURLRepository) FindActiveByCode(_ context.Context, code string) (*shorturldomain.Link, error) {
	if s.link == nil || s.link.Code != code {
		return nil, nil
	}
	copied := *s.link
	return &copied, nil
}

func (s *stubShortURLRepository) IncrementClick(_ context.Context, id int64) error {
	s.incrementedID = id
	return s.incrementClickErr
}

func TestCreateShortURLWithCustomCode(t *testing.T) {
	repo := &stubShortURLRepository{}
	service := NewService(repo)
	service.now = func() time.Time { return time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC) }

	result, err := service.Create(context.Background(), CreateInput{
		Code:      "go_2026",
		TargetURL: " https://example.com/docs?q=oauth ",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Code != "go_2026" {
		t.Fatalf("code = %q, want go_2026", result.Code)
	}
	if repo.created == nil || repo.created.TargetURL != "https://example.com/docs?q=oauth" {
		t.Fatalf("created target url = %#v", repo.created)
	}
}

func TestCreateRejectsUnsafeTargetURL(t *testing.T) {
	service := NewService(&stubShortURLRepository{})

	_, err := service.Create(context.Background(), CreateInput{
		Code:      "bad1",
		TargetURL: "javascript:alert(1)",
	})
	if err != ErrInvalidTargetURL {
		t.Fatalf("Create() error = %v, want %v", err, ErrInvalidTargetURL)
	}
}

func TestCreateMapsDuplicateCode(t *testing.T) {
	service := NewService(&stubShortURLRepository{createErr: repository.ErrDuplicate})

	_, err := service.Create(context.Background(), CreateInput{
		Code:      "dupe",
		TargetURL: "https://example.com",
	})
	if err != ErrCodeAlreadyExists {
		t.Fatalf("Create() error = %v, want %v", err, ErrCodeAlreadyExists)
	}
}

func TestResolveIncrementsClickAndReturnsTarget(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	repo := &stubShortURLRepository{
		link: &shorturldomain.Link{
			ID:        42,
			Code:      "abc123",
			TargetURL: "https://example.com/landing",
			ExpiresAt: &expiresAt,
		},
	}
	service := NewService(repo)

	result, err := service.Resolve(context.Background(), ResolveInput{Code: "abc123"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if result.TargetURL != "https://example.com/landing" {
		t.Fatalf("target url = %q", result.TargetURL)
	}
	if repo.incrementedID != 42 {
		t.Fatalf("incremented id = %d, want 42", repo.incrementedID)
	}
}

func TestResolveReturnsExpired(t *testing.T) {
	now := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(-time.Minute)
	service := NewService(&stubShortURLRepository{
		link: &shorturldomain.Link{
			ID:        1,
			Code:      "old1",
			TargetURL: "https://example.com",
			ExpiresAt: &expiresAt,
		},
	})
	service.now = func() time.Time { return now }

	_, err := service.Resolve(context.Background(), ResolveInput{Code: "old1"})
	if err != ErrLinkExpired {
		t.Fatalf("Resolve() error = %v, want %v", err, ErrLinkExpired)
	}
}
