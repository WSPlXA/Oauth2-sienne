package shorturl

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	neturl "net/url"
	"regexp"
	"strings"
	"time"

	shorturldomain "idp-server/internal/domain/shorturl"
	"idp-server/internal/ports/repository"
)

var shortCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{4,32}$`)

const shortCodeAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type Service struct {
	repo repository.ShortURLRepository
	now  func() time.Time
}

func NewService(repo repository.ShortURLRepository) *Service {
	return &Service{
		repo: repo,
		now:  time.Now,
	}
}

func (s *Service) Create(ctx context.Context, input CreateInput) (*CreateResult, error) {
	targetURL, err := normalizeTargetURL(input.TargetURL)
	if err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if input.ExpiresAt != nil {
		expiry := input.ExpiresAt.UTC()
		if !expiry.After(s.now().UTC()) {
			return nil, ErrInvalidExpiry
		}
		expiresAt = &expiry
	}

	code := strings.TrimSpace(input.Code)
	if code != "" {
		if !shortCodePattern.MatchString(code) {
			return nil, ErrInvalidCode
		}
		link := &shorturldomain.Link{
			Code:      code,
			TargetURL: targetURL,
			ExpiresAt: expiresAt,
			CreatedAt: s.now().UTC(),
		}
		if err := s.repo.Create(ctx, link); err != nil {
			if isDuplicateCode(err) {
				return nil, ErrCodeAlreadyExists
			}
			return nil, err
		}
		return createResultFromLink(link), nil
	}

	for attempts := 0; attempts < 8; attempts++ {
		generated, err := generateCode(7)
		if err != nil {
			return nil, err
		}
		link := &shorturldomain.Link{
			Code:      generated,
			TargetURL: targetURL,
			ExpiresAt: expiresAt,
			CreatedAt: s.now().UTC(),
		}
		if err := s.repo.Create(ctx, link); err != nil {
			if isDuplicateCode(err) {
				continue
			}
			return nil, err
		}
		return createResultFromLink(link), nil
	}

	return nil, ErrCodeAlreadyExists
}

func (s *Service) Resolve(ctx context.Context, input ResolveInput) (*ResolveResult, error) {
	code := strings.TrimSpace(input.Code)
	if !shortCodePattern.MatchString(code) {
		return nil, ErrInvalidCode
	}

	link, err := s.repo.FindActiveByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, ErrLinkNotFound
	}
	if link.ExpiresAt != nil && !link.ExpiresAt.After(s.now().UTC()) {
		return nil, ErrLinkExpired
	}
	if err := s.repo.IncrementClick(ctx, link.ID); err != nil {
		return nil, err
	}

	return &ResolveResult{
		Code:      link.Code,
		TargetURL: link.TargetURL,
		ExpiresAt: link.ExpiresAt,
	}, nil
}

func normalizeTargetURL(value string) (string, error) {
	targetURL := strings.TrimSpace(value)
	if targetURL == "" || len(targetURL) > 2048 {
		return "", ErrInvalidTargetURL
	}

	parsed, err := neturl.ParseRequestURI(targetURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", ErrInvalidTargetURL
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", ErrInvalidTargetURL
	}
	if parsed.User != nil {
		return "", ErrInvalidTargetURL
	}
	return parsed.String(), nil
}

func generateCode(length int) (string, error) {
	var builder strings.Builder
	builder.Grow(length)
	max := big.NewInt(int64(len(shortCodeAlphabet)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		builder.WriteByte(shortCodeAlphabet[n.Int64()])
	}
	return builder.String(), nil
}

func createResultFromLink(link *shorturldomain.Link) *CreateResult {
	return &CreateResult{
		Code:      link.Code,
		TargetURL: link.TargetURL,
		ExpiresAt: link.ExpiresAt,
		CreatedAt: link.CreatedAt,
	}
}

func isDuplicateCode(err error) bool {
	return errors.Is(err, repository.ErrDuplicate)
}
