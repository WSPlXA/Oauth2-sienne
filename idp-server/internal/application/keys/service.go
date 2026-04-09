package keys

import "context"

type Service struct {
	rotateNow func(ctx context.Context) (*RotateKeysResult, error)
}

func NewService(rotateNow func(ctx context.Context) (*RotateKeysResult, error)) *Service {
	return &Service{rotateNow: rotateNow}
}

func (s *Service) RotateNow(ctx context.Context, _ RotateKeysInput) (*RotateKeysResult, error) {
	if s == nil || s.rotateNow == nil {
		return nil, ErrRotateUnavailable
	}
	return s.rotateNow(ctx)
}
