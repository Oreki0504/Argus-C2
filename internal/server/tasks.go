package server

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/state"
)

const PollPath = "/api/v1/agent/tasks/poll"
const ResultsPath = "/api/v1/agent/results"

type Dispatcher interface {
	PollTask(context.Context, *x509.Certificate, string, string) ([]byte, error)
	SubmitResult(context.Context, *x509.Certificate, []byte, string) (protocol.ResultAck, error)
}
type TaskService struct {
	*state.Store
	key ed25519.PrivateKey
}

func NewTaskService(ctx context.Context, s *state.Store, key ed25519.PrivateKey) (*TaskService, error) {
	if s == nil {
		return nil, errors.New("persistent registry is required for dispatch")
	}
	if err := s.ConfigureSigner(ctx, key); err != nil {
		return nil, err
	}
	return &TaskService{Store: s, key: append(ed25519.PrivateKey{}, key...)}, nil
}
func (s *TaskService) PollTask(ctx context.Context, cert *x509.Certificate, digest, source string) ([]byte, error) {
	pollCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		data, err := s.Store.Poll(pollCtx, cert, digest, s.key, source)
		if err != nil {
			if pollCtx.Err() != nil && ctx.Err() == nil {
				return nil, nil
			}
			return nil, err
		}
		if len(data) > 0 {
			return data, nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, nil
		case <-timer.C:
		}
	}
}
