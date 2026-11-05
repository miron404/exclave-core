package security

import (
	"context"
)

type ConnectionApplicationProtocol interface {
	GetConnectionApplicationProtocol(ctx context.Context) (string, error)
}
