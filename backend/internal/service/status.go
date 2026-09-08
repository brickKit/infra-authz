package service

import (
	"errors"

	"github.com/brickKit/infra-authz/backend/internal/repo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ToStatus 把 repo 层的哨兵错误翻成 gRPC status——HTTP 与 gRPC 两条对外
// 接口共用同一套业务错误类型（同 erp-finance/erp-inventory 的判据）。
func ToStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, repo.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, repo.ErrRoleCodeReserved):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, repo.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
