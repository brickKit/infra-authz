package repo

import "errors"

// pgError 是 pgx 错误类型的最小接口（同 be-sdk-go events.go / erp-finance
// 的判据）：带 SQLSTATE 的错误都能用 errors.As 接住。
type pgError interface{ SQLState() string }

func isUniqueViolation(err error) bool {
	var pgErr pgError
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

func isForeignKeyViolation(err error) bool {
	var pgErr pgError
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23503"
	}
	return false
}
