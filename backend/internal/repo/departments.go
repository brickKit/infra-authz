// 阶段三的极简部门表——只为给 ResolveClaims 一个 dept_path 字符串
// （设计计划 §2、§9 待决问题 1）。⚠️ 临时的：阶段五 mdm-org 上线后这张
// 表连同 user_departments 一起退役，不要在这上面投入超出"能用"的设计。
package repo

import (
	"context"
	"database/sql"
	"strconv"

	besdk "github.com/brickKit/be-sdk-go"
)

type Department struct {
	ID       int64
	Name     string
	ParentID *int64
	DeptPath string // 含自身的祖先链，如 "/1/12/"（前缀匹配用，同 erp-sales 的 dept_path 约定）
}

// CreateDepartment 建一个部门。dept_path 在 id 生成之后才能算出来
// （它本身含有这个部门的 id），所以是"插入占位 → 算路径 → 回写"两步，
// 都在同一个事务里。
func (r *Repo) CreateDepartment(ctx context.Context, name string, parentID *int64) (*Department, error) {
	if name == "" {
		return nil, ErrInvalidArgument
	}
	d := &Department{Name: name, ParentID: parentID}
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		parentPath := "/"
		if parentID != nil {
			if err := tx.QueryRowContext(ctx,
				`SELECT dept_path FROM departments WHERE id = $1`, *parentID,
			).Scan(&parentPath); err != nil {
				if err == sql.ErrNoRows {
					return ErrNotFound
				}
				return err
			}
		}
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO departments (name, parent_id, dept_path) VALUES ($1, $2, '') RETURNING id`,
			name, parentID,
		).Scan(&d.ID); err != nil {
			return err
		}
		d.DeptPath = parentPath + strconv.FormatInt(d.ID, 10) + "/"
		_, err := tx.ExecContext(ctx,
			`UPDATE departments SET dept_path = $1 WHERE id = $2`, d.DeptPath, d.ID)
		return err
	})
	if err != nil {
		return nil, wrap("建部门", err)
	}
	return d, nil
}

func (r *Repo) ListDepartments(ctx context.Context) ([]*Department, error) {
	var out []*Department
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT id, name, parent_id, dept_path FROM departments ORDER BY dept_path`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Department
			if err := rows.Scan(&d.ID, &d.Name, &d.ParentID, &d.DeptPath); err != nil {
				return err
			}
			out = append(out, &d)
		}
		return rows.Err()
	})
	return out, wrap("列部门", err)
}

// AssignUserDepartment 把 sub 分到某个部门——幂等，重复分配/改分配都是
// 简单覆盖（不像角色分配那样需要 stale_since：dept_path 走 ResolveClaims，
// 登录/刷新时才读一次，见设计计划 §4 对两个 token 架构的说明）。
func (r *Repo) AssignUserDepartment(ctx context.Context, sub string, departmentID int64) error {
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO user_departments (sub, department_id) VALUES ($1, $2)
			ON CONFLICT (sub) DO UPDATE SET department_id = EXCLUDED.department_id, updated_at = now()`,
			sub, departmentID)
		return err
	})
	if err != nil {
		return mapConstraintErr(err, "部门不存在")
	}
	return nil
}

// DeptPathFor 给 ResolveClaims：未分配部门时返回空串，不是错误——阶段三
// 大量用户可能还没有部门归属，这是合法的过渡态。
func (r *Repo) DeptPathFor(ctx context.Context, sub string) (string, error) {
	var path string
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT d.dept_path FROM user_departments ud
			JOIN departments d ON d.id = ud.department_id
			WHERE ud.sub = $1`, sub).Scan(&path)
		if err == sql.ErrNoRows {
			path = ""
			return nil
		}
		return err
	})
	return path, wrap("查用户部门", err)
}
