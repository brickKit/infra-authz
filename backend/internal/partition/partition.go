// Package partition 是 Module.Start 的后台循环：为 event_outbox 自动建
// 未来的周分区（决策 54、§11.5.1，与其余组件同一套判据），为
// role_changes 自动建未来的月分区（设计计划 §7：它按变更时间归档，
// 窗口是月，不是周——同 erp-inventory 的 inventory_movements 判据）。
//
// ⚠️ 本组件没有 event_inbox——阶段三没有任何消费者（唯一的弱依赖
// mdm/org 要到阶段五才存在），YAGNI：不为不存在的消费面建表建分区任务。
package partition

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

const (
	checkInterval   = 24 * time.Hour
	lookAheadWeeks  = 4 // 提前建好当前周 + 未来 4 周
	lookAheadMonths = 3 // 提前建好当前月 + 未来 3 个月
)

var weeklyPartitionedTables = []string{"event_outbox"}
var monthlyPartitionedTables = []string{"role_changes"}

// Start 立刻检查一次周分区与月分区，之后每 24 小时检查一次。单次失败只
// 记日志，不让循环退出——下一轮还有机会补上（§13.3 铁律七）。
func Start(ctx context.Context, db *sql.DB, role, schema string, logger *slog.Logger) error {
	checkOnce := func() {
		if err := ensureAllWeekly(ctx, db, role, schema); err != nil {
			logger.Error("周分区维护失败", "error", err)
		}
		if err := ensureAllMonthly(ctx, db, role, schema); err != nil {
			logger.Error("月分区维护失败", "error", err)
		}
	}
	checkOnce()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			checkOnce()
		}
	}
}

func ensureAllWeekly(ctx context.Context, db *sql.DB, role, schema string) error {
	return besdk.WithTx(ctx, db, role, schema, func(tx *sql.Tx) error {
		weekStart := mondayOf(time.Now().UTC())
		for i := 0; i <= lookAheadWeeks; i++ {
			from := weekStart.AddDate(0, 0, 7*i)
			to := from.AddDate(0, 0, 7)
			for _, table := range weeklyPartitionedTables {
				if err := ensurePartition(ctx, tx, table, from, to); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func ensureAllMonthly(ctx context.Context, db *sql.DB, role, schema string) error {
	return besdk.WithTx(ctx, db, role, schema, func(tx *sql.Tx) error {
		monthStart := firstOfMonth(time.Now().UTC())
		for i := 0; i <= lookAheadMonths; i++ {
			from := monthStart.AddDate(0, i, 0)
			to := from.AddDate(0, 1, 0)
			for _, table := range monthlyPartitionedTables {
				if err := ensurePartition(ctx, tx, table, from, to); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// mondayOf 把任意时间点归到它所在周的周一 00:00 UTC——分区边界必须是
// 固定的锚点，不能是"从现在起 7 天"这种滑动窗口，否则相邻两次检查算出
// 来的分区边界会对不上。
func mondayOf(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 { // time.Sunday == 0，此处要归到"上一周的周一"而不是当天
		weekday = 7
	}
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return d.AddDate(0, 0, -(weekday - 1))
}

// firstOfMonth 把任意时间点归到它所在月的 1 号 00:00 UTC——同 mondayOf
// 的判据：分区边界必须是固定锚点。
func firstOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// ensurePartition 用 to_regclass 先确认分区存不存在，不存在才建。
//
// ⚠️ 不能反过来"先建、报 already exists 就忽略"——PostgreSQL 里一条
// 语句真的执行失败会让整个事务 aborted，即使这里选择忽略那个错误，
// 事务在数据库那侧也回不去了（同 mdm-product/erp-inventory 踩过的坑）。
func ensurePartition(ctx context.Context, tx *sql.Tx, table string, from, to time.Time) error {
	name := fmt.Sprintf("%s_%s", table, from.Format("2006_01_02"))

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		return fmt.Errorf("检查分区是否存在 %s: %w", name, err)
	}
	if exists {
		return nil
	}

	// table 只来自本文件顶部的固定清单，from/to 是格式化过的日期字符串，
	// 都不是外部输入，拼 SQL 是安全的。
	stmt := fmt.Sprintf(
		`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
		name, table, from.Format("2006-01-02"), to.Format("2006-01-02"),
	)
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("建分区 %s: %w", name, err)
	}
	return nil
}
