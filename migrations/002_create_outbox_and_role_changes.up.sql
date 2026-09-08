-- event_outbox：所有组件都有这张表，按 created_at 周分区（§11.2.5）。
-- ⚠️ 本组件没有 event_inbox——阶段三没有任何事件消费者（唯一弱依赖
-- mdm/org 阶段五才存在），YAGNI：不为不存在的消费面建表。
--
-- ⚠️ 初始分区覆盖当前周起 4 周（迁移执行时是 2026-09-07 那一周）。
-- 其余分区由组件内置定时任务自动建（决策 54、§11.5.1、backend/internal/
-- partition/partition.go）——这里只需要保证迁移跑完那一刻起系统能正常
-- 写入，不需要预先建满未来所有分区。

CREATE TABLE event_outbox (
    id           BIGSERIAL,
    subject      TEXT        NOT NULL,
    aggregate_id TEXT        NOT NULL,
    version      BIGINT      NOT NULL,
    trace_id     TEXT        NOT NULL DEFAULT '',
    causation_id TEXT        NOT NULL DEFAULT '',
    hop_count    INT         NOT NULL DEFAULT 0,
    payload      JSONB       NOT NULL,
    published_at TIMESTAMPTZ,
    attempts     INT         NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    status       TEXT        NOT NULL DEFAULT 'PENDING',
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);
CREATE TABLE event_outbox_2026_09_07 PARTITION OF event_outbox
  FOR VALUES FROM ('2026-09-07') TO ('2026-09-14');
CREATE TABLE event_outbox_2026_09_14 PARTITION OF event_outbox
  FOR VALUES FROM ('2026-09-14') TO ('2026-09-21');
CREATE TABLE event_outbox_2026_09_21 PARTITION OF event_outbox
  FOR VALUES FROM ('2026-09-21') TO ('2026-09-28');
CREATE TABLE event_outbox_2026_09_28 PARTITION OF event_outbox
  FOR VALUES FROM ('2026-09-28') TO ('2026-10-05');
CREATE INDEX event_outbox_pending ON event_outbox (status, created_at)
  WHERE status = 'PENDING';

-- ⚠️ 实测踩坑（同 finance/inventory 的 002 迁移）：建分区要求执行者是
-- 父表的 owner，迁移用管理凭据跑，建出来的表默认属于那个账号；分区
-- 维护后台任务运行时用 infra_authz_rw（SET LOCAL ROLE 切换）建未来的
-- 分区，两者不是同一身份，必须显式把 owner 转过去。
ALTER TABLE event_outbox OWNER TO infra_authz_rw;

-- role_changes：stale_since 有界列表的来源（设计计划 §2、§7、§14.1.6）。
-- 按 changed_at 月分区，只有最近 2×TTL 的窗口参与 stale_since 计算，
-- 超过 7 天可归档（设计计划 §7）——窗口恒短，月分区完全够用，不需要
-- 更细的周分区。
--
-- ⚠️ 只记录"人的角色变了"这一类事件（granted/revoked/kicked）。角色
-- 内容变更（给某个角色加一个权限键）不进这张表——那靠 bundle 的
-- roles 字段直接刷新，不需要让任何人的 token 变 stale（见
-- backend/internal/service 里 GrantRolePermission 的注释）。
-- "expired"（到期）同样不在这张表里出现：过期是纯粹的时间流逝，不是
-- 谁做了什么动作，bundle 生成时直接从 user_roles.expires_at 落在窗口
-- 内的行推导，不需要任何人在到期那一刻写一行。
CREATE TABLE role_changes (
    id          BIGSERIAL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    sub         TEXT        NOT NULL,
    role_code   TEXT,                 -- kick 场景可能一次性影响这个人的所有角色，留空
    change_type TEXT        NOT NULL CHECK (change_type IN ('granted', 'revoked', 'kicked')),
    PRIMARY KEY (id, changed_at)
) PARTITION BY RANGE (changed_at);
CREATE TABLE role_changes_2026_09_01 PARTITION OF role_changes
  FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE role_changes_2026_10_01 PARTITION OF role_changes
  FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE role_changes_2026_11_01 PARTITION OF role_changes
  FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE role_changes_2026_12_01 PARTITION OF role_changes
  FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE INDEX role_changes_sub_changed_at_idx ON role_changes (sub, changed_at);

ALTER TABLE role_changes OWNER TO infra_authz_rw;
