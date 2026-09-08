-- 权限键册镜像、角色模型（纯并集无 Deny）、阶段三极简部门表。
-- 强制字段全部符合总纲 §11.2.1；本组件 data_scopes: none，不需要
-- dept_id/dept_path/owner_id 三列（那是给别的组件做行级过滤用的）。

CREATE TABLE permissions (
    key             TEXT        PRIMARY KEY,
    title           TEXT        NOT NULL DEFAULT '',
    type            TEXT        NOT NULL DEFAULT 'action',
    owner_component TEXT        NOT NULL DEFAULT '',
    deprecated      TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 角色用字符串代码做自然主键（不是 bigserial）：bundle 里 role -> keys
-- 就是按这个代码组织的（设计书 §14.1.4），用自然键省一次 join。
-- u:<sub> 是"给这个人单独加一个权限"的底层实现（§14.1.3），is_system
-- 标它以及自举角色（见 003 迁移）——只影响管理界面的角色列表要不要显示，
-- ⚠️ 不影响 bundle：bundle 的 roles 字段必须包含全部角色（含 is_system），
-- 否则 JWT 里带着 u:zhangsan 的用户对应不到任何权限，静默失权。
CREATE TABLE roles (
    code       TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL,
    is_system  BOOLEAN     NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions (
    role_code      TEXT        NOT NULL REFERENCES roles(code) ON DELETE CASCADE,
    permission_key TEXT        NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_code, permission_key)
);

-- expires_at 为 NULL = 永不过期。查"当前有效角色"一律带
-- (expires_at IS NULL OR expires_at > now()) 这个条件（ResolveClaims/
-- bundle 生成/管理界面共用同一个判据）。
CREATE TABLE user_roles (
    sub        TEXT        NOT NULL,
    role_code  TEXT        NOT NULL REFERENCES roles(code) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sub, role_code)
);
CREATE INDEX user_roles_sub_idx ON user_roles (sub);
-- bundle 的 stale_since 要扫"最近窗口内到期"的行，按 expires_at 建索引。
CREATE INDEX user_roles_expires_at_idx ON user_roles (expires_at) WHERE expires_at IS NOT NULL;

-- ⚠️ 阶段三的临时表，只为给出 dept_path（设计计划 §2、§9 待决问题 1）。
-- 阶段五 mdm-org 上线后由它接管，届时这张表连同 user_departments 一起
-- 退役——不是长期存在的东西，不要在这上面投入超出"能用"的设计。
CREATE TABLE departments (
    id         BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       TEXT        NOT NULL,
    parent_id  BIGINT      REFERENCES departments(id),
    dept_path  TEXT        NOT NULL, -- 含自身的祖先链，如 "/1/12/"（前缀匹配用，§11.2.1）
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_departments (
    sub           TEXT        PRIMARY KEY,
    department_id BIGINT      NOT NULL REFERENCES departments(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
