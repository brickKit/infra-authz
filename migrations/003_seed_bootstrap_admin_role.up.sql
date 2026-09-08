-- 自举：解决"第一个管理员怎么来"的鸡生蛋问题（Task 4 设计决策，见 README
-- 「自举」一节）。这里只种结构性的部分（权限键 + 角色 + 两者的关联）——
-- 具体授予哪个 sub 是客户特定的，那部分在 Start() 里读 configSchema 的
-- bootstrapAdminSub 幂等地做（migrations 不应该依赖运行时配置）。
--
-- ⚠️ infra.authz.admin 同时也会被 config.permissionCatalog 的运行时同步
-- upsert 一遍（本组件自己的 assembly.yaml 也声明了这个键）——两条路径
-- 都是 upsert，不会冲突，这里先种是为了保证"即使 Start() 的目录同步
-- 因为某种原因还没跑过，authz_admin 角色也已经能挂上这个权限键"。
INSERT INTO permissions (key, title, type, owner_component)
VALUES ('infra.authz.admin', '权限与角色管理', 'page', 'infra/authz');

INSERT INTO roles (code, name, is_system)
VALUES ('authz_admin', '权限管理员（自举角色）', true);

INSERT INTO role_permissions (role_code, permission_key)
VALUES ('authz_admin', 'infra.authz.admin');
