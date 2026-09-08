DELETE FROM role_permissions WHERE role_code = 'authz_admin' AND permission_key = 'infra.authz.admin';
DELETE FROM roles WHERE code = 'authz_admin';
DELETE FROM permissions WHERE key = 'infra.authz.admin';
