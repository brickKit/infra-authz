-- The employee member's records as this member has applied them (the projection Employees' Changed hook): who is the
-- same person (the accounts linked to one employee), and the appointments records may bind.
CREATE TABLE authz_employee_fact (
    record   text PRIMARY KEY,
    kind     text NOT NULL CHECK (kind IN ('employee', 'appointment', 'account_link')),
    employee text NOT NULL,
    account  text,   -- an account link's account
    state    text NOT NULL,
    version  bigint NOT NULL
);
CREATE INDEX authz_employee_fact_account ON authz_employee_fact (account) WHERE kind = 'account_link';
CREATE INDEX authz_employee_fact_employee ON authz_employee_fact (employee);
