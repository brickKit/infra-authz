# employment：员工来源的事实

员工成员（`mdm/employee`）的水位流 `mdm.employee` 在本成员里应用后的事实（安全 02、04、08）：关联到同一员工的账号是同一个自然人，任职是记录可以绑定的资格。部署没有员工成员时（`EMPLOYEE_COMPONENT` 为空）没有这个来源。

## 负责与不负责

- 负责：表 `authz_employee_fact`（员工、任职、账号关联三种记录各一行：所属员工、关联的账号、状态、版本）；`Index`（投影 `Employees` 的 `Changed` 钩子调它，返回这次的事实与之前的状态，入口按它反应）；自然人（`PersonOf`：一个账号关联的员工此刻的全部有效账号，没有关联就是它自己；`fresh` 时要来源此刻证明，否则按最后应用的事实）与 `Shares`（确认人与一组账号或员工是不是同一个人：事实说是就算是，证明不了不是就答无法证明）；任职绑定（`Binding`：授予或管理持有带 `appointment`）：授出时 `Grantable`（任职计划中或在职、账号关联到它的员工，按 `D_src_high`；本成员还不知道的任职答无法证明，可重试），视图 `Effective`（任职在职且关联有效、来源按 `D_src_read` 证明，否则整条不给），持有的可用性 `HeldApplied`（最后应用的事实），闭包 `Ended`，`Closures`（任职状态变了、关联结束时登记闭包）。
- 不负责：投影本身（入口建 `Base.Employees`）；关联确认的消耗（`accounts`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `facts.go` | `Fact`、`Index`、三种记录的种类 |
| `person.go` | `Person`、`PersonOf`、`Shares`、`EmployeeRef` |
| `appointments.go` | `Binding`、`Grantable`、`Effective`、`HeldApplied`、`Ended`、`AppointmentsOf`、`Closures` |

## 依赖与被依赖

- 依赖：`core`。
- 被依赖：入口、`effectpoint`（`Independent`、处置的账号集合、授出时的任职、持有的可用性、闭包）、`accounts`、`view`、`restore`（6.5 的记账）。

## 规则在哪

安全 02（账号与员工的关联、自然人）、安全 04（任职实例）、安全 08 的“员工、账号与任职”；协议 02（水位来源）。

## 测试

`itest/employment_integration_test.go`（`TestTheEmployeeSource`）、`itest/person_integration_test.go`（`TestOnePerson`）、`itest/appointments_integration_test.go`（`TestAppointmentBindings`）；改坏检查在装配项目 `dev/rebuild/c1-data/e4b-mutants.txt`、`e4d-mutants.txt`、`e4e-mutants.txt`。

## 易错点

- 管理持有的可用性在任职结束与闭包作业之间按最后应用的事实判断（`HeldApplied`），只在读持有的 `effectpoint.HoldingsOf` 里；直接查表的地方（`OthersAvailable`、`administrator`）在闭包作业跑完之前仍把它算上，相差作业的延迟（秒级）。
