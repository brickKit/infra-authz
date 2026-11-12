package core

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/events"
)

// Identity of the component.
const (
	ID      = "infra/authz"
	Version = "3.0.54"
)

// The member's own resource and operations: the security records on the user surface, the two system methods.
const (
	Records  = "infra.authz.security_record"
	OpRead   = "infra.authz.security_record.read"
	OpChange = "infra.authz.security_record.change"
	// OpTighten revokes, narrows or ends before it takes effect a record (tightening_only, security 03): admitted on
	// the last view of a stale source, its requester judged by the last applied facts (A125)
	OpTighten = "infra.authz.security_record.tighten"
	// OpRelinquish ends one's own grant or holding (D82): nobody grants it, the member's own view gives every holder a
	// fixed segment of it
	OpRelinquish = "infra.authz.security_record.relinquish"
	// Dispositions (security 08's security dispositions, A128): who may dispose and release within the management
	// limit; dispose only reduces access, release restores it
	Dispositions = "infra.authz.security_disposition"
	OpDispRead   = "infra.authz.security_disposition.read"
	OpDispose    = "infra.authz.security_disposition.dispose"
	OpRelease    = "infra.authz.security_disposition.release"
	// Holder is the records' principal dimension (D82)
	Holder   = "holder"
	System   = "infra.authz.system"
	OpVerify = "infra.authz.system.verify"
	OpSubmit = "infra.authz.system.submit"
	// OpAccountCheck is AccountService.CheckAccountChange: the identity member only (T9c)
	OpAccountCheck = "infra.authz.system.account_check"
	// OpReplay is the replay of this member's evidence in a full recovery (be-protocol P12.19: the recovery tool only).
	OpReplay = "infra.authz.system.replay"
	// OpRecover is a full recovery's checks (be-protocol chapter 14: the recovery tool only).
	OpRecover = "infra.authz.system.recover"
	// OpClaim consumes the install claim: nobody is granted it, the claim itself says who may (A130)
	OpClaim        = "infra.authz.system.claim"
	SystemRead     = "infra.authz.system.read"
	GRPCPort       = 9223
	ShardDomain    = "authz.view."
	SecurityDomain = "authz.security.deployment"
)

// The identity member's account status, an internal source with a watermark (security 03, D64): every identity member
// declares this stream (contract-infra-iam); the member keeps the projection Accounts of it.
var AccountStream = events.Stream{Name: "infra.iam.account_status", Partitions: 4}

const Accounts = "accounts"

// The employee member's stream (mdm/employee): employees, appointments and account links, a watermark source with the
// record read (protocol 02). Optional: a deployment without an employee member has none, and then every account is
// a person by itself and no record binds an appointment. The member keeps the projection Employees of it.
var EmployeeStream = events.Stream{Name: "mdm.employee", Partitions: 4}

const Employees = "employees"

// Starting values of security 03's renewal and closing (D64): a view that depends on the source renews for high-risk
// operations while its watermark is no older than SourceHigh, for ordinary reads no older than SourceRead; the
// profile bounds what a customer may set.
const (
	DefaultSourceHigh = time.Minute
	DefaultSourceRead = 10 * time.Minute
	MaxSourceHigh     = 5 * time.Minute
	MaxSourceRead     = time.Hour
	// DefaultTight is T_tight (security 03's tightening-only operations): a requester judged by the last applied
	// facts acts alone while the identity source's watermark is no older; beyond it a second person confirms
	DefaultTight = time.Hour
)

// Definitions are the member's own declarations: it guards its user surface with a view like any component.
func Definitions() *sdkauthz.Definitions {
	none := map[string]sdkauthz.Dimension{}
	// holder: whose a record is (a grant's grantee, a holding's holder), so a principal may see and relinquish its own
	// (D82); a manager's segments hold every holder
	holder := map[string]sdkauthz.Dimension{Holder: {Kind: sdkauthz.Principal, Column: "holder", PrincipalRole: "holder"}}
	return &sdkauthz.Definitions{Component: ID,
		Resources: []sdkauthz.Resource{
			{Type: Records, ViewOperation: OpRead, Dimensions: holder, Fields: map[string]sdkauthz.Field{
				"id": {Class: sdkauthz.Ordinary}, "record_type": {Class: sdkauthz.Ordinary}, "state": {Class: sdkauthz.Ordinary},
				"body": {Class: sdkauthz.Ordinary}}},
			{Type: Dispositions, ViewOperation: OpDispRead, Dimensions: none, Fields: map[string]sdkauthz.Field{
				"id": {Class: sdkauthz.Ordinary}, "body": {Class: sdkauthz.Ordinary}}},
			{Type: System, ViewOperation: SystemRead, Dimensions: none, Fields: map[string]sdkauthz.Field{}}},
		Operations: []sdkauthz.Operation{
			{Key: OpRead, ResourceType: Records, Purpose: "read", RiskClass: "low"},
			{Key: OpChange, ResourceType: Records, Purpose: "manage", RiskClass: "high", SideEffects: []string{"security_change"},
				Audit: true},
			{Key: OpTighten, ResourceType: Records, Purpose: "manage", RiskClass: "high", SideEffects: []string{"security_change"},
				Audit: true, TighteningOnly: true},
			{Key: OpRelinquish, ResourceType: Records, Purpose: "manage", RiskClass: "high", SideEffects: []string{"security_change"},
				Audit: true, TighteningOnly: true},
			{Key: OpDispRead, ResourceType: Dispositions, Purpose: "read", RiskClass: "low"},
			{Key: OpDispose, ResourceType: Dispositions, Purpose: "manage", RiskClass: "high", SideEffects: []string{"security_change"},
				Audit: true, TighteningOnly: true},
			{Key: OpRelease, ResourceType: Dispositions, Purpose: "manage", RiskClass: "high", SideEffects: []string{"security_change"},
				Audit: true},
			{Key: SystemRead, ResourceType: System, Purpose: "read", RiskClass: "low"},
			{Key: OpVerify, ResourceType: System, Purpose: "read", RiskClass: "low"},
			{Key: OpSubmit, ResourceType: System, Purpose: "manage", RiskClass: "low", SideEffects: []string{"security_change"}},
			{Key: OpAccountCheck, ResourceType: System, Purpose: "read", RiskClass: "low"},
			{Key: OpReplay, ResourceType: System, Purpose: "action", RiskClass: "high", SideEffects: []string{"business_write"}},
			{Key: OpRecover, ResourceType: System, Purpose: "read", RiskClass: "low"},
			{Key: OpClaim, ResourceType: System, Purpose: "manage", RiskClass: "high", SideEffects: []string{"security_change"},
				Audit: true},
		}}
}
