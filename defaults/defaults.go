package defaults

// App level config
const (
	AppName    = "anubis-authz"
	AppUsage   = "Authorization plugin for docker"
	AppVersion = "v1.0.0"
)

// Flag keys
const (
	DebugFlag       = "debug"
	AuthorizerFlag  = "authorizer"
	AuditorFlag     = "auditor"
	AuditorHookFlag = "auditor-hook"
	PolicyFileFlag  = "policy"
)

// Default configurations
const (
	AuthorizerBasic = "basic"
	AuditorBasic    = "basic"
	PolicyFileBasic = "authz/policy-default.yaml"

	AuthorizerAnubis = "anubis"
	AuditorAnubis    = "anubis"
	PolicyFileAnubis = "authz/policy-anubis.yaml"
)
