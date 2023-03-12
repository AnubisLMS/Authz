package authz

const (
	// AuditHookSyslog indicates logs are streamed  to local syslog
	AuditHookSyslog = "syslog"

	// AuditHookFile indicates logs are streamed  to local syslog
	AuditHookFile = "file"

	// AuditHookStdout indicates logs are streamed to stdout
	AuditHookStdout = ""
)

// defaultAuditLogPath is the file test hook log path
const defaultAuditLogPath = "/var/log/authz-broker.log"
