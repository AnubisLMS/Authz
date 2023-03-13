package authz

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/docker/docker/pkg/authorization"
	"github.com/stretchr/testify/assert"
)

func TestPolicyApply(t *testing.T) {

	policy := `[
		{"name":"policy_1","users":["user_1","user_2"],"actions":["container_create","docker_version", "container_start"]},
		{"name":"policy_2","users":["user_3","user_4"],"actions":["container_create","container_exec"]},
		{"name":"policy_3","users":["user_5"],"actions":["container"]},
		{"name":"policy_4","users":["user_6"],"actions":["container"], "readonly":true }
		]` // User can do anything with containers

	const policyFileName = "/tmp/policy.yaml"
	err := ioutil.WriteFile(policyFileName, []byte(policy), 0755)
	assert.NoError(t, err)

	tests := []struct {
		method         string
		uri            string
		user           string // user is the user in the request
		allow          bool   // allow is the allow/deny response from the policy plugin
		expectedPolicy string // expectedPolicy is the expected policy name that should appear in the message
	}{
		{http.MethodGet, "/v1.21/version", "user_1", true, "policy_1"},                                // User and command allowed
		{http.MethodGet, "/v1.21/version", "user_3", false, "policy_2"},                               // User and command not allowed
		{http.MethodPost, "/v1.21/containers/id/rename?command=//start", "user_1", false, "policy_1"}, // User1 cannot perform container pause
		{http.MethodGet, "/v1.21/version", "user_5", false, ""},                                       // Non existing user (no policy found)
		{http.MethodGet, "/v1.21/containers/id/json", "user_5", true, "policy_3"},                     // All containers action allowed
		{http.MethodGet, "/v1.21/containers/id/json", "user_6", true, "policy_4"},                     // Readonly policy - GET allowed
		{http.MethodPost, "/v1.21/containers/id/rename", "user_6", false, "policy_4"},                 // Readonly policy - POST denied
	}

	authorizer := NewBasicAuthZAuthorizer(&BasicAuthorizerSettings{PolicyPath: policyFileName})

	assert.NoError(t, authorizer.Init(), "Initialization must be successful")

	for _, test := range tests {
		res := authorizer.AuthZReq(&authorization.Request{RequestMethod: test.method, RequestURI: test.uri, User: test.user})
		assert.Equal(t, test.allow, res.Allow, "Request must be allowed/denied based on policy")
		assert.Contains(t, res.Msg, test.expectedPolicy, "Policy name must appear in the response")
	}
}

func TestAuditRequestStdout(t *testing.T) {
	auditor := NewBasicAuditor(&BasicAuditorSettings{LogHook: AuditHookStdout})
	assert.NoError(t, auditor.AuditRequest(&authorization.Request{User: "user"}, &authorization.Response{Allow: true}))
	assert.Error(t, auditor.AuditRequest(&authorization.Request{User: "user"}, nil), "Missing request")
	assert.Error(t, auditor.AuditRequest(nil, &authorization.Response{Err: "err"}), "Missing plugin response")
}

func TestAuditRequestSyslog(t *testing.T) {
	auditor := NewBasicAuditor(&BasicAuditorSettings{LogHook: AuditHookSyslog})
	assert.NoError(t, auditor.AuditRequest(&authorization.Request{User: "user"}, &authorization.Response{Allow: true}))
}

func TestAuditRequestFile(t *testing.T) {
	logPath := "/tmp/auth-broker.log"
	auditor := NewBasicAuditor(&BasicAuditorSettings{LogHook: AuditHookFile, LogPath: logPath})
	assert.NoError(t, auditor.AuditRequest(&authorization.Request{User: "user"}, &authorization.Response{Allow: true}))
	log, err := ioutil.ReadFile(logPath)
	assert.NoError(t, err)
	assert.Contains(t, string(log), "allow", "Log doesn't container authorization data")
}
