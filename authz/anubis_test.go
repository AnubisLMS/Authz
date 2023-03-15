package authz

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/docker/docker/pkg/authorization"
	"github.com/stretchr/testify/assert"
)

func TestAnubis(t *testing.T) {

	policy := `[
		{"name":"policy_1","actions":[{"name":"container_rename"}]},
		{"name":"policy_2","actions":[{"name":"docker_version"}]},
		{"name":"policy_3","actions":[{"name":"container_create","body":{"HostConfig":{"CapAdd":null}}}]},
		]` // User can do anything with containers

	const policyFileName = "/tmp/anubis-policy.yaml"
	err := ioutil.WriteFile(policyFileName, []byte(policy), 0755)
	assert.NoError(t, err)

	tests := []struct {
		method         string
		uri            string
		allow          bool   // allow is the allow/deny response from the policy plugin
		expectedPolicy string // expectedPolicy is the expected policy name that should appear in the message
		body           []byte
	}{
		{http.MethodPost, "/v1.21/containers/id/rename?command=//start", true, "policy_1", []byte("{}")}, // User1 cannot perform container pause
		{http.MethodGet, "/v1.21/version", true, "policy_2", []byte("{}")},                               // Non existing user (no policy found)
		{http.MethodPost, "/v1.42/containers/create", true, "policy_3", []byte(`{"HostConfig":{"CapAdd":null}}`)},
		{http.MethodPost, "/v1.42/containers/create", false, "policy_3", []byte(`{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`)},
	}

	authorizer := NewAnubisAuthZAuthorizer(&AnubisAuthorizerSettings{PolicyPath: policyFileName})

	assert.NoError(t, authorizer.Init(), "Initialization must be successful")

	for _, test := range tests {
		res := authorizer.AuthZReq(&authorization.Request{RequestMethod: test.method, RequestURI: test.uri, User: "test", RequestBody: test.body})
		assert.Equal(t, test.allow, res.Allow, "Request must be allowed/denied based on policy")
		fmt.Println(res.Msg)
		assert.Contains(t, res.Msg, test.expectedPolicy, "Policy name must appear in the response")
	}
}
