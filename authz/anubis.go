package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"authz/core"

	"github.com/docker/docker/pkg/authorization"
	"github.com/howeyc/fsnotify"
	"github.com/sirupsen/logrus"
)

// AnubisPolicy represent a single policy object that is evaluated in the authorization flow.
// Each policy object consists of multiple users and docker actions, where each user belongs to a single policy.
//
// The policies are evaluated according to the following flow:
//
//	For each policy object check
//	   If the user belongs to the policy
//	      If action in request in policy allow otherwise deny
//	If no appropriate policy found, return deny
//
// Remark: In anubis flow, each user must have a unique policy.
// If a user is used by more than one policy, the results may be inconsistent
type Action struct {
	Name string                 `json:"name"`
	Body map[string]interface{} `json:"body, omitempty" default:nil`
}
type AnubisPolicy struct {
	Actions  []Action `json:"actions"`  // Actions are the docker actions (mapped to authz terminology) that are allowed according to this policy
	Name     string   `json:"name"`     // Name is the policy name
	Readonly bool     `json:"readonly"` // Readonly indicates this policy only allow get commands
}

type anubisAuthorizer struct {
	settings *AnubisAuthorizerSettings
	policies []AnubisPolicy
}

// AnubisAuthorizerSettings provides settings for the anubis authoerizer flow
type AnubisAuthorizerSettings struct {
	PolicyPath string // PolicyPath is the path to the policy settings
}

// NewAnubisAuthZAuthorizer creates a new anubis authorizer
func NewAnubisAuthZAuthorizer(settings *AnubisAuthorizerSettings) core.Authorizer {
	return &anubisAuthorizer{settings: settings}
}

// Init loads the anubis authz plugin configuration from disk
func (f *anubisAuthorizer) Init() error {
	err := f.loadPolicies()
	if err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case ev := <-watcher.Event:
				if ev.IsModify() {
					err := f.loadPolicies()
					if err != nil {
						logrus.Errorf("Error refreshing policy %q", err.Error())
					}
				}
			case err := <-watcher.Error:
				logrus.Errorf("Settings watcher error '%v'", err)
			}
		}
	}()

	err = watcher.Watch(f.settings.PolicyPath)
	if err != nil {
		// Silently ignore watching error
		logrus.Errorf("Failed to start watching folder %q", err.Error())
	}

	return nil
}

func (f *anubisAuthorizer) loadPolicies() error {
	data, err := ioutil.ReadFile(path.Join(f.settings.PolicyPath))

	if err != nil {
		return err
	}

	var policies []AnubisPolicy
	for _, l := range strings.Split(string(data), "\n") {

		if l == "" {
			continue
		}

		var policy AnubisPolicy
		err := json.Unmarshal([]byte(l), &policy)
		if err != nil {
			logrus.Errorf("Failed to unmarshal policy entry %q %q", l, err.Error())
		}
		policies = append(policies, policy)
	}
	logrus.Infof("Loaded '%d' policies", len(policies))

	f.policies = policies
	return nil
}

func parseAction(authZReq *authorization.Request) (string, error) {
	url, err := url.Parse(authZReq.RequestURI)
	if err != nil {
		return "", errors.New(fmt.Sprintf("invalid request URI: %s", err.Error()))
	}
	return core.ParseRoute(authZReq.RequestMethod, url.Path), nil
}

func CheckPolicy(authZReq *authorization.Request, policies []AnubisPolicy, action string) (bool, string) {
	noPolicyMsg := fmt.Sprintf("no policy applied (action: '%s')", action)

	// Check policies
	for _, policy := range policies {

		// Generate messages
		deniedMsg := fmt.Sprintf("action '%s' denied for user '%s' by policy '%s'", action, authZReq.User, policy.Name)
		notAllowedMsg := fmt.Sprintf("action '%s' not allowed for user '%s' by readonly policy '%s'", action, authZReq.User, policy.Name)
		allowedMsg := fmt.Sprintf("action '%s' allowed for user '%s' by policy '%s'", action, authZReq.User, policy.Name)

		// Check policy actions
		for _, policyAction := range policy.Actions {
			match, err := regexp.MatchString(policyAction.Name, action)
			if err != nil {
				logrus.Errorf("Failed to evaluate action %q against policy %q error %q", action, policyAction.Name, err.Error())
			}

			// If policy matches this action
			if !match {
				continue
			}

			// Parse the body of the statement
			var body map[string]interface{}
			err = json.Unmarshal(authZReq.RequestBody, &body)
			if err != nil {
				logrus.Errorf("Failed to evaluate json authZReq.RequestBody %q error %q", authZReq.RequestBody, err.Error())
				return false, deniedMsg
			}

			if policyAction.Body != nil {

			}

			if policy.Readonly && authZReq.RequestMethod != http.MethodGet {
				return false, notAllowedMsg
			}

			return true, allowedMsg
		}
	}

	// Default to no policy deny
	return false, noPolicyMsg
}

func (f *anubisAuthorizer) AuthZReq(authZReq *authorization.Request) *authorization.Response {
	logrus.Debugf("Received AuthZ request, method: '%s', url: '%s'", authZReq.RequestMethod, authZReq.RequestURI)
	logrus.Debugf("AuthZ request.RequestBody %s", authZReq.RequestBody)

	// Parse the request for an action
	action, err := parseAction(authZReq)
	if err != nil {
		return &authorization.Response{Allow: false, Msg: err.Error()}
	}

	// Iterate over policies
	allowed, msg := CheckPolicy(authZReq, f.policies, action)
	return &authorization.Response{Allow: allowed, Msg: msg}
}

// AuthZRes always allow responses from server
func (f *anubisAuthorizer) AuthZRes(authZReq *authorization.Request) *authorization.Response {
	return &authorization.Response{Allow: true}
}
