// broker consists of the entry point for the twistlock authz broker
package main

import (
	"fmt"
	"os"

	"authz/authz"
	"authz/core"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	debugFlag       = "debug"
	authorizerFlag  = "authorizer"
	auditorFlag     = "auditor"
	auditorHookFlag = "auditor-hook"
	policyFileFlag  = "policy-file"
)

const (
	authorizerBasic = "basic"
	auditorBasic    = "basic"

	authorizerAnubis = "anubis"
	auditorAnubis    = "anubis"
)

var (
	version = "v1.0.0"
)

func main() {

	app := &cli.App{
		Name:    "anubis-authz",
		Usage:   "Authorization plugin for docker",
		Version: version,

		Action: func(c *cli.Context) error {

			initLogger(c.Bool(debugFlag))

			var auditor core.Auditor
			var authZHandler core.Authorizer

			switch c.String(authorizerFlag) {
			case authorizerBasic:
				authZHandler = authz.NewBasicAuthZAuthorizer(&authz.BasicAuthorizerSettings{PolicyPath: c.String(policyFileFlag)})
			case authorizerAnubis:
				authZHandler = authz.NewAnubisAuthZAuthorizer(&authz.AnubisAuthorizerSettings{PolicyPath: c.String(policyFileFlag)})
			default:
				panic(fmt.Sprintf("Unknown authz handler %q", c.String(authorizerFlag)))
			}

			switch c.String(auditorFlag) {
			case auditorBasic:
				auditor = authz.NewBasicAuditor(&authz.BasicAuditorSettings{LogHook: c.String(auditorHookFlag)})
			default:
				panic(fmt.Sprintf("Unknown authz handler %q", c.String(authorizerFlag)))
			}

			srv := core.NewAuthZSrv(authZHandler, auditor)
			return srv.Start()
		},

		Flags: []cli.Flag{
			// debug
			&cli.BoolFlag{
				Name:    debugFlag,
				Usage:   "Enable debug mode",
				EnvVars: []string{"DEBUG"},
			},

			// policy file
			&cli.StringFlag{
				Name:  policyFileFlag,
				Value: "authz/policy.json",
				Usage: "Defines the authz policy file for basic handler",
			},

			// authorizer
			&cli.StringFlag{
				Name:    authorizerFlag,
				Value:   authorizerBasic,
				// EnvVars: []string{"AUTHORIZER"},
				Usage:   "Defines the authz handler type",
			},

			// auditor
			&cli.StringFlag{
				Name:    auditorFlag,
				Value:   auditorBasic,
				// EnvVars: []string{"AUDITOR"},
				Usage:   "Defines the authz auditor type",
			},
			&cli.StringFlag{
				Name:    auditorHookFlag,
				Value:   authz.AuditHookStdout,
				// EnvVars: []string{"AUDITOR_HOOK"},
				Usage:   "Defines the authz auditor hook type (log engine)",
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

// initLogger initialize the logger based on the log level
func initLogger(debug bool) {

	logrus.SetFormatter(&logrus.TextFormatter{})
	// Output to stderr instead of stdout, could also be a file.
	logrus.SetOutput(os.Stdout)
	// Only log the warning severity or above.
	logrus.SetLevel(logrus.DebugLevel)
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
}
