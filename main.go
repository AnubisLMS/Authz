// broker consists of the entry point for the AnubisLMS authz broker
package main

import (
	"fmt"
	"os"

	"authz/authz"
	"authz/core"
	"authz/defaults"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func main() {

	app := &cli.App{
		Name:    defaults.AppName,
		Usage:   defaults.AppUsage,
		Version: defaults.AppVersion,

		Action: func(c *cli.Context) error {

			initLogger(c.Bool(defaults.DebugFlag))

			var auditor core.Auditor
			var authZHandler core.Authorizer

			// Configure authorizer
			switch c.String(defaults.AuthorizerFlag) {
			case defaults.AuthorizerBasic:
				authZHandler = authz.NewBasicAuthZAuthorizer(&authz.BasicAuthorizerSettings{PolicyPath: c.String(defaults.PolicyFileFlag)})
			case defaults.AuthorizerAnubis:
				authZHandler = authz.NewAnubisAuthZAuthorizer(&authz.AnubisAuthorizerSettings{PolicyPath: c.String(defaults.PolicyFileFlag)})
			default:
				panic(fmt.Sprintf("Unknown authz handler %q", c.String(defaults.AuthorizerFlag)))
			}

			// Configure auditor
			switch c.String(defaults.AuditorFlag) {
			case defaults.AuditorBasic:
				auditor = authz.NewBasicAuditor(&authz.BasicAuditorSettings{LogHook: c.String(defaults.AuditorHookFlag)})
			default:
				panic(fmt.Sprintf("Unknown authz handler %q", c.String(defaults.AuthorizerFlag)))
			}

			srv := core.NewAuthZSrv(authZHandler, auditor)
			return srv.Start()
		},

		Flags: []cli.Flag{
			// debug
			&cli.BoolFlag{
				Name:    defaults.DebugFlag,
				Usage:   "Enable debug mode",
				EnvVars: []string{"DEBUG"},
			},

			// policy file
			&cli.StringFlag{
				Name:  defaults.PolicyFileFlag,
				Value: defaults.PolicyFileAnubis,
				Usage: "Defines the authz policy file for basic handler",
			},

			// authorizer
			&cli.StringFlag{
				Name:    defaults.AuthorizerFlag,
				Value:   defaults.AuthorizerAnubis,
				EnvVars: []string{"AUTHORIZER"},
				Usage:   "Defines the authz handler type",
			},

			// auditor
			&cli.StringFlag{
				Name:    defaults.AuditorFlag,
				Value:   defaults.AuditorBasic,
				EnvVars: []string{"AUDITOR"},
				Usage:   "Defines the authz auditor type",
			},
			&cli.StringFlag{
				Name:    defaults.AuditorHookFlag,
				Value:   authz.AuditHookStdout,
				EnvVars: []string{"AUDITOR_HOOK"},
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
