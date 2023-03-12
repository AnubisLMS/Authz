#!/usr/bin/env bash

name=anubis_authz_broker
cp ./anubis_authz_broker /usr/bin/

cat <<SERVICE > "/lib/systemd/system/anubis-authz.service"
[Unit]
Description=anubis docker authorization plugin
After=syslog.target
[Service]
Type=simple
ExecStart=/usr/bin/authz-broker
[Install]
WantedBy=multi-user.target
SERVICE

# sudo systemctl enable my-app
# sudo systemctl start my-app
