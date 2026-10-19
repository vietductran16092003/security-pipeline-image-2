package docker

import rego.v1

df_root := [
	{"Cmd": "from", "Value": ["node:20.11-alpine"]},
	{"Cmd": "user", "Value": ["root"]},
]

df_app := [
	{"Cmd": "from", "Value": ["node:20.11-alpine"]},
	{"Cmd": "user", "Value": ["app"]},
	{"Cmd": "healthcheck", "Value": ["CMD", "true"]},
]

df_latest := [
	{"Cmd": "from", "Value": ["node:latest", "AS", "build"]},
	{"Cmd": "user", "Value": ["app"]},
]

test_root_user_denied if {
	count(deny) > 0 with input as df_root
}

test_non_root_not_denied if {
	count(deny) == 0 with input as df_app
}

test_latest_warned_even_with_alias if {
	some msg in warn with input as df_latest
	contains(msg, ":latest")
}

test_healthcheck_present_no_warning if {
	count(warn) == 0 with input as df_app
}

test_missing_healthcheck_warned if {
	some msg in warn with input as df_root
	contains(msg, "HEALTHCHECK")
}
