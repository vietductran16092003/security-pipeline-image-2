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

df_no_user := [{"Cmd": "from", "Value": ["node:20.11-alpine"]}]

df_root_group := [
	{"Cmd": "from", "Value": ["node:20.11-alpine"]},
	{"Cmd": "user", "Value": ["root:root"]},
]

df_uid0 := [
	{"Cmd": "from", "Value": ["node:20.11-alpine"]},
	{"Cmd": "user", "Value": ["0:0"]},
]

df_uid1000 := [
	{"Cmd": "from", "Value": ["node:20.11-alpine"]},
	{"Cmd": "user", "Value": ["1000:1000"]},
]

test_no_user_denied if {
	count(deny) > 0 with input as df_no_user
}

test_root_with_group_denied if {
	count(deny) > 0 with input as df_root_group
}

test_uid0_with_group_denied if {
	count(deny) > 0 with input as df_uid0
}

test_uid1000_not_denied if {
	count(deny) == 0 with input as df_uid1000
}

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
