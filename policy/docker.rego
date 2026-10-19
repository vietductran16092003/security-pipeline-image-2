package docker

import rego.v1

# Rule 1: USER cuối cùng không được là root (bắt buộc)
deny contains msg if {
	user_cmds := [v |
		some i
		input[i].Cmd == "user"
		v := input[i].Value[0]
	]
	count(user_cmds) > 0
	lower(user_cmds[count(user_cmds) - 1]) in {"root", "0"}
	msg := "[DENY] USER cuối phải là non-root. Dùng 'USER <username>' hoặc 'USER <uid>' (uid khác 0)"
}

# Rule 2: không dùng tag :latest cho base image (khuyến nghị)
warn contains msg if {
	some i
	input[i].Cmd == "from"
	image := input[i].Value[0]
	endswith(image, ":latest")
	msg := sprintf("[WARN] Image '%v' dùng tag :latest, nên pin phiên bản cụ thể (vd: node:20.11-alpine)", [image])
}

# Rule 3: nên có HEALTHCHECK (khuyến nghị)
warn contains msg if {
	not has_healthcheck
	msg := "[WARN] Không có HEALTHCHECK, nên thêm để orchestrator theo dõi container"
}

has_healthcheck if {
	some i
	input[i].Cmd == "healthcheck"
}
