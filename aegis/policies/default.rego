package aegis

import rego.v1

# Helper: true when the tool is a shell/bash command
is_shell_tool if {
	input.tool.name == "shell"
}

is_shell_tool if {
	input.tool.name == "Bash"
}

# Deny destructive shell commands
deny contains reason if {
	is_shell_tool
	cmd := input.tool.arguments.command
	destructive_patterns := [
		"rm -rf /",
		"rm -rf /*",
		"rm -rf ~",
		"rm -rf ~/",
		"mkfs.",
		"dd if=/dev/zero",
		"dd if=/dev/random",
		"> /dev/sda",
		"chmod -R 777 /",
		"chown -R",
		":(){:|:&};:",
	]
	some pattern in destructive_patterns
	contains(cmd, pattern)
	reason := sprintf("destructive command blocked: %s", [pattern])
}

# Deny format/wipe commands
deny contains reason if {
	is_shell_tool
	cmd := input.tool.arguments.command
	startswith(trim_space(cmd), "rm -rf /")
	reason := "destructive rm at filesystem root"
}

# Deny any push to main/master (not just force push)
deny contains reason if {
	is_shell_tool
	cmd := input.tool.arguments.command
	contains(cmd, "git push")
	targets_main(cmd)
	reason := "push to main/master branch is blocked — use a feature branch and create a PR"
}

targets_main(cmd) if {
	contains(cmd, " main")
}

targets_main(cmd) if {
	contains(cmd, " master")
}

# Deny writes outside project directory
deny contains reason if {
	input.tool.name == "write_file"
	path := input.tool.arguments.path
	not startswith(path, input.project_dir)
	reason := sprintf("write outside project directory blocked: %s", [path])
}

# Also catch Claude Code's Write tool
deny contains reason if {
	input.tool.name == "Write"
	path := input.tool.arguments.file_path
	not startswith(path, input.project_dir)
	reason := sprintf("write outside project directory blocked: %s", [path])
}

# Deny shell commands that write outside project
deny contains reason if {
	is_shell_tool
	cmd := input.tool.arguments.command
	redirect_targets := ["> /", ">> /", "> ~/", ">> ~/"]
	some target in redirect_targets
	contains(cmd, target)
	not contains(cmd, concat("", ["> ", input.project_dir]))
	not contains(cmd, concat("", [">> ", input.project_dir]))
	reason := "shell redirect outside project directory"
}
