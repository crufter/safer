package safer

func inspectPackageManager(tool string, args []string, source string) []Finding {
	verb, rest := firstOperand(args)
	if verb == "" {
		return nil
	}

	if tool == "uv" && verb == "pip" {
		pipVerb, pipRest := firstOperand(rest)
		return inspectPackageManager("pip", append([]string{pipVerb}, pipRest...), source)
	}

	switch tool {
	case "go":
		switch verb {
		case "get", "install":
			return []Finding{newFinding(source, RiskDataWrite, "go command changes dependencies or installs binaries", "go "+verb)}
		case "mod":
			sub, _ := firstOperand(rest)
			if sub == "tidy" || sub == "edit" || sub == "vendor" {
				return []Finding{newFinding(source, RiskDataWrite, "go mod command writes module files", "go mod "+sub)}
			}
			return nil
		case "work":
			sub, _ := firstOperand(rest)
			if sub == "sync" || sub == "edit" || sub == "use" {
				return []Finding{newFinding(source, RiskDataWrite, "go work command writes workspace files", "go work "+sub)}
			}
			return nil
		case "test", "build", "vet", "list", "version", "env":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, "go subcommand is not known read-only", "go "+verb)}
		}
	case "cargo":
		if verb == "remove" || verb == "uninstall" {
			return []Finding{newFinding(source, RiskDataDelete, "cargo removal command requires user attention", "cargo "+verb)}
		}
		if verb == "add" || verb == "install" || verb == "update" || verb == "publish" || verb == "yank" {
			return []Finding{newFinding(source, RiskDataWrite, "cargo command changes dependencies or registry state", "cargo "+verb)}
		}
		if verb == "test" || verb == "build" || verb == "check" || verb == "clippy" || verb == "fmt" || verb == "tree" || verb == "metadata" {
			return nil
		}
		return []Finding{newFinding(source, RiskUnknown, "cargo subcommand is not known read-only", "cargo "+verb)}
	}

	if isPackageRemoval(tool, verb) {
		return []Finding{newFinding(source, RiskDataDelete, tool+" removal command requires user attention", tool+" "+verb)}
	}
	if isPackageInstallOrUpdate(tool, verb, rest) {
		return []Finding{newFinding(source, RiskDataWrite, tool+" command changes dependencies or installed packages", tool+" "+verb)}
	}
	if isPackageReadCommand(verb) {
		return nil
	}
	return []Finding{newFinding(source, RiskUnknown, tool+" subcommand is not known read-only", tool+" "+verb)}
}

func isPackageRemoval(tool, verb string) bool {
	switch verb {
	case "uninstall", "remove", "rm", "purge", "autoremove":
		return true
	case "del":
		return tool == "yarn" || tool == "bun"
	default:
		return false
	}
}

func isPackageInstallOrUpdate(tool, verb string, rest []string) bool {
	switch verb {
	case "install", "i", "add", "update", "upgrade", "link", "publish", "ci", "sync", "lock", "pin", "tap", "untap":
		return true
	case "audit":
		sub, _ := firstOperand(rest)
		return sub == "fix"
	case "cache":
		sub, _ := firstOperand(rest)
		return sub == "clean" || sub == "prune"
	case "services":
		return tool == "brew"
	default:
		return false
	}
}

func isPackageReadCommand(verb string) bool {
	switch verb {
	case "list", "ls", "info", "show", "view", "search", "outdated", "why", "test", "run", "version", "help", "audit":
		return true
	default:
		return false
	}
}
