package safer

func inspectGit(args []string, source string) []Finding {
	verb, rest := firstOperand(args)
	switch verb {
	case "":
		return nil
	case "reset":
		if hasArg(rest, "--hard") {
			return []Finding{newFinding(source, RiskDataDelete, "git reset --hard requires user attention", "git reset --hard")}
		}
		return []Finding{newFinding(source, RiskDataWrite, "git reset changes repository state", "git reset")}
	case "clean":
		if hasShortFlag(rest, "f") || hasArg(rest, "--force") {
			return []Finding{newFinding(source, RiskDataDelete, "git clean with force requires user attention", "git clean -f")}
		}
		return nil
	case "push":
		if hasArg(rest, "--force") || hasArg(rest, "--force-with-lease") || hasShortFlag(rest, "f") {
			return []Finding{newFinding(source, RiskDataDelete, "git force push requires user attention", "git push --force")}
		}
		return []Finding{newFinding(source, RiskEnvPersistent, "git push changes remote repository state", "git push")}
	case "branch":
		if hasArg(rest, "-D") || hasArg(rest, "-d") || hasArg(rest, "--delete") {
			return []Finding{newFinding(source, RiskDataDelete, "git branch deletion requires user attention", "git branch -d")}
		}
		if len(rest) > 0 {
			return []Finding{newFinding(source, RiskDataWrite, "git branch command changes repository refs", "git branch")}
		}
		return nil
	case "tag":
		if hasArg(rest, "-d") || hasArg(rest, "--delete") {
			return []Finding{newFinding(source, RiskDataDelete, "git tag deletion requires user attention", "git tag -d")}
		}
		if len(rest) > 0 {
			return []Finding{newFinding(source, RiskDataWrite, "git tag command changes repository refs", "git tag")}
		}
		return nil
	case "add", "commit", "restore", "checkout", "switch", "merge", "rebase", "cherry-pick", "revert", "stash", "pull", "fetch", "clone", "init", "remote", "submodule", "worktree":
		return []Finding{newFinding(source, RiskDataWrite, "git command changes local or remote repository state", "git "+verb)}
	case "status", "log", "diff", "show", "grep", "ls-files", "rev-parse", "remote-ls", "describe", "blame":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, "git subcommand is not known read-only", "git "+verb)}
	}
}

func inspectGitHubCLI(args []string, source string) []Finding {
	area, rest := firstOperand(args)
	verb, _ := firstOperand(rest)
	switch area {
	case "repo":
		if verb == "delete" {
			return []Finding{newFinding(source, RiskDataDelete, "gh repo delete requires user attention", "gh repo delete")}
		}
		if verb == "create" || verb == "edit" || verb == "rename" || verb == "archive" || verb == "unarchive" || verb == "fork" {
			return []Finding{newFinding(source, RiskEnvPersistent, "gh repo command changes GitHub state", "gh repo "+verb)}
		}
	case "pr":
		if verb == "close" || verb == "merge" {
			return []Finding{newFinding(source, RiskDataDelete, "gh pr command changes pull request state", "gh pr "+verb)}
		}
		if verb == "create" || verb == "edit" || verb == "ready" || verb == "reopen" || verb == "review" || verb == "comment" {
			return []Finding{newFinding(source, RiskEnvPersistent, "gh pr command changes pull request state", "gh pr "+verb)}
		}
	case "issue":
		if verb == "close" || verb == "delete" {
			return []Finding{newFinding(source, RiskDataDelete, "gh issue command changes issue state", "gh issue "+verb)}
		}
		if verb == "create" || verb == "edit" || verb == "reopen" || verb == "comment" || verb == "transfer" {
			return []Finding{newFinding(source, RiskEnvPersistent, "gh issue command changes issue state", "gh issue "+verb)}
		}
	case "release":
		if verb == "delete" {
			return []Finding{newFinding(source, RiskDataDelete, "gh release delete requires user attention", "gh release delete")}
		}
		if verb == "create" || verb == "edit" || verb == "upload" {
			return []Finding{newFinding(source, RiskEnvPersistent, "gh release command changes release state", "gh release "+verb)}
		}
	}
	if area == "api" && hasFlagPrefix(rest, "-X") {
		return []Finding{newFinding(source, RiskEnvPersistent, "gh api with explicit method can change GitHub state", "gh api")}
	}
	if area == "auth" {
		switch verb {
		case "status", "token":
			return nil
		default:
			return []Finding{newFinding(source, RiskDataWrite, "gh auth command changes local credentials", "gh auth "+verb)}
		}
	}
	if ghDestructiveVerbs[verb] {
		return []Finding{newFinding(source, RiskDataDelete, "gh command removes or closes GitHub state", "gh "+area+" "+verb)}
	}
	if ghMutatingVerbs[verb] {
		return []Finding{newFinding(source, RiskEnvPersistent, "gh command changes GitHub state", "gh "+area+" "+verb)}
	}
	switch area {
	case "", "browse", "search", "status", "alias", "completion", "config", "extension", "gpg-key", "label", "ruleset", "secret", "ssh-key", "variable", "workflow":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, "gh subcommand is not known read-only", "gh "+area)}
	}
}

var ghDestructiveVerbs = map[string]bool{
	"close": true, "delete": true, "disable": true, "remove": true, "rm": true,
}

var ghMutatingVerbs = map[string]bool{
	"add": true, "create": true, "edit": true, "enable": true, "run": true, "set": true, "upload": true,
}
