package safer

func inspectDocker(args []string, source string) []Finding {
	verb, rest := firstOperand(args)
	switch verb {
	case "":
		return nil
	case "compose":
		return inspectDockerCompose(rest, source)
	case "rm", "rmi", "kill":
		return []Finding{newFinding(source, RiskDataDelete, "docker deletion or kill command requires user attention", "docker "+verb)}
	case "prune":
		return []Finding{newFinding(source, RiskDataDelete, "docker prune removes resources and requires user attention", "docker prune")}
	case "system", "container", "image", "volume", "network", "builder":
		sub, _ := firstOperand(rest)
		switch sub {
		case "rm", "remove", "prune":
			return []Finding{newFinding(source, RiskDataDelete, "docker resource deletion requires user attention", "docker "+verb+" "+sub)}
		case "create":
			return []Finding{newFinding(source, RiskEnvEphemeral, "docker command changes local runtime state", "docker "+verb+" "+sub)}
		case "ls", "list", "inspect", "df":
			return nil
		default:
			return []Finding{newFinding(source, RiskUnknown, "docker subcommand is not known read-only", "docker "+verb+" "+sub)}
		}
	case "run", "create", "start", "stop", "restart", "pause", "unpause", "exec", "cp", "build", "pull", "tag", "commit":
		return []Finding{newFinding(source, RiskEnvEphemeral, "docker command changes local runtime state", "docker "+verb)}
	case "push", "login", "logout":
		return []Finding{newFinding(source, RiskEnvPersistent, "docker command changes remote runtime state", "docker "+verb)}
	case "ps", "images", "logs", "inspect", "stats", "version", "info", "events", "context":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, "docker subcommand is not known read-only", "docker "+verb)}
	}
}

func inspectDockerCompose(args []string, source string) []Finding {
	verb, _ := firstOperand(args)
	switch verb {
	case "":
		return nil
	case "down", "rm":
		return []Finding{newFinding(source, RiskDataDelete, "docker compose removes containers/resources and requires user attention", "docker compose "+verb)}
	case "up", "create", "start", "stop", "restart", "pause", "unpause", "kill", "build", "pull", "push", "run", "exec":
		return []Finding{newFinding(source, RiskEnvEphemeral, "docker compose command changes runtime state", "docker compose "+verb)}
	case "ps", "logs", "config", "version", "images", "top", "events", "ls":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, "docker compose subcommand is not known read-only", "docker compose "+verb)}
	}
}
