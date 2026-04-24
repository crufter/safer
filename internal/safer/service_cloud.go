package safer

func inspectServiceManager(tool string, args []string, source string) []Finding {
	verb, _ := firstOperand(args)
	switch verb {
	case "":
		return nil
	case "kill", "disable", "mask":
		return []Finding{newFinding(source, RiskDataDelete, tool+" command can remove service availability and requires user attention", tool+" "+verb)}
	case "start", "stop", "restart", "reload", "enable", "reenable", "unmask", "daemon-reload":
		return []Finding{newFinding(source, RiskEnvEphemeral, tool+" command changes service state", tool+" "+verb)}
	case "status", "show", "list-units", "list-unit-files", "is-active", "is-enabled", "cat":
		return nil
	default:
		return []Finding{newFinding(source, RiskUnknown, tool+" subcommand is not known read-only", tool+" "+verb)}
	}
}

func inspectCloudCLI(tool string, args []string, source string) []Finding {
	for _, word := range lowerWords(args) {
		if cloudDestructiveWords[word] || hasAnyPrefix(word, "delete-", "remove-", "terminate-", "destroy-", "purge-") {
			return []Finding{newFinding(source, RiskDataDelete, tool+" destructive cloud operation requires user attention", tool+" "+word)}
		}
	}
	for _, word := range lowerWords(args) {
		if cloudMutatingWords[word] || hasAnyPrefix(word, "create-", "update-", "put-", "modify-", "start-", "stop-", "restart-", "reboot-", "attach-", "detach-", "enable-", "disable-", "deploy-") {
			return []Finding{newFinding(source, RiskEnvPersistent, tool+" cloud operation changes remote state", tool+" "+word)}
		}
	}
	return nil
}

var cloudDestructiveWords = map[string]bool{
	"delete": true, "destroy": true, "remove": true, "rm": true, "terminate": true, "purge": true,
}

var cloudMutatingWords = map[string]bool{
	"add": true, "apply": true, "attach": true, "authorize": true, "create": true, "deploy": true,
	"detach": true, "disable": true, "enable": true, "grant": true, "modify": true, "put": true,
	"reboot": true, "restart": true, "revoke": true, "save": true, "set": true, "start": true,
	"stop": true, "unset": true, "update": true,
}
