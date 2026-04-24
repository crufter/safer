package safer

import (
	"path/filepath"
	"strings"
)

func CheckCommand(req CheckRequest) []Finding {
	caps := req.Capabilities
	if caps == (Capabilities{}) && req.Mode != "" {
		caps = capabilitiesFromMode(req.Mode)
	}
	findings := inspectTool(normalizedTool(req.Tool), req.Args, req.WorkDir, "command")
	return filterFindings(findings, caps)
}

func filterFindings(findings []Finding, caps Capabilities) []Finding {
	var filtered []Finding
	for _, finding := range uniqueFindings(findings) {
		if shouldAlert(caps, finding.Risk) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func capabilitiesFromMode(mode Mode) Capabilities {
	mode, err := NormalizeMode(mode)
	if err != nil {
		return Capabilities{}
	}
	switch mode {
	case ModeNondestructive:
		return Capabilities{DataWrite: true, EnvEphemeral: true, EnvPersistent: true}
	case ModeReadonly:
		return Capabilities{}
	case ModeCareful:
		return Capabilities{}
	default:
		return Capabilities{}
	}
}

func shouldAlert(caps Capabilities, risk Risk) bool {
	switch risk {
	case RiskDataWrite:
		return !caps.DataWrite
	case RiskDataDelete:
		return !caps.DataDelete
	case RiskEnvEphemeral:
		return !caps.EnvEphemeral
	case RiskEnvPersistent:
		return !caps.EnvPersistent
	case RiskUnknown:
		return !caps.AllowUnknown
	default:
		return true
	}
}

func inspectTool(tool string, args []string, workDir, source string) []Finding {
	switch {
	case isSQLTool(tool):
		return inspectSQLTool(tool, args, workDir, source)
	case isShellTool(tool):
		return inspectShellTool(tool, args, workDir, source)
	default:
		return inspectDirectTool(tool, args, workDir, source)
	}
}

func normalizedTool(tool string) string {
	return strings.ToLower(filepath.Base(tool))
}

func isSQLTool(tool string) bool {
	switch tool {
	case "psql", "mysql", "mariadb", "sqlite3":
		return true
	default:
		return false
	}
}

func isShellTool(tool string) bool {
	switch tool {
	case "bash", "sh", "zsh", "fish":
		return true
	default:
		return false
	}
}
