package safer

import (
	"os"
	"path/filepath"
	"strings"
)

func readFileRelative(workDir, path string) ([]byte, error) {
	if workDir != "" && !filepath.IsAbs(path) {
		path = filepath.Join(workDir, path)
	}
	return os.ReadFile(path)
}

func firstOperand(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return strings.ToLower(args[i+1]), args[i+2:]
			}
			return "", nil
		}
		if strings.HasPrefix(arg, "-") {
			if flagConsumesValue(arg) && i+1 < len(args) {
				i++
			}
			continue
		}
		return strings.ToLower(arg), args[i+1:]
	}
	return "", nil
}

func flagConsumesValue(arg string) bool {
	if strings.Contains(arg, "=") {
		return false
	}
	switch arg {
	case "-C", "-c", "-f", "-k", "-l", "-n", "-o", "-p", "-s", "-u",
		"--context", "--filename", "--file", "--kubeconfig", "--namespace", "--output", "--selector",
		"--config", "--profile", "--project", "--region", "--resource-group", "--subscription",
		"--repo", "--repository", "--tag", "--message", "--name", "--user":
		return true
	default:
		return false
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if strings.EqualFold(arg, want) {
			return true
		}
	}
	return false
}

func hasShortFlag(args []string, flag string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") || !strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg[1:], flag) {
			return true
		}
	}
	return false
}

func hasFlagPrefix(args []string, prefix string) bool {
	for _, arg := range args {
		if strings.HasPrefix(strings.ToLower(arg), strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func lowerWords(args []string) []string {
	words := make([]string, 0, len(args))
	for _, arg := range args {
		arg = strings.TrimLeft(arg, "-")
		if arg == "" || strings.Contains(arg, "=") {
			continue
		}
		words = append(words, strings.ToLower(arg))
	}
	return words
}

func hasAnyPrefix(word string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(word, prefix) {
			return true
		}
	}
	return false
}

func displayCommand(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if strings.IndexFunc(arg, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || r == '=' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) == -1 {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
}

func newFinding(source string, risk Risk, reason, detail string) Finding {
	if source == "" {
		source = "command"
	}
	return Finding{Source: source, Risk: risk, Reason: reason, Detail: detail}
}

func uniqueFindings(findings []Finding) []Finding {
	seen := make(map[Finding]bool)
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if seen[finding] {
			continue
		}
		seen[finding] = true
		out = append(out, finding)
	}
	return out
}
