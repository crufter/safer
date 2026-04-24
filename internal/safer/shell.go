package safer

import (
	"regexp"
	"strings"
)

func inspectShellTool(tool string, args []string, workDir, source string) []Finding {
	var findings []Finding
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if inline, usesNext := shellCommandOption(arg); inline != "" || usesNext {
			if inline != "" {
				findings = append(findings, inspectShellScript(inline, workDir, tool+" -c")...)
				continue
			}
			if i+1 < len(args) {
				i++
				findings = append(findings, inspectShellScript(args[i], workDir, tool+" -c")...)
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if content, err := readFileRelative(workDir, arg); err == nil {
			findings = append(findings, inspectShellScript(string(content), workDir, source+" "+arg)...)
		}
	}
	return uniqueFindings(findings)
}

func shellCommandOption(arg string) (inline string, usesNext bool) {
	if arg == "-c" {
		return "", true
	}
	if strings.HasPrefix(arg, "-c") && len(arg) > 2 {
		return arg[2:], false
	}
	if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "c") {
		return "", true
	}
	return "", false
}

func inspectShellScript(script, workDir, source string) []Finding {
	var findings []Finding
	for _, command := range shellCommands(script) {
		if len(command.Words) == 0 {
			continue
		}
		tool := normalizedTool(command.Words[0])
		findings = append(findings, inspectTool(tool, command.Words[1:], workDir, source)...)
	}
	findings = append(findings, inspectShellPatterns(script, source)...)
	return uniqueFindings(findings)
}

func inspectSimpleCommand(command string, args []string, source string) []Finding {
	command = normalizedTool(command)
	if reason, ok := destructiveShellCommands[command]; ok {
		return []Finding{newFinding(source, RiskDataDelete, reason, command)}
	}
	if strings.HasPrefix(command, "mkfs.") {
		return []Finding{newFinding(source, RiskDataDelete, "filesystem formatting command requires user attention", command)}
	}
	if reason, ok := mutatingShellCommands[command]; ok {
		return []Finding{newFinding(source, RiskDataWrite, reason, command)}
	}
	if command == "chmod" || command == "chown" || command == "chgrp" {
		for _, arg := range args {
			if arg == "--recursive" || (strings.HasPrefix(arg, "-") && strings.Contains(arg, "R")) {
				return []Finding{newFinding(source, RiskDataDelete, "recursive ownership or permission change requires user attention", command)}
			}
		}
	}
	if readonlyShellAllowlist[command] {
		return nil
	}
	return []Finding{newFinding(source, RiskUnknown, "command is not known read-only", command)}
}

var destructiveShellCommands = map[string]string{
	"rm":       "file deletion command requires user attention",
	"rmdir":    "directory deletion command requires user attention",
	"unlink":   "file deletion command requires user attention",
	"truncate": "file truncation command requires user attention",
	"dd":       "raw copy command requires user attention",
	"mkfs":     "filesystem formatting command requires user attention",
	"kill":     "process termination command requires user attention",
	"pkill":    "process termination command requires user attention",
	"killall":  "process termination command requires user attention",
	"sudo":     "privilege escalation requires user attention",
	"su":       "privilege escalation requires user attention",
	"reboot":   "system reboot requires user attention",
	"shutdown": "system shutdown requires user attention",
	"halt":     "system shutdown requires user attention",
	"poweroff": "system shutdown requires user attention",
}

var mutatingShellCommands = map[string]string{
	"cp":      "file write command requires user attention",
	"mv":      "file move command requires user attention",
	"mkdir":   "directory creation command requires user attention",
	"touch":   "file creation command requires user attention",
	"tee":     "file write command requires user attention",
	"chmod":   "permission change command requires user attention",
	"chown":   "ownership change command requires user attention",
	"chgrp":   "ownership change command requires user attention",
	"install": "file installation command requires user attention",
	"ln":      "link creation command requires user attention",
}

var readonlyShellAllowlist = map[string]bool{
	"awk": true, "basename": true, "cat": true, "comm": true, "cut": true, "dirname": true,
	"echo": true, "env": true, "false": true, "find": true, "grep": true, "head": true,
	"jq": true, "less": true, "ls": true, "nl": true, "printf": true, "pwd": true,
	"rg": true, "sed": true, "sort": true, "stat": true, "tail": true, "test": true,
	"true": true, "uniq": true, "wc": true, "which": true, "whoami": true, "xargs": true,
	"yq": true,
}

type shellPattern struct {
	re     *regexp.Regexp
	risk   Risk
	reason string
	detail string
}

var shellPatterns = []shellPattern{
	{regexp.MustCompile(`(?is)\b(?:curl|wget)\b[^\n;|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b`), RiskDataDelete, "remote script execution requires user attention", "curl/wget piped to shell"},
	{regexp.MustCompile(`(?is)(?:^|[;&|]\s*)dd\b[^\n;]*\bof=`), RiskDataDelete, "raw copy with output target requires user attention", "dd of="},
	{regexp.MustCompile(`(?is)>\s*/dev/(?:sd|xvd|nvme|hd|mapper/)`), RiskDataDelete, "direct write to device path requires user attention", "> /dev/..."},
	{regexp.MustCompile(`(?is)\b(?:chmod|chown|chgrp)\b\s+(?:-[^\s]*R[^\s]*|--recursive)\b`), RiskDataDelete, "recursive ownership or permission change requires user attention", "chmod/chown -R"},
	{regexp.MustCompile(`(?is)\bfind\b[^\n;]*\b-delete\b`), RiskDataDelete, "find -delete requires user attention", "find -delete"},
	{regexp.MustCompile(`(?is)\bfind\b[^\n;]*\b-exec\s+(?:sudo\s+)?(?:rm|rmdir|unlink)\b`), RiskDataDelete, "find -exec deletion requires user attention", "find -exec rm"},
	{regexp.MustCompile(`(?is)\bxargs\b[^\n;|]*\b(?:rm|rmdir|unlink)\b`), RiskDataDelete, "xargs deletion requires user attention", "xargs rm"},
	{regexp.MustCompile(`(?m)(^|[^<>])>>?\s*[^&\s]`), RiskDataWrite, "shell redirection writes to a file", "redirect"},
}

func inspectShellPatterns(script, source string) []Finding {
	var findings []Finding
	for _, pattern := range shellPatterns {
		if pattern.re.MatchString(script) {
			findings = append(findings, newFinding(source, pattern.risk, pattern.reason, pattern.detail))
		}
	}
	return uniqueFindings(findings)
}

type shellCommand struct {
	Words []string
}

func shellCommands(script string) []shellCommand {
	var commands []shellCommand
	var current []string

	flush := func() {
		if len(current) > 0 {
			commands = append(commands, shellCommand{Words: current})
			current = nil
		}
	}

	for i := 0; i < len(script); {
		c := script[i]

		if isShellHorizontalSpace(c) {
			i++
			continue
		}
		if isShellSeparator(c) {
			flush()
			i++
			continue
		}
		if c == '#' {
			for i < len(script) && script[i] != '\n' {
				i++
			}
			flush()
			continue
		}

		word, next := readShellWord(script, i)
		i = next
		if word == "" {
			continue
		}
		lower := strings.ToLower(word)

		if len(current) == 0 {
			if isShellControlWord(lower) || isShellAssignment(word) {
				continue
			}
		}
		current = append(current, word)
	}
	flush()

	return commands
}

func readShellWord(script string, start int) (string, int) {
	var b strings.Builder
	i := start
	for i < len(script) {
		c := script[i]
		if isShellHorizontalSpace(c) || isShellSeparator(c) {
			break
		}
		if c == '\'' || c == '"' {
			quote := c
			i++
			for i < len(script) && script[i] != quote {
				if quote == '"' && script[i] == '\\' && i+1 < len(script) {
					i += 2
					continue
				}
				b.WriteByte(script[i])
				i++
			}
			if i < len(script) {
				i++
			}
			continue
		}
		if c == '\\' && i+1 < len(script) {
			b.WriteByte(script[i+1])
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), i
}

func isShellHorizontalSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r'
}

func isShellSeparator(c byte) bool {
	return c == ';' || c == '&' || c == '|' || c == '(' || c == ')' || c == '\n'
}

func isShellAssignment(word string) bool {
	if strings.HasPrefix(word, "-") {
		return false
	}
	idx := strings.IndexByte(word, '=')
	if idx <= 0 {
		return false
	}
	name := word[:idx]
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isShellControlWord(word string) bool {
	switch word {
	case "then", "do", "else", "elif", "fi", "done", "case", "esac", "time", "while", "until", "if", "for", "function":
		return true
	default:
		return false
	}
}
