package safer

import (
	"fmt"
	"strings"
)

type sqlSource struct {
	Name string
	SQL  string
}

func inspectSQLTool(tool string, args []string, workDir, source string) []Finding {
	sources, findings := collectSQLSources(tool, args, workDir, source)
	for _, source := range sources {
		findings = append(findings, inspectSQL(source)...)
	}
	return uniqueFindings(findings)
}

func collectSQLSources(tool string, args []string, workDir, source string) ([]sqlSource, []Finding) {
	var sources []sqlSource
	var findings []Finding
	seenSQLiteDatabase := false

	readSQLFile := func(sourceName, path string) {
		content, err := readFileRelative(workDir, path)
		if err != nil {
			findings = append(findings, newFinding(sourceName, RiskDataDelete, "SQL file could not be inspected", fmt.Sprintf("%s: %v", path, err)))
			return
		}
		sources = append(sources, sqlSource{Name: sourceName + " " + path, SQL: string(content)})
	}

	sqlSourceName := func(flag string) string {
		if source == "" || source == "command" {
			return flag
		}
		return source + " " + tool + " " + flag
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch tool {
		case "psql":
			switch {
			case arg == "-c" || arg == "--command":
				if i+1 < len(args) {
					i++
					sources = append(sources, sqlSource{Name: sqlSourceName(arg), SQL: args[i]})
				}
			case strings.HasPrefix(arg, "--command="):
				sources = append(sources, sqlSource{Name: sqlSourceName("--command"), SQL: strings.TrimPrefix(arg, "--command=")})
			case strings.HasPrefix(arg, "-c") && len(arg) > 2:
				sources = append(sources, sqlSource{Name: sqlSourceName("-c"), SQL: arg[2:]})
			case arg == "-f" || arg == "--file":
				if i+1 < len(args) {
					i++
					readSQLFile(sqlSourceName(arg), args[i])
				}
			case strings.HasPrefix(arg, "--file="):
				readSQLFile(sqlSourceName("--file"), strings.TrimPrefix(arg, "--file="))
			case strings.HasPrefix(arg, "-f") && len(arg) > 2:
				readSQLFile(sqlSourceName("-f"), arg[2:])
			}
		case "mysql", "mariadb":
			switch {
			case arg == "-e" || arg == "--execute":
				if i+1 < len(args) {
					i++
					sources = append(sources, sqlSource{Name: sqlSourceName(arg), SQL: args[i]})
				}
			case strings.HasPrefix(arg, "--execute="):
				sources = append(sources, sqlSource{Name: sqlSourceName("--execute"), SQL: strings.TrimPrefix(arg, "--execute=")})
			case strings.HasPrefix(arg, "-e") && len(arg) > 2:
				sources = append(sources, sqlSource{Name: sqlSourceName("-e"), SQL: arg[2:]})
			}
		case "sqlite3":
			if arg == ".read" && i+1 < len(args) {
				i++
				readSQLFile(sqlSourceName(".read"), args[i])
				continue
			}
			if strings.HasPrefix(arg, ".read ") {
				readSQLFile(sqlSourceName(".read"), strings.TrimSpace(strings.TrimPrefix(arg, ".read ")))
				continue
			}
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if !seenSQLiteDatabase && !strings.ContainsAny(arg, " \t\n;") {
				seenSQLiteDatabase = true
				continue
			}
			if looksLikeSQL(arg) {
				sources = append(sources, sqlSource{Name: sqlSourceName("arg"), SQL: arg})
			}
		}
	}

	return sources, findings
}

func looksLikeSQL(input string) bool {
	words := sqlWords(input)
	if len(words) == 0 {
		return false
	}
	first := words[0]
	switch first {
	case "select", "with", "show", "describe", "desc", "explain", "values", "pragma",
		"insert", "update", "delete", "drop", "truncate", "alter", "create", "grant", "revoke", "merge", "copy":
		return true
	default:
		return false
	}
}

func inspectSQL(source sqlSource) []Finding {
	words := sqlWords(source.SQL)
	if len(words) == 0 {
		return nil
	}

	var findings []Finding
	for _, first := range statementFirstWords(words) {
		if destructiveSQL[first] {
			continue
		}
		if !readonlySQL[first] {
			findings = append(findings, newFinding(source.Name, RiskDataWrite, "SQL statement changes database state", strings.ToUpper(first)))
		}
	}

	for _, word := range words {
		if destructiveSQL[word] {
			findings = append(findings, newFinding(source.Name, RiskDataDelete, fmt.Sprintf("%s requires user attention", strings.ToUpper(word)), strings.ToUpper(word)))
		}
	}

	return uniqueFindings(findings)
}

var readonlySQL = map[string]bool{
	"select":   true,
	"with":     true,
	"show":     true,
	"describe": true,
	"desc":     true,
	"explain":  true,
	"values":   true,
	"pragma":   true,
}

var destructiveSQL = map[string]bool{
	"delete":   true,
	"drop":     true,
	"truncate": true,
	"alter":    true,
	"grant":    true,
	"revoke":   true,
}

func statementFirstWords(words []string) []string {
	var firsts []string
	expectFirst := true
	for _, word := range words {
		if word == ";" {
			expectFirst = true
			continue
		}
		if expectFirst {
			firsts = append(firsts, word)
			expectFirst = false
		}
	}
	return firsts
}

func sqlWords(input string) []string {
	var words []string
	for i := 0; i < len(input); {
		c := input[i]

		if isSQLWordByte(c) {
			start := i
			for i < len(input) && isSQLWordByte(input[i]) {
				i++
			}
			words = append(words, strings.ToLower(input[start:i]))
			continue
		}

		if c == ';' {
			words = append(words, ";")
			i++
			continue
		}

		if c == '-' && i+1 < len(input) && input[i+1] == '-' {
			i += 2
			for i < len(input) && input[i] != '\n' {
				i++
			}
			continue
		}

		if c == '/' && i+1 < len(input) && input[i+1] == '*' {
			i += 2
			for i+1 < len(input) && !(input[i] == '*' && input[i+1] == '/') {
				i++
			}
			if i+1 < len(input) {
				i += 2
			}
			continue
		}

		if c == '\'' || c == '"' {
			i = skipQuoted(input, i, c)
			continue
		}

		if c == '$' {
			if end := dollarQuoteEnd(input, i); end > i {
				i = end
				continue
			}
		}

		i++
	}
	return words
}

func isSQLWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func skipQuoted(input string, start int, quote byte) int {
	i := start + 1
	for i < len(input) {
		if input[i] == quote {
			if i+1 < len(input) && input[i+1] == quote {
				i += 2
				continue
			}
			return i + 1
		}
		if input[i] == '\\' && i+1 < len(input) {
			i += 2
			continue
		}
		i++
	}
	return len(input)
}

func dollarQuoteEnd(input string, start int) int {
	endTag := start + 1
	for endTag < len(input) && (isSQLWordByte(input[endTag]) || input[endTag] == '_') {
		endTag++
	}
	if endTag >= len(input) || input[endTag] != '$' {
		return start
	}
	tag := input[start : endTag+1]
	if len(tag) < 2 {
		return start
	}
	if end := strings.Index(input[endTag+1:], tag); end >= 0 {
		return endTag + 1 + end + len(tag)
	}
	return len(input)
}
