package safer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	core "github.com/crufter/safer/internal/safer"
	"github.com/spf13/cobra"
)

const exitBlocked = 2

type config struct {
	capabilities core.Capabilities
	action       core.Action
	dryRun       bool
}

func Execute(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRootCommand(stdin, stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		if errors.Is(err, errBlocked) {
			return exitBlocked
		}
		var exitErr commandExitError
		if errors.As(err, &exitErr) {
			return exitErr.code
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

var errBlocked = errors.New("blocked")

type commandExitError struct {
	code int
}

func (err commandExitError) Error() string {
	return fmt.Sprintf("command exited with status %d", err.code)
}

func newRootCommand(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	cfg, configErr := loadConfig(mustGetwd())
	modeValue := ""
	levelValue := ""
	modeAliasValue := ""
	actionValue := string(cfg.action)
	dataWrite := cfg.capabilities.DataWrite
	dataDelete := cfg.capabilities.DataDelete
	envEphemeral := cfg.capabilities.EnvEphemeral
	envPersistent := cfg.capabilities.EnvPersistent
	allowUnknown := cfg.capabilities.AllowUnknown
	dw := false
	dd := false
	ee := false
	ep := false
	readonly := false
	careful := false
	nondestructive := false

	cmd := &cobra.Command{
		Use:   "safer [flags] <command> [args...]",
		Short: "Run an AI-generated command after checking its required capabilities.",
		Long: strings.TrimSpace(`
safer is a command wrapper for AI coding agents that have shell access to your
workspace.

It inspects a command before execution and raises a visible alert when the
command needs capabilities that were not explicitly granted. By default safer
allows only known read-only commands. Use flags to grant data, environment, or
unknown-command capabilities.

safer is not a sandbox, a permissions system, or a CI/CD policy engine. It is a
pre-execution guardrail for local agent workspaces.

Capabilities:
  --data-write       allow non-destructive data/workspace/database writes
  --data-delete      allow data deletion/removal and destructive data actions
  --env-ephemeral    allow temporary runtime/session/environment operations
  --env-persistent   allow persistent environment/infrastructure changes
  --allow-unknown    allow unknown commands/subcommands

Actions:
  block           print the alert and exit with status 2.
  warn            print the alert, then run the command anyway.

Environment:
  .saferrc        repo defaults, for example: data_write=true
  SAFER_*         capability defaults such as SAFER_DATA_WRITE=true
`),
		Example: `  safer psql -c 'SELECT * FROM users'
  safer --dw git commit -m change
  safer --ee kubectl port-forward svc/api 8080:80
  safer --ep terraform apply`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("missing command")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, command []string) error {
			if configErr != nil {
				return configErr
			}

			caps := core.Capabilities{
				DataWrite:     dataWrite || dw,
				DataDelete:    dataDelete || dd,
				EnvEphemeral:  envEphemeral || ee,
				EnvPersistent: envPersistent || ep,
				AllowUnknown:  allowUnknown,
			}
			modeFlagCount := 0
			for _, name := range []string{"care", "level", "mode", "readonly", "careful", "nondestructive"} {
				if cmd.Flags().Changed(name) {
					modeFlagCount++
				}
			}
			if modeFlagCount > 1 {
				return fmt.Errorf("choose only one compatibility mode flag")
			}
			selectedMode := modeValue
			if cmd.Flags().Changed("level") {
				selectedMode = levelValue
			}
			if cmd.Flags().Changed("mode") {
				selectedMode = modeAliasValue
			}
			if readonly {
				selectedMode = string(core.ModeReadonly)
			}
			if careful {
				selectedMode = string(core.ModeCareful)
			}
			if nondestructive {
				selectedMode = string(core.ModeNondestructive)
			}
			if selectedMode != "" {
				compatCaps, err := capabilitiesFromModeValue(selectedMode)
				if err != nil {
					return err
				}
				caps = compatCaps
			}
			cfg.capabilities = caps
			cfg.action = core.Action(actionValue)
			if err := core.ValidateAction(cfg.action); err != nil {
				return err
			}

			return runCheckedCommand(stdin, stdout, stderr, cfg, command)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	flags := cmd.Flags()
	flags.SetInterspersed(false)
	flags.BoolVar(&dataWrite, "data-write", dataWrite, "allow non-destructive data/workspace/database writes")
	flags.BoolVar(&dataDelete, "data-delete", dataDelete, "allow data deletion/removal and destructive data actions")
	flags.BoolVar(&envEphemeral, "env-ephemeral", envEphemeral, "allow temporary runtime/session/environment operations")
	flags.BoolVar(&envPersistent, "env-persistent", envPersistent, "allow persistent environment/infrastructure changes")
	flags.BoolVar(&allowUnknown, "allow-unknown", allowUnknown, "allow unknown commands/subcommands")
	flags.BoolVar(&dw, "dw", false, "alias for --data-write")
	flags.BoolVar(&dd, "dd", false, "alias for --data-delete")
	flags.BoolVar(&ee, "ee", false, "alias for --env-ephemeral")
	flags.BoolVar(&ep, "ep", false, "alias for --env-persistent")
	flags.StringVar(&modeValue, "care", "", "compatibility mode: nondestructive, careful, or readonly")
	flags.StringVar(&levelValue, "level", "", "alias for --care")
	flags.StringVar(&modeAliasValue, "mode", "", "alias for --care")
	flags.BoolVar(&readonly, "readonly", false, "shortcut for --care=readonly")
	flags.BoolVar(&careful, "careful", false, "shortcut for --care=careful")
	flags.BoolVar(&nondestructive, "nondestructive", false, "shortcut for --care=nondestructive")
	flags.StringVar(&actionValue, "action", actionValue, "alert action: block or warn")
	flags.BoolVar(&cfg.dryRun, "dry-run", false, "inspect only; do not execute the command")
	for _, name := range []string{"care", "level", "mode", "readonly", "careful", "nondestructive"} {
		_ = flags.MarkHidden(name)
	}

	return cmd
}

func runCheckedCommand(stdin io.Reader, stdout, stderr io.Writer, cfg config, command []string) error {
	tool := command[0]
	args := command[1:]
	findings := core.CheckCommand(core.CheckRequest{
		Tool:         tool,
		Args:         args,
		Capabilities: cfg.capabilities,
		WorkDir:      mustGetwd(),
	})

	if len(findings) > 0 {
		writeAlert(stderr, cfg, command, findings)
		if cfg.action == core.ActionBlock {
			return errBlocked
		}
	}

	if cfg.dryRun {
		return nil
	}

	cmd := exec.Command(tool, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return commandExitError{code: exitErr.ExitCode()}
		}
		return fmt.Errorf("failed to execute %s: %w", tool, err)
	}
	return nil
}

func loadConfig(workDir string) (config, error) {
	cfg := config{
		action: core.ActionBlock,
	}
	if path, ok := findConfigFile(workDir); ok {
		if err := applyConfigFile(&cfg, path); err != nil {
			return cfg, err
		}
	}
	if err := applyEnv(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func findConfigFile(workDir string) (string, bool) {
	if workDir == "" {
		return "", false
	}
	dir, err := filepath.Abs(workDir)
	if err != nil {
		return "", false
	}
	for {
		path := filepath.Join(dir, ".saferrc")
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func applyConfigFile(cfg *config, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := parseConfigLine(line)
		if !ok {
			return fmt.Errorf("%s:%d: expected key=value", path, lineNo)
		}
		if key == "" {
			continue
		}
		if err := applyConfigValue(cfg, key, value); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func parseConfigLine(line string) (string, string, bool) {
	line = strings.SplitN(line, "#", 2)[0]
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", true
	}
	sep := strings.IndexAny(line, "=:")
	if sep < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:sep])
	value := strings.TrimSpace(line[sep+1:])
	return strings.ToLower(key), value, key != "" && value != ""
}

func applyConfigValue(cfg *config, key, value string) error {
	switch key {
	case "data_write", "data-write":
		enabled, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.capabilities.DataWrite = enabled
	case "data_delete", "data-delete":
		enabled, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.capabilities.DataDelete = enabled
	case "env_ephemeral", "env-ephemeral":
		enabled, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.capabilities.EnvEphemeral = enabled
	case "env_persistent", "env-persistent":
		enabled, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.capabilities.EnvPersistent = enabled
	case "allow_unknown", "allow-unknown":
		enabled, err := parseBool(value)
		if err != nil {
			return err
		}
		cfg.capabilities.AllowUnknown = enabled
	case "care", "level", "mode":
		caps, err := capabilitiesFromModeValue(value)
		if err != nil {
			return err
		}
		cfg.capabilities = caps
	case "action":
		action := core.Action(strings.ToLower(value))
		if err := core.ValidateAction(action); err != nil {
			return err
		}
		cfg.action = action
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}

func applyEnv(cfg *config) error {
	if value := os.Getenv("SAFER_DATA_WRITE"); value != "" {
		enabled, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("SAFER_DATA_WRITE: %w", err)
		}
		cfg.capabilities.DataWrite = enabled
	}
	if value := os.Getenv("SAFER_DATA_DELETE"); value != "" {
		enabled, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("SAFER_DATA_DELETE: %w", err)
		}
		cfg.capabilities.DataDelete = enabled
	}
	if value := os.Getenv("SAFER_ENV_EPHEMERAL"); value != "" {
		enabled, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("SAFER_ENV_EPHEMERAL: %w", err)
		}
		cfg.capabilities.EnvEphemeral = enabled
	}
	if value := os.Getenv("SAFER_ENV_PERSISTENT"); value != "" {
		enabled, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("SAFER_ENV_PERSISTENT: %w", err)
		}
		cfg.capabilities.EnvPersistent = enabled
	}
	if value := os.Getenv("SAFER_ALLOW_UNKNOWN"); value != "" {
		enabled, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("SAFER_ALLOW_UNKNOWN: %w", err)
		}
		cfg.capabilities.AllowUnknown = enabled
	}
	if value := os.Getenv("SAFER_CARE"); value != "" {
		caps, err := capabilitiesFromModeValue(value)
		if err != nil {
			return fmt.Errorf("SAFER_CARE: %w", err)
		}
		cfg.capabilities = caps
	}
	if value := os.Getenv("SAFER_LEVEL"); value != "" {
		caps, err := capabilitiesFromModeValue(value)
		if err != nil {
			return fmt.Errorf("SAFER_LEVEL: %w", err)
		}
		cfg.capabilities = caps
	}
	if value := os.Getenv("SAFER_MODE"); value != "" {
		caps, err := capabilitiesFromModeValue(value)
		if err != nil {
			return fmt.Errorf("SAFER_MODE: %w", err)
		}
		cfg.capabilities = caps
	}
	if value := os.Getenv("SAFER_ACTION"); value != "" {
		cfg.action = core.Action(value)
	}
	return nil
}

func capabilitiesFromModeValue(value string) (core.Capabilities, error) {
	mode, err := core.NormalizeMode(core.Mode(value))
	if err != nil {
		return core.Capabilities{}, err
	}
	switch mode {
	case core.ModeNondestructive:
		return core.Capabilities{DataWrite: true, EnvEphemeral: true, EnvPersistent: true}, nil
	case core.ModeCareful, core.ModeReadonly:
		return core.Capabilities{}, nil
	default:
		return core.Capabilities{}, nil
	}
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "y", "yes", "on":
		return true, nil
	case "0", "f", "false", "n", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean, got %q", value)
	}
}

func writeAlert(w io.Writer, cfg config, command []string, findings []core.Finding) {
	label := "blocked"
	if cfg.action == core.ActionWarn {
		label = "warning"
	}

	fmt.Fprintf(w, "safer: command requires user attention (%s)\n", label)
	fmt.Fprintf(w, "capabilities: %s\n", displayCapabilities(cfg.capabilities))
	fmt.Fprintf(w, "action: %s\n", cfg.action)
	fmt.Fprintf(w, "command: %s\n", displayCommand(command))
	fmt.Fprintln(w, "findings:")
	for _, finding := range findings {
		prefix := finding.Source
		if finding.Risk != "" {
			prefix += " [" + string(finding.Risk) + "]"
		}
		if finding.Detail == "" {
			fmt.Fprintf(w, "- %s: %s\n", prefix, finding.Reason)
			continue
		}
		fmt.Fprintf(w, "- %s: %s (%s)\n", prefix, finding.Reason, finding.Detail)
	}
	fmt.Fprintln(w, "instruction: bring this to the user's attention. Do not retry, rephrase, or bypass this command without explicit user approval.")
}

func displayCapabilities(caps core.Capabilities) string {
	var names []string
	if caps.DataWrite {
		names = append(names, "data-write")
	}
	if caps.DataDelete {
		names = append(names, "data-delete")
	}
	if caps.EnvEphemeral {
		names = append(names, "env-ephemeral")
	}
	if caps.EnvPersistent {
		names = append(names, "env-persistent")
	}
	if caps.AllowUnknown {
		names = append(names, "allow-unknown")
	}
	if len(names) == 0 {
		return "read-only"
	}
	return strings.Join(names, ", ")
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

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}
