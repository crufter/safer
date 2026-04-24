package safer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/crufter/safer/internal/safer"
)

func TestAlertTellsAgentToBringItToUser(t *testing.T) {
	var buf bytes.Buffer
	writeAlert(&buf, config{capabilities: core.Capabilities{}, action: core.ActionBlock}, []string{"psql", "-c", "DELETE FROM users"}, []core.Finding{{
		Source: "-c",
		Reason: "DELETE requires user attention",
		Detail: "DELETE",
	}})

	got := buf.String()
	if !strings.Contains(got, "bring this to the user's attention") {
		t.Fatalf("expected user-attention instruction, got:\n%s", got)
	}
	if !strings.Contains(got, "Do not retry") {
		t.Fatalf("expected retry instruction, got:\n%s", got)
	}
}

func TestHelpDocumentsCapabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--help"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--help) = %d, stderr:\n%s", code, stderr.String())
	}

	got := stdout.String()
	for _, want := range []string{"Capabilities:", "--data-write", "--data-delete", "--env-ephemeral", "--env-persistent", "--allow-unknown", "--dry-run"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected help to contain %q, got:\n%s", want, got)
		}
	}
}

func TestDefaultReadOnlyBlocksDataWrites(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--dry-run", "npm", "install"}, strings.NewReader(""), &stdout, &stderr)
	if code != exitBlocked {
		t.Fatalf("Execute(default npm install) = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "capabilities: read-only") {
		t.Fatalf("expected default capabilities to be read-only, got:\n%s", stderr.String())
	}
}

func TestDataWriteFlagAllowsDataWrites(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--data-write", "--dry-run", "npm", "install"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--data-write npm install) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestDataWriteShortAliasAllowsDataWrites(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--dw", "--dry-run", "git", "commit", "-m", "change"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--dw git commit) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestDataDeleteFlagAllowsDeletesButNotWrites(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--data-delete", "--dry-run", "rm", "tmp.txt"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--data-delete rm) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"--data-delete", "--dry-run", "npm", "install"}, strings.NewReader(""), &stdout, &stderr)
	if code != exitBlocked {
		t.Fatalf("Execute(--data-delete npm install) = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout.String(), stderr.String())
	}
}

func TestDataDeleteShortAliasAllowsDeletes(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--dd", "--dry-run", "rm", "tmp.txt"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--dd rm) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestEnvCapabilityFlagsAreIndependent(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--env-ephemeral", "--dry-run", "kubectl", "rollout", "restart", "deployment/api"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--env-ephemeral kubectl restart) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"--env-ephemeral", "--dry-run", "terraform", "apply"}, strings.NewReader(""), &stdout, &stderr)
	if code != exitBlocked {
		t.Fatalf("Execute(--env-ephemeral terraform apply) = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"--ep", "--dry-run", "terraform", "apply"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--ep terraform apply) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestEnvEphemeralShortAliasAllowsRuntimeMutation(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--ee", "--dry-run", "kubectl", "rollout", "restart", "deployment/api"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--ee kubectl restart) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestDefaultBlocksUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--dry-run", "custom-tool"}, strings.NewReader(""), &stdout, &stderr)
	if code != exitBlocked {
		t.Fatalf("Execute(custom-tool) = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "not known read-only") {
		t.Fatalf("expected unknown warning, got:\n%s", stderr.String())
	}
}

func TestAllowUnknownFlagAllowsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--allow-unknown", "--dry-run", "custom-tool"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--allow-unknown custom-tool) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestSaferrcConfiguresCapabilities(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".saferrc"), []byte("data_write=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--dry-run", "npm", "install"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(with .saferrc data_write=true) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if stderr.String() != "" {
		t.Fatalf("expected data-write capability to allow npm install, got stderr:\n%s", stderr.String())
	}
}

func TestSaferrcWarnsWhenBlocked(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".saferrc"), []byte("action=warn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--dry-run", "npm", "install"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(with .saferrc action=warn) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	got := stderr.String()
	for _, want := range []string{"capabilities: read-only", "action: warn", "changes dependencies"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected stderr to contain %q, got:\n%s", want, got)
		}
	}
}

func TestEnvConfiguresCapabilities(t *testing.T) {
	t.Setenv("SAFER_ENV_PERSISTENT", "true")
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--dry-run", "terraform", "apply"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(SAFER_ENV_PERSISTENT terraform apply) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestCompatibilityNondestructiveAllowsWritesAndEnvButNotDeletes(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Execute([]string{"--nondestructive", "--dry-run", "npm", "install"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--nondestructive npm install) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"--nondestructive", "--dry-run", "terraform", "apply"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Execute(--nondestructive terraform apply) = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"--nondestructive", "--dry-run", "rm", "tmp.txt"}, strings.NewReader(""), &stdout, &stderr)
	if code != exitBlocked {
		t.Fatalf("Execute(--nondestructive rm) = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout.String(), stderr.String())
	}
}
