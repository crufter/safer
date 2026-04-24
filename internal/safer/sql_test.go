package safer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSQLNondestructiveAllowsSelect(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "psql",
		Args: []string{"-c", "SELECT * FROM users"},
		Mode: ModeNondestructive,
	})
	requireNoFindings(t, findings)
}

func TestSQLNondestructiveBlocksDeleteEvenWithWhere(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "psql",
		Args: []string{"-c", "DELETE FROM users WHERE id = 1"},
		Mode: ModeNondestructive,
	})
	requireFinding(t, findings, "DELETE requires user attention")
}

func TestSQLReadonlyBlocksInsert(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "mysql",
		Args: []string{"--execute=INSERT INTO users(id) VALUES (1)"},
		Mode: ModeReadonly,
	})
	requireFinding(t, findings, "SQL statement changes database state")
}

func TestSQLNondestructiveAllowsInsert(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "psql",
		Args: []string{"-c", "INSERT INTO users(id) VALUES (1)"},
		Mode: ModeNondestructive,
	})
	requireNoFindings(t, findings)
}

func TestSQLCarefulBlocksInsert(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "psql",
		Args: []string{"-c", "INSERT INTO users(id) VALUES (1)"},
		Mode: ModeCareful,
	})
	requireFinding(t, findings, "SQL statement changes database state")
}

func TestSQLInsertRequiresDataWrite(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "psql",
		Args: []string{"-c", "INSERT INTO users(id) VALUES (1)"},
	})
	requireFinding(t, findings, "SQL statement changes database state")
	requireRisk(t, findings, RiskDataWrite)

	findings = CheckCommand(CheckRequest{
		Tool:         "psql",
		Args:         []string{"-c", "INSERT INTO users(id) VALUES (1)"},
		Capabilities: Capabilities{DataWrite: true},
	})
	requireNoFindings(t, findings)
}

func TestSQLDeleteRequiresDataDelete(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "psql",
		Args: []string{"-c", "DELETE FROM users WHERE id = 1"},
	})
	requireFinding(t, findings, "DELETE requires user attention")
	requireRisk(t, findings, RiskDataDelete)

	findings = CheckCommand(CheckRequest{
		Tool:         "psql",
		Args:         []string{"-c", "DELETE FROM users WHERE id = 1"},
		Capabilities: Capabilities{DataDelete: true},
	})
	requireNoFindings(t, findings)
}

func TestSQLScannerIgnoresCommentsAndStrings(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "psql",
		Args: []string{"-c", "SELECT 'delete from users'; -- DROP TABLE users"},
		Mode: ModeNondestructive,
	})
	requireNoFindings(t, findings)
}

func TestSQLFileIsInspected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cleanup.sql")
	if err := os.WriteFile(path, []byte("TRUNCATE TABLE events;"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckCommand(CheckRequest{
		Tool:    "psql",
		Args:    []string{"-f", "cleanup.sql"},
		Mode:    ModeNondestructive,
		WorkDir: dir,
	})
	requireFinding(t, findings, "TRUNCATE requires user attention")
}

func TestSQLiteDatabaseNameIsNotTreatedAsSQL(t *testing.T) {
	findings := CheckCommand(CheckRequest{
		Tool: "sqlite3",
		Args: []string{"drop.db", "SELECT 1"},
		Mode: ModeNondestructive,
	})
	requireNoFindings(t, findings)
}
