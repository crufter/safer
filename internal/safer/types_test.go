package safer

import "testing"

func TestModeAliases(t *testing.T) {
	tests := map[Mode]Mode{
		"delete":      ModeNondestructive,
		"destructive": ModeNondestructive,
		"write":       ModeCareful,
		"mutating":    ModeCareful,
		"paranoid":    ModeReadonly,
	}

	for input, want := range tests {
		got, err := NormalizeMode(input)
		if err != nil {
			t.Fatalf("NormalizeMode(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeMode(%q) = %q, want %q", input, got, want)
		}
	}
}
