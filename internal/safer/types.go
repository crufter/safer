package safer

import (
	"fmt"
	"strings"
)

type Mode string

const (
	ModeNondestructive Mode = "nondestructive"
	ModeCareful        Mode = "careful"
	ModeReadonly       Mode = "readonly"
)

type Action string

const (
	ActionBlock Action = "block"
	ActionWarn  Action = "warn"
)

type Risk string

const (
	RiskDataWrite     Risk = "data-write"
	RiskDataDelete    Risk = "data-delete"
	RiskEnvEphemeral  Risk = "env-ephemeral"
	RiskEnvPersistent Risk = "env-persistent"
	RiskUnknown       Risk = "unknown"
)

type Capabilities struct {
	DataWrite     bool
	DataDelete    bool
	EnvEphemeral  bool
	EnvPersistent bool
	AllowUnknown  bool
}

type Finding struct {
	Source string
	Risk   Risk
	Reason string
	Detail string
}

type CheckRequest struct {
	Tool         string
	Args         []string
	Capabilities Capabilities
	Mode         Mode
	WorkDir      string
}

func ValidateMode(mode Mode) error {
	_, err := NormalizeMode(mode)
	return err
}

func NormalizeMode(mode Mode) (Mode, error) {
	switch Mode(strings.ToLower(string(mode))) {
	case "", ModeNondestructive, "delete", "deletes", "destructive":
		return ModeNondestructive, nil
	case ModeCareful, "write", "writes", "mutating", "mutation":
		return ModeCareful, nil
	case ModeReadonly, "read-only", "paranoid":
		return ModeReadonly, nil
	default:
		return "", fmt.Errorf("unknown mode %q", mode)
	}
}

func ValidateAction(action Action) error {
	switch action {
	case ActionBlock, ActionWarn:
		return nil
	default:
		return fmt.Errorf("unknown action %q", action)
	}
}
