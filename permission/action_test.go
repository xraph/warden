package permission

import (
	"errors"
	"testing"
)

func TestCheckActionRefusesAColon(t *testing.T) {
	for _, action := range []string{"role:manage", ":", "read:", ":read", "a:b:c"} {
		err := CheckAction(action)
		var ce *ActionColonError
		if !errors.As(err, &ce) {
			t.Errorf("CheckAction(%q) = %v, want an *ActionColonError", action, err)
			continue
		}
		if ce.Action != action {
			t.Errorf("CheckAction(%q) names action %q", action, ce.Action)
		}
		want := `action "` + action + `" contains ':': the engine joins resource and action with ':', so an action may not contain one`
		if err.Error() != want {
			t.Errorf("CheckAction(%q) message\n got: %s\nwant: %s", action, err, want)
		}
	}
}

func TestCheckActionAcceptsOrdinaryActionsAndTheWildcard(t *testing.T) {
	for _, action := range []string{"read", "manage", "read_audit", "*", "doc.read", "write-all"} {
		if err := CheckAction(action); err != nil {
			t.Errorf("CheckAction(%q) = %v, want nil", action, err)
		}
	}
}
