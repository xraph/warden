package dsl

import (
	"fmt"
	"strings"
)

// Warnings reports source that parses and resolves but that an apply may
// refuse, depending on what the store holds. They are warnings and not
// errors because the store decides: `warden lint` and the LSP read no
// store.
//
// Today that is a permission whose action contains ':'. The apply refuses
// it (permission.CheckAction) unless the store already holds that
// permission with exactly the declared resource and action, which keeps a
// permission stored before the rule applying cleanly.
func Warnings(prog *Program) []*Diagnostic {
	if prog == nil {
		return nil
	}
	var out []*Diagnostic
	for _, p := range prog.Permissions {
		if !strings.Contains(p.Action, ":") {
			continue
		}
		out = append(out, &Diagnostic{Pos: p.Pos, Msg: fmt.Sprintf(
			"permission %q has action %q, which contains ':'; the engine joins resource and action with ':', so apply refuses it unless the store already holds this permission with exactly this resource and action",
			p.Name, p.Action)})
	}
	return out
}
