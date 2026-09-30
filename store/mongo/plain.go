package mongo

import (
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/warden/policy"
)

// plainValue turns a value decoded by the mongo driver into plain Go types,
// recursively, so the engine sees what every other backend hands it.
//
// A condition value is stored as an `any`, and the driver decodes into named
// driver types: a BSON array becomes bson.A, an embedded document bson.D, and
// a datetime bson.DateTime. The engine's evaluator switches on exact types
// (`case []any` in inSlice and ipInCIDR, `time.Time` in parseTime), and a
// named type matches none of them. Without this a `not_in` list on a deny is
// "not a list", so the deny hits everyone; an `in` on an allow never grants; a
// list `ip_in_cidr` never matches; a Go-written time is "not a time".
//
// Numbers are left as the driver decodes them (int32, int64, float64): the
// evaluator's toFloat64 accepts each.
func plainValue(v any) any {
	switch x := v.(type) {
	case bson.A:
		return plainSlice([]any(x))
	case []any:
		return plainSlice(x)
	case bson.D:
		out := make(map[string]any, len(x))
		for _, e := range x {
			out[e.Key] = plainValue(e.Value)
		}
		return out
	case bson.M:
		return plainMap(map[string]any(x))
	case map[string]any:
		return plainMap(x)
	case bson.DateTime:
		return x.Time().UTC()
	}
	return v
}

func plainSlice(in []any) []any {
	out := make([]any, len(in))
	for i, item := range in {
		out[i] = plainValue(item)
	}
	return out
}

// plainMap normalises every value of m. A nil map stays nil.
func plainMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = plainValue(v)
	}
	return out
}

// plainConditions returns conds with every Value normalised. The input is not
// modified.
func plainConditions(conds []policy.Condition) []policy.Condition {
	if conds == nil {
		return nil
	}
	out := make([]policy.Condition, len(conds))
	for i, c := range conds {
		c.Value = plainValue(c.Value)
		out[i] = c
	}
	return out
}
