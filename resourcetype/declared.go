package resourcetype

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/wardenerr"
)

// NameGetter is the one read the declaration check needs. Store satisfies
// it, and so does any view that answers for resource types as a pending
// write would leave them (the DSL applier uses one).
type NameGetter interface {
	GetResourceTypeByName(ctx context.Context, tenantID, namespacePath, name string) (*ResourceType, error)
}

// Governing returns the resource type named name that governs namespacePath,
// and the namespace it sits in. It is the evaluator's rule
// (dsl/engine_evaluator.go findResourceType): the nearest namespace up the
// ancestor chain, the path itself first and the tenant root last, that
// holds a resource type of that name. A sibling's or a descendant's never
// governs. It returns nil when no namespace in the chain holds one.
//
// A not-found answer moves on to the next ancestor. Any other read error is
// returned: a write guard that cannot read the schema must not let the
// write through. The evaluator skips such errors instead, which only ever
// denies.
func Governing(ctx context.Context, s NameGetter, tenantID, namespacePath, name string) (*ResourceType, string, error) {
	for _, ns := range ancestorNamespaces(namespacePath) {
		rt, err := s.GetResourceTypeByName(ctx, tenantID, ns, name)
		if err != nil {
			if errors.Is(err, wardenerr.ErrNotFound) {
				continue
			}
			return nil, "", fmt.Errorf("warden: read resource type %q in namespace %q: %w", name, ns, err)
		}
		if rt != nil {
			return rt, ns, nil
		}
	}
	return nil, "", nil
}

// ancestorNamespaces is warden.AncestorNamespaces, which this package
// cannot import (the root package imports the store, which imports this
// one). dsl's parity test holds the two to the same answer.
func ancestorNamespaces(path string) []string {
	if path == "" {
		return []string{""}
	}
	segments := strings.Split(path, "/")
	out := make([]string, 0, len(segments)+1)
	for i := len(segments); i > 0; i-- {
		out = append(out, strings.Join(segments[:i], "/"))
	}
	return append(out, "")
}

// SubjectSpec is how a tuple's subject is spelled in allowed_subjects: the
// subject type, plus "#" and the subject relation when the tuple has one.
// It is the spelling the DSL applier stores ("group#member").
func SubjectSpec(subjectType, subjectRelation string) string {
	if subjectRelation == "" {
		return subjectType
	}
	return subjectType + "#" + subjectRelation
}

// SubjectAllowed reports whether a subject is one allowed entries admit.
// An entry is either a bare type ("user"), which admits a subject of that
// type with no subject relation, or a subject set ("group#member"), which
// admits that type with that subject relation only. So "group" does not
// admit group:eng#member, and "group#member" does not admit group:eng. The
// DSL has no wildcard: a quoted name such as "user:*" is a literal type
// name and matches only a subject of that literal type. An empty list
// admits nothing.
func SubjectAllowed(allowed []string, subjectType, subjectRelation string) bool {
	spec := SubjectSpec(subjectType, subjectRelation)
	for _, a := range allowed {
		if a == spec {
			return true
		}
	}
	return false
}

// UndeclaredTupleError is the refusal CheckTupleDeclared returns: the
// governing resource type does not declare the tuple's relation, or that
// relation does not allow the tuple's subject.
type UndeclaredTupleError struct {
	Tuple relation.Tuple
	// ResourceType and Namespace name the governing resource type.
	ResourceType string
	Namespace    string
	// RelationDeclared is false when the resource type has no relation of
	// the tuple's name, true when it has one that does not allow the
	// subject.
	RelationDeclared bool
	// Declared lists the resource type's relations when RelationDeclared
	// is false, and the relation's allowed subjects when it is true.
	Declared []string
}

func (e *UndeclaredTupleError) Error() string {
	t := e.Tuple
	head := fmt.Sprintf("tuple %s:%s#%s@%s:%s in %s is refused: ",
		t.ObjectType, t.ObjectID, t.Relation,
		t.SubjectType, subjectSpecID(t.SubjectID, t.SubjectRelation),
		namespacePhrase(t.NamespacePath))
	rt := fmt.Sprintf("resource type %q in %s", e.ResourceType, namespacePhrase(e.Namespace))
	if !e.RelationDeclared {
		if len(e.Declared) == 0 {
			return head + fmt.Sprintf("%s declares no relation %q (it declares no relations)", rt, t.Relation)
		}
		return head + fmt.Sprintf("%s declares no relation %q (its relations are %s)", rt, t.Relation, quotedList(e.Declared))
	}
	spec := SubjectSpec(t.SubjectType, t.SubjectRelation)
	if len(e.Declared) == 0 {
		return head + fmt.Sprintf("relation %q of %s allows no subject type, so it cannot hold %q", t.Relation, rt, spec)
	}
	return head + fmt.Sprintf("relation %q of %s allows subjects %s, not %q", t.Relation, rt, quotedList(e.Declared), spec)
}

// subjectSpecID spells a subject's id with its subject relation, the way a
// tuple is written: "eng#member" for group:eng#member.
func subjectSpecID(subjectID, subjectRelation string) string {
	if subjectRelation == "" {
		return subjectID
	}
	return subjectID + "#" + subjectRelation
}

func namespacePhrase(ns string) string {
	if ns == "" {
		return "the tenant root"
	}
	return fmt.Sprintf("namespace %q", ns)
}

func quotedList(in []string) string {
	parts := make([]string, len(in))
	for i, s := range in {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(parts, ", ")
}

// CheckTupleDeclared refuses a tuple the resource type governing its object
// type does not declare. The governing resource type is the one Governing
// finds for t.ObjectType from t.NamespacePath. When there is none, the
// object type is undeclared and the tuple is not checked. When there is
// one, it must declare t.Relation, and that relation's allowed subjects
// must admit the tuple's subject (SubjectAllowed). A refusal is an
// *UndeclaredTupleError.
//
// It checks a write. Tuples already stored are not read, and the evaluator
// does not call it.
func CheckTupleDeclared(ctx context.Context, s NameGetter, t *relation.Tuple) error {
	rt, ns, err := Governing(ctx, s, t.TenantID, t.NamespacePath, t.ObjectType)
	if err != nil || rt == nil {
		return err
	}
	refusal := &UndeclaredTupleError{Tuple: *t, ResourceType: rt.Name, Namespace: ns}
	for _, rel := range rt.Relations {
		if rel.Name != t.Relation {
			continue
		}
		if SubjectAllowed(rel.AllowedSubjects, t.SubjectType, t.SubjectRelation) {
			return nil
		}
		refusal.RelationDeclared = true
		refusal.Declared = append([]string(nil), rel.AllowedSubjects...)
		return refusal
	}
	for _, rel := range rt.Relations {
		refusal.Declared = append(refusal.Declared, rel.Name)
	}
	return refusal
}
