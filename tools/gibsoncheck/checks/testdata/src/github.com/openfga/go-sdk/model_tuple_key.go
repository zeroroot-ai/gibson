// Package openfga is an analyzer-fixture stub of the real
// github.com/openfga/go-sdk package. It carries only the tuple-key shapes
// the tenantrolewrite guard's type-identity match needs.
package openfga

// TupleKey mirrors the real SDK's tuple-key shape. client.ClientTupleKey is
// a type alias for this in the real SDK.
type TupleKey struct {
	User     string
	Relation string
	Object   string
}

// TupleKeyWithoutCondition mirrors the real SDK's shape.
// client.ClientTupleKeyWithoutCondition is a type alias for this.
type TupleKeyWithoutCondition struct {
	User     string
	Relation string
	Object   string
}
