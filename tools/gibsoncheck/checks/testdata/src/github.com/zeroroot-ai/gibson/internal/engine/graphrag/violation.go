package graphrag

import "fmt"

// rawSprintfViolation is the mutation case for the fmt.Sprintf rule: a new
// call site builds Cypher text directly instead of routing the node type
// through sanitizeIdentifier/cypherf. If the analyzer stops flagging this,
// the guard has stopped working.
func rawSprintfViolation(nodeType string) string {
	cypher := fmt.Sprintf("MATCH (n:%s)", nodeType) // want `fmt\.Sprintf builds Cypher-shaped text`
	return cypher
}

// rawConcatViolation is the mutation case for the concatenation rule: the
// exact shape local_provider.go's QueryNodes MATCH clause used before
// cypherf existed, but with a plain string instead of labelExpr's cypherFrag.
func rawConcatViolation(nodeType string) string {
	return "MATCH (n:" + nodeType + ")" // want `string concatenation builds Cypher-shaped text`
}

// unsafeConversionViolation is the mutation case for the conversion rule: a
// naked cypherFrag(...) conversion of caller input, bypassing every
// designated constructor. This is the shape that defeats a "smart
// constructor" type if the type system alone were relied on — Go permits any
// conversion between a named type and its underlying type.
func unsafeConversionViolation(nodeType string) cypherFrag {
	return cypherFrag(nodeType) // want `cypherFrag\(nodeType\) converts a non-constant value`
}
