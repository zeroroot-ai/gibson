package graphrag

import "fmt"

// queryNodesSafe mirrors QueryNodes' MATCH/WHERE/RETURN construction using
// only the trusted combinators. No `want` comment: the analyzer must stay
// silent on legitimate cypherf-built Cypher.
func queryNodesSafe(nodeType, key string, limit int) string {
	match := cypherf("MATCH (n:%s)", labelExpr([]string{nodeType}))
	where := cypherf("n.%s = $p0", sanitizeIdentifier(key))
	cypher := cypherf("%s WHERE %s RETURN n LIMIT %s", match, where, intFrag(limit))
	return string(cypher)
}

// staticFrag shows a literal-constant conversion is allowed anywhere, not
// just inside a trusted constructor: it cannot carry caller input.
func staticFrag() cypherFrag {
	return cypherFrag("a.id = $from")
}

// safeConcat shows that concatenating a Cypher-shaped literal with a value
// that is ALREADY cypherFrag-typed (labelExpr's return) is not flagged: the
// result is exactly as safe as using cypherf, just spelled with `+`.
func safeConcat(nodeType string) cypherFrag {
	return "MATCH (n:" + labelExpr([]string{nodeType}) + ")"
}

// nonCypherSprintf shows an ordinary fmt.Sprintf with no Cypher keyword in
// its format string is never flagged — error messages remain unrestricted.
func nonCypherSprintf(id string) string {
	return fmt.Sprintf("invalid node: %s", id)
}

// lowercaseProseIsFine shows the keyword match is whole-word and
// case-sensitive: ordinary English prose using "return" or "match" in lower
// case must not be mistaken for Cypher.
func lowercaseProseIsFine(name string) string {
	return fmt.Sprintf("did not match or return a result for %s", name)
}
