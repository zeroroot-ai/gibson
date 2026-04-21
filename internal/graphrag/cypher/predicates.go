package cypher

import "fmt"

// TenantPredicate returns a Cypher predicate that scopes a node to a specific tenant parameter.
func TenantPredicate(varName, paramName string) string {
	return fmt.Sprintf("%s.tenant_id = $%s", varName, paramName)
}
