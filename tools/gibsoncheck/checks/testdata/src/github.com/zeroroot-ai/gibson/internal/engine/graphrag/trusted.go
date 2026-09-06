package graphrag

import (
	"fmt"
	"strconv"
	"strings"
)

// sanitizeIdentifier, intFrag, paramFrag, cypherf, joinFrags and labelExpr
// mirror local_provider.go's constructors closely enough to exercise the
// analyzer's trusted-constructor exemption: each converts a non-constant
// value to cypherFrag inside its own body and must NOT be flagged. None of
// these carry a `want` comment — that absence is the assertion.

func sanitizeIdentifier(s string) cypherFrag {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return cypherFrag(b.String())
}

func intFrag(n int) cypherFrag {
	return cypherFrag(strconv.Itoa(n))
}

func paramFrag(prefix string, i int) cypherFrag {
	return cypherFrag(prefix) + intFrag(i)
}

func cypherf(format string, frags ...cypherFrag) cypherFrag {
	args := make([]any, len(frags))
	for i, f := range frags {
		args[i] = string(f)
	}
	return cypherFrag(fmt.Sprintf(format, args...))
}

func joinFrags(frags []cypherFrag, sep string) cypherFrag {
	strs := make([]string, len(frags))
	for i, f := range frags {
		strs[i] = string(f)
	}
	return cypherFrag(strings.Join(strs, sep))
}

func labelExpr(labels []string) cypherFrag {
	clean := make([]cypherFrag, 0, len(labels))
	for _, l := range labels {
		if s := sanitizeIdentifier(l); s != "" {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return cypherFrag("Node")
	}
	return joinFrags(clean, ":")
}
