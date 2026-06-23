package reembed

import "testing"

func TestStrip(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"gibson:vector:abc", "abc"},
		{"gibson:vector:tenant_42:abc", "tenant_42:abc"},
		{"gibson:vector:", "gibson:vector:"}, // no ID after prefix: returned unchanged
		{"unprefixed", "unprefixed"},
		{"", ""},
	}
	for _, c := range cases {
		if got := strip(c.in); got != c.want {
			t.Fatalf("strip(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
