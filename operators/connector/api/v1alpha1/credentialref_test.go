package v1alpha1

import "testing"

// TestCredentialRef_EnvName pins the one rule the daemon and the operator
// share for naming a declared credential's env var (gibson#597).
func TestCredentialRef_EnvName(t *testing.T) {
	cases := []struct {
		ref  CredentialRef
		want string
	}{
		{CredentialRef{Key: "gitlab-token", TargetEnv: "GITLAB_PAT"}, "GITLAB_PAT"},
		{CredentialRef{Key: "gitlab-token"}, "GITLAB_TOKEN"},
		{CredentialRef{Key: "vendor.api.key"}, "VENDOR_API_KEY"},
		{CredentialRef{Key: "a--b__c"}, "A_B_C"},
		{CredentialRef{Key: "2fa-secret"}, "_2FA_SECRET"},
		{CredentialRef{Key: "-trailing-"}, "TRAILING"},
	}
	for _, c := range cases {
		if got := c.ref.EnvName(); got != c.want {
			t.Errorf("EnvName(%q, %q) = %q, want %q", c.ref.Key, c.ref.TargetEnv, got, c.want)
		}
	}
}
