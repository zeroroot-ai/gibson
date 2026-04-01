package keycloak

// RealmConfig contains the parameters for creating a Keycloak realm.
type RealmConfig struct {
	// Name is the unique realm identifier (e.g., "acme-corp").
	Name string

	// DisplayName is the human-readable name shown in the UI.
	DisplayName string

	// Enabled controls whether the realm is active.
	Enabled bool

	// RegistrationAllowed controls self-registration by end users.
	RegistrationAllowed bool

	// LoginTheme sets the theme used for the login page.
	LoginTheme string

	// AccessTokenLifespan is the token lifetime in seconds. Defaults to 300.
	AccessTokenLifespan int

	// SSOSessionMax is the maximum SSO session duration in seconds. Defaults to 36000.
	SSOSessionMax int
}

// RealmRepresentation is the Keycloak realm object returned by the Admin REST API.
type RealmRepresentation struct {
	ID          string `json:"id"`
	Realm       string `json:"realm"`
	DisplayName string `json:"displayName"`
	Enabled     bool   `json:"enabled"`
}

// OIDCClientConfig contains the parameters for creating an OIDC client within a realm.
type OIDCClientConfig struct {
	// ClientID is the OIDC client identifier.
	ClientID string

	// Secret is the client secret for confidential clients.
	Secret string

	// RedirectURIs is the list of permitted redirect URIs.
	RedirectURIs []string

	// WebOrigins is the list of permitted CORS origins.
	WebOrigins []string
}

// UserConfig contains the parameters for creating a user within a realm.
type UserConfig struct {
	// Username is the unique login name.
	Username string

	// Email is the user's email address.
	Email string

	// FirstName is the user's given name.
	FirstName string

	// LastName is the user's family name.
	LastName string

	// Enabled controls whether the user account is active.
	Enabled bool

	// EmailVerified marks the email address as already verified.
	EmailVerified bool

	// Password is the initial password. Optional — no credential is created when empty.
	Password string

	// TemporaryPassword marks the password as temporary, requiring a reset on first login.
	TemporaryPassword bool

	// RequiredActions lists actions the user must complete on next login (e.g., "VERIFY_EMAIL").
	RequiredActions []string

	// RealmRoles lists the realm-level roles to assign to the user.
	RealmRoles []string

	// Groups lists the group names or IDs to add the user to.
	Groups []string

	// Attributes is a map of custom attributes to set on the user.
	Attributes map[string][]string
}

// UserRepresentation is the Keycloak user object returned by the Admin REST API.
type UserRepresentation struct {
	ID               string              `json:"id"`
	Username         string              `json:"username"`
	Email            string              `json:"email"`
	FirstName        string              `json:"firstName"`
	LastName         string              `json:"lastName"`
	Enabled          bool                `json:"enabled"`
	EmailVerified    bool                `json:"emailVerified"`
	CreatedTimestamp int64               `json:"createdTimestamp"`
	Attributes       map[string][]string `json:"attributes,omitempty"`
	RequiredActions  []string            `json:"requiredActions,omitempty"`
}

// ListUsersOpts provides filtering options for listing users in a realm.
type ListUsersOpts struct {
	// Search performs a broad match against username, email, firstName, and lastName.
	Search string

	// Email filters by exact email address.
	Email string

	// First is the index of the first result to return (pagination offset).
	First int

	// Max is the maximum number of results to return. Defaults to 100 when zero.
	Max int
}

// RoleRepresentation is the Keycloak role object returned by the Admin REST API.
type RoleRepresentation struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Composite   bool   `json:"composite"`
}

// GroupRepresentation is the Keycloak group object returned by the Admin REST API.
type GroupRepresentation struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Path       string              `json:"path"`
	Attributes map[string][]string `json:"attributes,omitempty"`
}

// SessionRepresentation is the Keycloak session object returned by the Admin REST API.
type SessionRepresentation struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	UserID     string `json:"userId"`
	IPAddress  string `json:"ipAddress"`
	Start      int64  `json:"start"`
	LastAccess int64  `json:"lastAccess"`
}

// ClientRepresentation is the Keycloak OIDC client object returned by the Admin REST API.
type ClientRepresentation struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
	Protocol string `json:"protocol"`
	Enabled  bool   `json:"enabled"`
	Secret   string `json:"secret,omitempty"`
}

// ProtocolMapperConfig contains the parameters for adding a protocol mapper to an OIDC client.
type ProtocolMapperConfig struct {
	// Name is the display name for this mapper.
	Name string

	// Protocol is the protocol this mapper applies to (e.g., "openid-connect").
	Protocol string

	// ProtocolMapper is the mapper type identifier (e.g., "oidc-hardcoded-claim-mapper").
	ProtocolMapper string

	// Config is the mapper-specific configuration key/value pairs.
	Config map[string]string
}
