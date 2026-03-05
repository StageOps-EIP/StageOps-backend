package auth

// Role constants represent every recognized role in the system.
const (
	RoleRG      = "rg"      // Régisseur Général — full access
	RoleLumiere = "lumiere" // Technicien lumière
	RoleSon     = "son"     // Technicien son
	RolePlateau = "plateau" // Technicien plateau
)

// DefaultRole is assigned to newly registered users until an RG promotes them.
const DefaultRole = RolePlateau

// knownRoles maps each valid role name to true for O(1) lookup.
var knownRoles = map[string]bool{
	RoleRG:      true,
	RoleLumiere: true,
	RoleSon:     true,
	RolePlateau: true,
}

// IsValidRole reports whether r is a recognized role string.
func IsValidRole(r string) bool {
	return knownRoles[r]
}
