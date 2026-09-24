package projects

import "time"

// ModulesConfig defines which operational domains are enabled for a project.
type ModulesConfig struct {
	Lighting bool `json:"lighting"`
	Audio    bool `json:"audio"`
	Stage    bool `json:"stage"`
}

// Project is the CouchDB representation of a project.
type Project struct {
	ID            string        `json:"_id"`
	Rev           string        `json:"_rev,omitempty"`
	Type          string        `json:"type"`
	Name          string        `json:"name"`
	Venue         string        `json:"venue"`
	StartDate     string        `json:"start_date"`
	EndDate       string        `json:"end_date"`
	ModulesConfig ModulesConfig `json:"modules_config"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

// PublicProject is returned by the HTTP API without CouchDB metadata.
type PublicProject struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Venue         string        `json:"venue"`
	StartDate     string        `json:"start_date"`
	EndDate       string        `json:"end_date"`
	ModulesConfig ModulesConfig `json:"modules_config"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

// CreateInput is the payload accepted when creating a project.
type CreateInput struct {
	Name          string         `json:"name"`
	Venue         string         `json:"venue"`
	StartDate     string         `json:"start_date"`
	EndDate       string         `json:"end_date"`
	ModulesConfig *ModulesConfig `json:"modules_config,omitempty"`
}

// UpdateInput contains the fields that can be changed on a project.
type UpdateInput struct {
	Name          *string        `json:"name,omitempty"`
	Venue         *string        `json:"venue,omitempty"`
	StartDate     *string        `json:"start_date,omitempty"`
	EndDate       *string        `json:"end_date,omitempty"`
	ModulesConfig *ModulesConfig `json:"modules_config,omitempty"`
}

func toPublic(project *Project) *PublicProject {
	return &PublicProject{
		ID:            project.ID,
		Name:          project.Name,
		Venue:         project.Venue,
		StartDate:     project.StartDate,
		EndDate:       project.EndDate,
		ModulesConfig: project.ModulesConfig,
		CreatedAt:     project.CreatedAt,
		UpdatedAt:     project.UpdatedAt,
	}
}

func toPublicSlice(projects []Project) []PublicProject {
	result := make([]PublicProject, 0, len(projects))
	for i := range projects {
		result = append(result, *toPublic(&projects[i]))
	}
	return result
}
