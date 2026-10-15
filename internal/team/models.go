package team

import "errors"

var ErrNotFound = errors.New("team member not found")

type doc struct {
	ID          string   `json:"_id"`
	Rev         string   `json:"_rev,omitempty"`
	Type        string   `json:"type"`
	TheatreID   string   `json:"theatre_id"`
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Avatar      string   `json:"avatar,omitempty"`
	Email       string   `json:"email"`
	Phone       string   `json:"phone,omitempty"`
	Permissions []string `json:"permissions"`
}

type Member struct {
	ID          string   `json:"id"`
	TheatreID   string   `json:"theatre_id"`
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Avatar      string   `json:"avatar,omitempty"`
	Email       string   `json:"email"`
	Phone       string   `json:"phone,omitempty"`
	Permissions []string `json:"permissions"`
}

type Input struct {
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Avatar      string   `json:"avatar"`
	Email       string   `json:"email"`
	Phone       string   `json:"phone"`
	Permissions []string `json:"permissions"`
}

type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

func toPublic(d *doc) *Member {
	return &Member{
		ID:          d.ID,
		TheatreID:   d.TheatreID,
		Name:        d.Name,
		Role:        d.Role,
		Avatar:      d.Avatar,
		Email:       d.Email,
		Phone:       d.Phone,
		Permissions: nilToEmpty(d.Permissions),
	}
}

func toPublicSlice(docs []doc) []Member {
	out := make([]Member, len(docs))
	for i := range docs {
		out[i] = *toPublic(&docs[i])
	}
	return out
}

func nilToEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
