package models

type HTMLData struct {
	FormActions []string
	Comments    []string
	URLs        []string
}

type JSFunction struct {
	Name       string   `json:"name" jsonschema:"description=Function name"`
	Parameters []string `json:"parameters" jsonschema:"description=Function parameters"`
	Context    string   `json:"context" jsonschema:"description=Function context/code snippet"`
	Suspicious bool     `json:"suspicious" jsonschema:"description=Whether function is potentially suspicious"`
	Reason     string   `json:"reason,omitempty" jsonschema:"description=Reason why function is suspicious"`
}
