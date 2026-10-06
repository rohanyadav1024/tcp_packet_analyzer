package validation

type Severity string

const (
	Info    Severity = "INFO"
	Warning Severity = "WARNING"
	Error   Severity = "ERROR"
)

type Finding struct {
	Layer    string
	Field    string
	Code     string
	Severity Severity
	Message  string
}

func NewFinding(
	layer string,
	field string,
	code string,
	severity Severity,
	message string,
) Finding {
	return Finding{
		Layer:    layer,
		Field:    field,
		Code:     code,
		Severity: severity,
		Message:  message,
	}
}