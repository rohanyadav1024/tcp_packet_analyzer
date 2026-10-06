package validation

type Classification string

const (
	Valid         Classification = "VALID"
	Truncated     Classification = "TRUNCATED"
	Malformed     Classification = "MALFORMED"
	Unsupported   Classification = "UNSUPPORTED"
	Inconsistent  Classification = "INCONSISTENT"
)

func Classify(findings []Finding) Classification {
	hasError := false
	hasWarning := false

	for _, finding := range findings {
		switch finding.Severity {
		case Error:
			hasError = true
		case Warning:
			hasWarning = true
		}
	}

	if hasError {
		return Malformed
	}

	if hasWarning {
		return Inconsistent
	}

	return Valid
}