package extensions

import "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

func SeverityToInt(s v1alpha1.Severity) int {
	switch s {
	case v1alpha1.SeverityCritical:
		return 4
	case v1alpha1.SeverityHigh:
		return 3
	case v1alpha1.SeverityMedium:
		return 2
	case v1alpha1.SeverityLow:
		return 1
	default:
		return 0
	}
}
