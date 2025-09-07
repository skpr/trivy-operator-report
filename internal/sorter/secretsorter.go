package sorter

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

	"github.com/skpr/trivy-operator-report/internal/extensions"
)

type SecretSorter []v1alpha1.ExposedSecret

func (a SecretSorter) Len() int {
	return len(a)
}

func (a SecretSorter) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a SecretSorter) Less(i, j int) bool {
	if a[i].Severity == a[j].Severity {
		return a[i].RuleID > a[j].RuleID
	}
	return extensions.SeverityToInt(a[i].Severity) > extensions.SeverityToInt(a[j].Severity)
}
