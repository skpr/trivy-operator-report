package sorter

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

	"github.com/skpr/trivy-operator-report/internal/extensions"
)

type CheckSorter []v1alpha1.Check

func (a CheckSorter) Len() int {
	return len(a)
}

func (a CheckSorter) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a CheckSorter) Less(i, j int) bool {
	if a[i].Severity == a[j].Severity {
		return a[i].ID > a[j].ID
	}
	return extensions.SeverityToInt(a[i].Severity) > extensions.SeverityToInt(a[j].Severity)
}
