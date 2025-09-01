package report

import (
	"sort"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/skpr/trivy-operator-report/internal/sorter"
)

type Report struct {
	ClusterConfigAudits    []*v1alpha1.ClusterConfigAuditReport
	ConfigAudits           []*v1alpha1.ConfigAuditReport
	ClusterVulnerabilities []*v1alpha1.ClusterVulnerabilityReport
	Vulnerabilities        []*v1alpha1.VulnerabilityReport
}

func NewReport() Report {
	return Report{
		ClusterConfigAudits:    []*v1alpha1.ClusterConfigAuditReport{},
		ConfigAudits:           []*v1alpha1.ConfigAuditReport{},
		ClusterVulnerabilities: []*v1alpha1.ClusterVulnerabilityReport{},
		Vulnerabilities:        []*v1alpha1.VulnerabilityReport{},
	}
}

func (r *Report) AppendClusterConfigAuditReports(reports v1alpha1.ClusterConfigAuditReportList) {
	for _, configAuditReport := range reports.Items {
		if len(configAuditReport.Report.Checks) == 0 {
			continue
		}
		sort.Sort(sorter.CheckSorter(configAuditReport.Report.Checks))
		r.ClusterConfigAudits = append(r.ClusterConfigAudits, &configAuditReport)
	}
}

func (r *Report) AppendConfigAuditReports(reports v1alpha1.ConfigAuditReportList) {
	for _, configAuditReport := range reports.Items {
		if len(configAuditReport.Report.Checks) == 0 {
			continue
		}
		sort.Sort(sorter.CheckSorter(configAuditReport.Report.Checks))
		r.ConfigAudits = append(r.ConfigAudits, &configAuditReport)
	}
}

func (r *Report) AppendClusterVulnerabilityReports(reports v1alpha1.ClusterVulnerabilityReportList) {
	for _, vulnerabilityReport := range reports.Items {
		if len(vulnerabilityReport.Report.Vulnerabilities) == 0 {
			continue
		}
		sort.Sort(sorter.VulnerabilitySorter(vulnerabilityReport.Report.Vulnerabilities))
		r.ClusterVulnerabilities = append(r.ClusterVulnerabilities, &vulnerabilityReport)
	}
}

func (r *Report) AppendVulnerabilityReports(reports v1alpha1.VulnerabilityReportList) {
	for _, vulnerabilityReport := range reports.Items {
		if len(vulnerabilityReport.Report.Vulnerabilities) == 0 {
			continue
		}
		sort.Sort(sorter.VulnerabilitySorter(vulnerabilityReport.Report.Vulnerabilities))
		r.Vulnerabilities = append(r.Vulnerabilities, &vulnerabilityReport)
	}
}
