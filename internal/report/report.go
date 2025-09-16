package report

import (
	"sort"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/skpr/trivy-operator-report/internal/sorter"
)

type Report struct {
	ClusterConfigAudits     []*v1alpha1.ClusterConfigAuditReport
	ClusterInfraAssessments []*v1alpha1.ClusterInfraAssessmentReport
	ClusterRbacAssessments  []*v1alpha1.ClusterRbacAssessmentReport
	ClusterVulnerabilities  []*v1alpha1.ClusterVulnerabilityReport
	ConfigAudits            []*v1alpha1.ConfigAuditReport
	ExposedSecrets          []*v1alpha1.ExposedSecretReport
	InfraAssessments        []*v1alpha1.InfraAssessmentReport
	RbacAssessments         []*v1alpha1.RbacAssessmentReport
	Vulnerabilities         []*v1alpha1.VulnerabilityReport
}

func NewReport() Report {
	return Report{
		ClusterConfigAudits:     []*v1alpha1.ClusterConfigAuditReport{},
		ClusterInfraAssessments: []*v1alpha1.ClusterInfraAssessmentReport{},
		ClusterRbacAssessments:  []*v1alpha1.ClusterRbacAssessmentReport{},
		ClusterVulnerabilities:  []*v1alpha1.ClusterVulnerabilityReport{},
		ConfigAudits:            []*v1alpha1.ConfigAuditReport{},
		ExposedSecrets:          []*v1alpha1.ExposedSecretReport{},
		InfraAssessments:        []*v1alpha1.InfraAssessmentReport{},
		RbacAssessments:         []*v1alpha1.RbacAssessmentReport{},
		Vulnerabilities:         []*v1alpha1.VulnerabilityReport{},
	}
}

func (r *Report) IsEmpty() bool {
	if len(r.ClusterConfigAudits) != 0 {
		return false
	}
	if len(r.ClusterInfraAssessments) != 0 {
		return false
	}
	if len(r.ClusterRbacAssessments) != 0 {
		return false
	}
	if len(r.ClusterVulnerabilities) != 0 {
		return false
	}
	if len(r.ConfigAudits) != 0 {
		return false
	}
	if len(r.ExposedSecrets) != 0 {
		return false
	}
	if len(r.InfraAssessments) != 0 {
		return false
	}
	if len(r.RbacAssessments) != 0 {
		return false
	}
	if len(r.Vulnerabilities) != 0 {
		return false
	}
	return true
}

func (r *Report) AddClusterConfigAuditReport(report v1alpha1.ClusterConfigAuditReport) {
	if len(report.Report.Checks) == 0 {
		return
	}
	sort.Sort(sorter.CheckSorter(report.Report.Checks))
	r.ClusterConfigAudits = append(r.ClusterConfigAudits, &report)
}

func (r *Report) AddClusterInfraAssessmentReport(report v1alpha1.ClusterInfraAssessmentReport) {
	if len(report.Report.Checks) == 0 {
		return
	}
	sort.Sort(sorter.CheckSorter(report.Report.Checks))
	r.ClusterInfraAssessments = append(r.ClusterInfraAssessments, &report)
}

func (r *Report) AddClusterRbacAssessmentReport(report v1alpha1.ClusterRbacAssessmentReport) {
	if len(report.Report.Checks) == 0 {
		return
	}
	sort.Sort(sorter.CheckSorter(report.Report.Checks))
	r.ClusterRbacAssessments = append(r.ClusterRbacAssessments, &report)
}

func (r *Report) AddClusterVulnerabilityReport(report v1alpha1.ClusterVulnerabilityReport) {
	if len(report.Report.Vulnerabilities) == 0 {
		return
	}
	sort.Sort(sorter.VulnerabilitySorter(report.Report.Vulnerabilities))
	r.ClusterVulnerabilities = append(r.ClusterVulnerabilities, &report)
}

func (r *Report) AddConfigAuditReport(report v1alpha1.ConfigAuditReport) {
	if len(report.Report.Checks) == 0 {
		return
	}
	sort.Sort(sorter.CheckSorter(report.Report.Checks))
	r.ConfigAudits = append(r.ConfigAudits, &report)
}

func (r *Report) AddExposedSecretReport(report v1alpha1.ExposedSecretReport) {
	if len(report.Report.Secrets) == 0 {
		return
	}
	sort.Sort(sorter.SecretSorter(report.Report.Secrets))
	r.ExposedSecrets = append(r.ExposedSecrets, &report)
}

func (r *Report) AddInfraAssessmentReport(report v1alpha1.InfraAssessmentReport) {
	if len(report.Report.Checks) == 0 {
		return
	}
	sort.Sort(sorter.CheckSorter(report.Report.Checks))
	r.InfraAssessments = append(r.InfraAssessments, &report)
}

func (r *Report) AddRbacAssessmentReport(report v1alpha1.RbacAssessmentReport) {
	if len(report.Report.Checks) == 0 {
		return
	}
	sort.Sort(sorter.CheckSorter(report.Report.Checks))
	r.RbacAssessments = append(r.RbacAssessments, &report)
}

func (r *Report) AddVulnerabilityReport(report v1alpha1.VulnerabilityReport) {
	if len(report.Report.Vulnerabilities) == 0 {
		return
	}
	sort.Sort(sorter.VulnerabilitySorter(report.Report.Vulnerabilities))
	r.Vulnerabilities = append(r.Vulnerabilities, &report)
}
