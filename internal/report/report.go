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

func (r *Report) AppendClusterConfigAuditReports(reports v1alpha1.ClusterConfigAuditReportList) {
	for _, configAuditReport := range reports.Items {
		if len(configAuditReport.Report.Checks) == 0 {
			continue
		}
		sort.Sort(sorter.CheckSorter(configAuditReport.Report.Checks))
		r.ClusterConfigAudits = append(r.ClusterConfigAudits, &configAuditReport)
	}
}

func (r *Report) AppendClusterInfraAssessmentReports(reports v1alpha1.ClusterInfraAssessmentReportList) {
	for _, infraAssessmentReport := range reports.Items {
		if len(infraAssessmentReport.Report.Checks) == 0 {
			continue
		}
		sort.Sort(sorter.CheckSorter(infraAssessmentReport.Report.Checks))
		r.ClusterInfraAssessments = append(r.ClusterInfraAssessments, &infraAssessmentReport)
	}
}

func (r *Report) AppendClusterRbacAssessmentReports(reports v1alpha1.ClusterRbacAssessmentReportList) {
	for _, rbacAssessmentReport := range reports.Items {
		if len(rbacAssessmentReport.Report.Checks) == 0 {
			continue
		}
		sort.Sort(sorter.CheckSorter(rbacAssessmentReport.Report.Checks))
		r.ClusterRbacAssessments = append(r.ClusterRbacAssessments, &rbacAssessmentReport)
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

func (r *Report) AppendConfigAuditReports(reports v1alpha1.ConfigAuditReportList) {
	for _, configAuditReport := range reports.Items {
		if len(configAuditReport.Report.Checks) == 0 {
			continue
		}
		sort.Sort(sorter.CheckSorter(configAuditReport.Report.Checks))
		r.ConfigAudits = append(r.ConfigAudits, &configAuditReport)
	}
}

func (r *Report) AppendExposedSecretReports(reports v1alpha1.ExposedSecretReportList) {
	for _, exposedSecretReport := range reports.Items {
		if len(exposedSecretReport.Report.Secrets) == 0 {
			continue
		}
		sort.Sort(sorter.SecretSorter(exposedSecretReport.Report.Secrets))
		r.ExposedSecrets = append(r.ExposedSecrets, &exposedSecretReport)
	}
}

func (r *Report) AppendInfraAssessmentReports(reports v1alpha1.InfraAssessmentReportList) {
	for _, infraAssessmentReport := range reports.Items {
		if len(infraAssessmentReport.Report.Checks) == 0 {
			continue
		}
		sort.Sort(sorter.CheckSorter(infraAssessmentReport.Report.Checks))
		r.InfraAssessments = append(r.InfraAssessments, &infraAssessmentReport)
	}
}

func (r *Report) AppendRbacAssessmentReports(reports v1alpha1.RbacAssessmentReportList) {
	for _, rbacAssessmentReport := range reports.Items {
		if len(rbacAssessmentReport.Report.Checks) == 0 {
			continue
		}
		sort.Sort(sorter.CheckSorter(rbacAssessmentReport.Report.Checks))
		r.RbacAssessments = append(r.RbacAssessments, &rbacAssessmentReport)
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
