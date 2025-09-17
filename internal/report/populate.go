package report

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/trivy-operator/pkg/clientset"
)

func (r *Report) PopulateReports(client *clientset.Clientset, namespace string, ctx context.Context, opts metav1.ListOptions) error {
	// Only include cluster reports if the namespace is 'ALL'.
	if namespace == "" {
		clusterConfigAudits, err := client.AquasecurityV1alpha1().ClusterConfigAuditReports(namespace).List(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to list cluster config audit reports: %w", err)
		}
		for _, item := range clusterConfigAudits.Items {
			r.AddClusterConfigAuditReport(item)
		}

		clusterInfraAssessments, err := client.AquasecurityV1alpha1().ClusterInfraAssessmentReports(namespace).List(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to list cluster infra assessment reports: %w", err)
		}
		for _, item := range clusterInfraAssessments.Items {
			r.AddClusterInfraAssessmentReport(item)
		}

		clusterRbacAssesments, err := client.AquasecurityV1alpha1().ClusterRbacAssessmentReports(namespace).List(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to list cluster rbac assessment reports: %w", err)
		}
		for _, item := range clusterRbacAssesments.Items {
			r.AddClusterRbacAssessmentReport(item)
		}

		clusterVulnerabilityReports, err := client.AquasecurityV1alpha1().ClusterVulnerabilityReports(namespace).List(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to list cluster vulnerability reports: %w", err)
		}
		for _, item := range clusterVulnerabilityReports.Items {
			r.AddClusterVulnerabilityReport(item)
		}
	}

	configAudits, err := client.AquasecurityV1alpha1().ConfigAuditReports(namespace).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list config audit reports: %w", err)
	}
	for _, item := range configAudits.Items {
		r.AddConfigAuditReport(item)
	}

	exposedSecrets, err := client.AquasecurityV1alpha1().ExposedSecretReports(namespace).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list exposed secret reports: %w", err)
	}
	for _, item := range exposedSecrets.Items {
		r.AddExposedSecretReport(item)
	}

	infraAssessments, err := client.AquasecurityV1alpha1().InfraAssessmentReports(namespace).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list infra assessment reports: %w", err)
	}
	for _, item := range infraAssessments.Items {
		r.AddInfraAssessmentReport(item)
	}

	rbacAssesments, err := client.AquasecurityV1alpha1().RbacAssessmentReports(namespace).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list rbac assessment reports: %w", err)
	}
	for _, item := range rbacAssesments.Items {
		r.AddRbacAssessmentReport(item)
	}

	reports, err := client.AquasecurityV1alpha1().VulnerabilityReports(namespace).List(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list vulnerability reports: %w", err)
	}
	for _, item := range reports.Items {
		r.AddVulnerabilityReport(item)
	}

	return nil
}

func (r *Report) PopulateReportByName(client *clientset.Clientset, name string, namespace string, ctx context.Context, opts metav1.GetOptions) error {
	// Namespace hard-coded to 'ALL' for cluster reports so it can find them by name always. Equivalent to how 'k get clusterrole [name]' ignores any namespace parameters.
	clusterConfigAudit, _ := client.AquasecurityV1alpha1().ClusterConfigAuditReports("").Get(ctx, name, opts)
	if clusterConfigAudit != nil {
		r.AddClusterConfigAuditReport(*clusterConfigAudit)
	}

	clusterInfraAssessment, _ := client.AquasecurityV1alpha1().ClusterInfraAssessmentReports("").Get(ctx, name, opts)
	if clusterInfraAssessment != nil {
		r.AddClusterInfraAssessmentReport(*clusterInfraAssessment)
	}

	clusterRbacAssessment, _ := client.AquasecurityV1alpha1().ClusterRbacAssessmentReports("").Get(ctx, name, opts)
	if clusterRbacAssessment != nil {
		r.AddClusterRbacAssessmentReport(*clusterRbacAssessment)
	}

	clusterVulnerabilityReport, _ := client.AquasecurityV1alpha1().ClusterVulnerabilityReports("").Get(ctx, name, opts)
	if clusterVulnerabilityReport != nil {
		r.AddClusterVulnerabilityReport(*clusterVulnerabilityReport)
	}

	configAudit, _ := client.AquasecurityV1alpha1().ConfigAuditReports(namespace).Get(ctx, name, opts)
	if configAudit != nil {
		r.AddConfigAuditReport(*configAudit)
	}

	exposedSecret, _ := client.AquasecurityV1alpha1().ExposedSecretReports(namespace).Get(ctx, name, opts)
	if exposedSecret != nil {
		r.AddExposedSecretReport(*exposedSecret)
	}

	infraAssessment, _ := client.AquasecurityV1alpha1().InfraAssessmentReports(namespace).Get(ctx, name, opts)
	if infraAssessment != nil {
		r.AddInfraAssessmentReport(*infraAssessment)
	}

	rbacAssesment, _ := client.AquasecurityV1alpha1().RbacAssessmentReports(namespace).Get(ctx, name, opts)
	if rbacAssesment != nil {
		r.AddRbacAssessmentReport(*rbacAssesment)
	}

	report, _ := client.AquasecurityV1alpha1().VulnerabilityReports(namespace).Get(ctx, name, opts)
	if report != nil {
		r.AddVulnerabilityReport(*report)
	}

	return nil
}
