package main

import (
	"context"
	"fmt"
	"html/template"
	"os"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/skpr/trivy-operator-report/internal/report"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return fmt.Errorf("failed to build config: %w", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	document := report.NewReport()

	clusterConfigAudits, err := client.AquasecurityV1alpha1().ClusterConfigAuditReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list cluster config audit reports: %w", err)
	}
	document.AppendClusterConfigAuditReports(*clusterConfigAudits)

	clusterInfraAssessments, err := client.AquasecurityV1alpha1().ClusterInfraAssessmentReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list cluster infra assessment reports: %w", err)
	}
	document.AppendClusterInfraAssessmentReports(*clusterInfraAssessments)

	clusterRbacAssesments, err := client.AquasecurityV1alpha1().ClusterRbacAssessmentReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list cluster rbac assessment reports: %w", err)
	}
	document.AppendClusterRbacAssessmentReports(*clusterRbacAssesments)

	clusterReports, err := client.AquasecurityV1alpha1().ClusterVulnerabilityReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list cluster vulnerability reports: %w", err)
	}
	document.AppendClusterVulnerabilityReports(*clusterReports)

	configAudits, err := client.AquasecurityV1alpha1().ConfigAuditReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list config audit reports: %w", err)
	}
	document.AppendConfigAuditReports(*configAudits)

	exposedSecrets, err := client.AquasecurityV1alpha1().ExposedSecretReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list exposed secret reports: %w", err)
	}
	document.AppendExposedSecretReports(*exposedSecrets)

	infraAssessments, err := client.AquasecurityV1alpha1().InfraAssessmentReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list infra assessment reports: %w", err)
	}
	document.AppendInfraAssessmentReports(*infraAssessments)

	rbacAssesments, err := client.AquasecurityV1alpha1().RbacAssessmentReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list rbac assessment reports: %w", err)
	}
	document.AppendRbacAssessmentReports(*rbacAssesments)

	reports, err := client.AquasecurityV1alpha1().VulnerabilityReports("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list vulnerability reports: %w", err)
	}
	document.AppendVulnerabilityReports(*reports)

	funcMap := template.FuncMap{
		"severity": func(input v1alpha1.Severity) string {
			return string(input)
		},
	}

	tmpl := template.New("base").Funcs(funcMap)

	globs := []string{"*.css", "*.html"}
	for _, glob := range globs {
		tmpl, err = tmpl.ParseGlob("templates/" + glob)
		if err != nil {
			return fmt.Errorf("failed to parse %s template: %w", glob, err)
		}
	}

	err = tmpl.ExecuteTemplate(os.Stdout, "report.html", document)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}
