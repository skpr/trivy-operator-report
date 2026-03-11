package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/clientset"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
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

	reports, err := client.AquasecurityV1alpha1().VulnerabilityReports(metav1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list vulnerability reports: %w", err)
	}

	summaries := make(map[string]v1alpha1.VulnerabilitySummary)

	for _, item := range reports.Items {
		name := fmt.Sprintf("%s:%s", item.Report.Artifact.Repository, item.Report.Artifact.Tag)

		if _, ok := summaries[name]; !ok {
			summaries[name] = item.Report.Summary
		}
	}

	t := table.New(os.Stdout)

	t.SetHeaders("Image", "Critical", "High", "Medium", "Low", "Unknown", "None")

	for name, summary := range summaries {
		t.AddRow(name, fmt.Sprintf("%d", summary.CriticalCount), fmt.Sprintf("%d", summary.HighCount), fmt.Sprintf("%d", summary.MediumCount), fmt.Sprintf("%d", summary.LowCount), fmt.Sprintf("%d", summary.UnknownCount), fmt.Sprintf("%d", summary.NoneCount))
	}

	t.Render()

	return nil
}
