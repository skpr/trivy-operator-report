package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log"
	"os"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/clientset"
	"github.com/slack-go/slack"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/skpr/trivy-operator-report/internal/report"
)

//go:embed templates/*
var templateFS embed.FS

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

	namespace := pflag.StringP("namespace", "n", "default", "Namespace of the cluster reports.")
	clusterReports := pflag.BoolP("cluster-reports", "c", false, "Whether to include global cluster reports.")
	allNamespaces := pflag.BoolP("all-reports", "A", false, "Whether to get all reports from a cluster.")
	outputFile := pflag.StringP("output-file", "o", "", "File to write results to.")
	slackNotification := pflag.Bool("slack-notification", false, "Write the report to a slack channel.")
	pflag.Parse()

	if allNamespaces != nil && *allNamespaces {
		*namespace = ""
		*clusterReports = true
	}

	document := report.NewReport()

	if clusterReports != nil && *clusterReports {
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
	}

	configAudits, err := client.AquasecurityV1alpha1().ConfigAuditReports(*namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list config audit reports: %w", err)
	}
	document.AppendConfigAuditReports(*configAudits)

	exposedSecrets, err := client.AquasecurityV1alpha1().ExposedSecretReports(*namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list exposed secret reports: %w", err)
	}
	document.AppendExposedSecretReports(*exposedSecrets)

	infraAssessments, err := client.AquasecurityV1alpha1().InfraAssessmentReports(*namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list infra assessment reports: %w", err)
	}
	document.AppendInfraAssessmentReports(*infraAssessments)

	rbacAssesments, err := client.AquasecurityV1alpha1().RbacAssessmentReports(*namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list rbac assessment reports: %w", err)
	}
	document.AppendRbacAssessmentReports(*rbacAssesments)

	reports, err := client.AquasecurityV1alpha1().VulnerabilityReports(*namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list vulnerability reports: %w", err)
	}
	document.AppendVulnerabilityReports(*reports)

	if document.IsEmpty() {
		log.Println("No vulnerability reports found.")
		return nil
	}

	funcMap := template.FuncMap{
		"severity": func(input v1alpha1.Severity) string {
			return string(input)
		},
	}

	tmpl := template.New("base").Funcs(funcMap)

	globs := []string{"*.css", "*.html"}
	for _, glob := range globs {
		tmpl, err = tmpl.ParseFS(templateFS, "templates/"+glob)
		if err != nil {
			return fmt.Errorf("failed to parse %s template: %w", glob, err)
		}
	}

	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "report.html", document)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	if outputFile != nil && *outputFile != "" {
		err := os.WriteFile(*outputFile, buf.Bytes(), 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("successfully generated the report to file: %s\n", *outputFile)
	}

	if *slackNotification {
		slackBotToken := os.Getenv("SLACK_BOT_TOKEN")
		channelID := os.Getenv("SLACK_CHANNEL_ID")
		cluster := os.Getenv("CLUSTER_NAME")
		ctx := context.Background()

		filename := fmt.Sprintf("%s_trivy_report_%s.html", cluster, time.Now().Format(time.RFC3339))

		uploadParams := slack.UploadFileV2Parameters{
			Channel:        channelID,
			Title:          filename,
			InitialComment: "New infrastructure security report for [stack]",
			Content:        buf.String(),
			Filename:       filename,
			FileSize:       buf.Len(),
		}

		client := slack.New(slackBotToken)
		_, err = client.UploadFileV2Context(ctx, uploadParams)
		if err != nil {
			return fmt.Errorf("error uploading file: %v", err)
		}

		fmt.Println("successfully posted report to Slack")
	}

	return nil
}
