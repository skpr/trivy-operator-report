package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
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
	allNamespaces := pflag.BoolP("all-reports", "A", false, "Whether to get all reports from a cluster.")
	outputFile := pflag.StringP("output-file", "o", "", "File to write results to.")
	slackNotification := pflag.Bool("slack-notification", false, "Write the report to a slack channel.")
	pflag.Parse()

	if allNamespaces != nil && *allNamespaces {
		*namespace = ""
	}

	var name *string
	args := pflag.Args()
	if len(args) > 1 {
		return fmt.Errorf("you can only pass one report name at a time")
	}
	if len(args) > 0 {
		name = &args[0]
	}

	ctx := context.Background()

	document := report.NewReport()
	if name == nil {
		opts := metav1.ListOptions{}
		err = document.PopulateReports(client, *namespace, ctx, opts)
		if err != nil {
			return err
		}
		if document.IsEmpty() {
			fmt.Println("No vulnerability reports found.")
			return nil
		}
	} else {
		opts := metav1.GetOptions{}
		err = document.PopulateReportByName(client, *name, *namespace, ctx, opts)
		if err != nil {
			return err
		}
		if document.IsEmpty() {
			fmt.Printf("Report \"%s\" not found. If not a cluster level report ensure you include the correct namespace.\n", *name)
			return nil
		}
	}

	funcMap := template.FuncMap{
		"severity": func(input v1alpha1.Severity) string {
			return string(input)
		},
		"numberOfReports": func(report report.Report) int { return report.NumberOfReports() },
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
