package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aquasecurity/table"
	"github.com/aquasecurity/trivy-operator/pkg/clientset"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

type cveEntry struct {
	title  string
	images []string
}

type jsonEntry struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Images []string `json:"images"`
}

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	var asJSON bool
	flag.BoolVar(&asJSON, "json", false, "Output as JSON")
	flag.Parse()

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

	cves := make(map[string]*cveEntry)

	for _, item := range reports.Items {
		namespace := item.Namespace
		image := fmt.Sprintf("%s:%s", item.Report.Artifact.Repository, item.Report.Artifact.Tag)
		ref := fmt.Sprintf("%s/%s", namespace, image)

		for _, vuln := range item.Report.Vulnerabilities {
			if string(vuln.Severity) != "CRITICAL" {
				continue
			}

			id := vuln.VulnerabilityID
			entry, ok := cves[id]
			if !ok {
				title := vuln.Title
				if title == "" {
					title = vuln.Description
				}
				entry = &cveEntry{
					title: title,
				}
				cves[id] = entry
			}

			found := false
			for _, existing := range entry.images {
				if existing == ref {
					found = true
					break
				}
			}
			if !found {
				entry.images = append(entry.images, ref)
			}
		}
	}

	ids := make([]string, 0, len(cves))
	for id := range cves {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	if asJSON {
		entries := make([]jsonEntry, 0, len(ids))
		for _, id := range ids {
			entry := cves[id]
			sort.Strings(entry.images)
			entries = append(entries, jsonEntry{
				ID:     id,
				Title:  entry.title,
				Images: entry.images,
			})
		}
		return json.NewEncoder(os.Stdout).Encode(entries)
	}

	t := table.New(os.Stdout)
	t.SetHeaders("CVE ID", "Title", "Namespace/Image")

	for _, id := range ids {
		entry := cves[id]
		sort.Strings(entry.images)
		t.AddRow(id, entry.title, strings.Join(entry.images, "\n"))
	}

	t.Render()

	return nil
}
