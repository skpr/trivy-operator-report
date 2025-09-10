FROM scratch

COPY trivy-operator-report /bin/trivy-operator-report

ENTRYPOINT ["/bin/trivy-operator-report"]
