FROM scratch

COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY trivy-operator-report /bin/trivy-operator-report

ENTRYPOINT ["/bin/trivy-operator-report"]
