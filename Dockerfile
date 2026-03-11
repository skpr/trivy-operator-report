FROM scratch

COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/trivy-operator-report /usr/local/bin/trivy-operator-report

ENTRYPOINT ["trivy-operator-report"]
