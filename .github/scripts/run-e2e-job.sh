#!/usr/bin/env bash
# Run one selection of the in-cluster e2e suite as a Kubernetes Job and
# turn the Job's condition into this script's exit code.
#
# Usage: run-e2e-job.sh <job-name> <-test.run regex> <-test.timeout>
# Env:   NS (namespace), RELEASE (Helm release name)
#        E2E_RUNNER_BINARY   optional: the test binary inside the image to run
#                            (default: the image's ENTRYPOINT, e2e.test). The
#                            cluster e2e lane (exit-test-e2e-cluster.yml) bakes
#                            a second binary, secrets.test, into the same image.
#        E2E_RUNNER_ENV_FILE optional: a KEY=VALUE file whose entries reach the
#                            Job's environment through the same Secret that
#                            carries REDIS_PASSWORD, so a suite's own settings
#                            (a tenant id, a platform URL) never land in the
#                            Job manifest in clear.
#
# The suite runs INSIDE the cluster, not over a port-forward. The daemon's
# gRPC listener speaks SPIFFE mTLS and refuses to bind a non-loopback
# plaintext listener at all (zero-trust-hardening Req 1.2), so a port-forward
# from the runner is closed before the gRPC preface. authz.enabled=false does
# not change it because that disables authorization, not transport. The
# suite therefore needs an attested SVID, which means being a pod in the
# mesh. The image is built and loaded by the workflow
# (ghcr.io/zeroroot-ai/gibson-e2e-runner:local).
set -euo pipefail

JOB="${1:?job name}"
TEST_RUN="${2:?-test.run regex}"
TEST_TIMEOUT="${3:?-test.timeout}"
: "${NS:?NS is required}"
: "${RELEASE:?RELEASE is required}"

pw=$(kubectl -n "$NS" get secret gibson-redis-stack -o jsonpath='{.data.redis-password}' | base64 -d)
if [ -z "$pw" ]; then
  echo "::error::gibson-redis-stack has no redis-password; the fixture helpers cannot authenticate"
  exit 1
fi
echo "::add-mask::$pw"
kubectl -n "$NS" delete secret gibson-e2e-runner-env --ignore-not-found
if [ -n "${E2E_RUNNER_ENV_FILE:-}" ]; then
  [ -s "$E2E_RUNNER_ENV_FILE" ] || { echo "::error::E2E_RUNNER_ENV_FILE=$E2E_RUNNER_ENV_FILE is missing or empty"; exit 1; }
  kubectl -n "$NS" create secret generic gibson-e2e-runner-env \
    --from-literal=REDIS_PASSWORD="$pw" \
    --from-env-file="$E2E_RUNNER_ENV_FILE"
else
  kubectl -n "$NS" create secret generic gibson-e2e-runner-env \
    --from-literal=REDIS_PASSWORD="$pw"
fi

# The binary the Job runs. Unset, the image's ENTRYPOINT (e2e.test) runs.
COMMAND_LINE=""
if [ -n "${E2E_RUNNER_BINARY:-}" ]; then
  COMMAND_LINE="          command: [\"${E2E_RUNNER_BINARY}\"]"
fi

# In-cluster addresses: no port-forward, and the SVID is minted for this pod
# by the ClusterSPIFFEID keyed on its label + ServiceAccount.
kubectl -n "$NS" delete job "$JOB" --ignore-not-found
cat <<YAML | kubectl -n "$NS" apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB}
spec:
  backoffLimit: 0
  template:
    metadata:
      labels:
        # The daemon's NetworkPolicy admits the runner by the chart's
        # selector labels plus the component; the component alone left
        # every dial to the daemon in "i/o timeout" (run 34154995591).
        app.kubernetes.io/name: gibson-workloads
        app.kubernetes.io/instance: ${RELEASE}
        app.kubernetes.io/component: e2e-runner
    spec:
      restartPolicy: Never
      serviceAccountName: ${RELEASE}-e2e-runner
      containers:
        - name: e2e
          image: ghcr.io/zeroroot-ai/gibson-e2e-runner:local
          imagePullPolicy: IfNotPresent
${COMMAND_LINE}
          args: ["-test.run", "${TEST_RUN}", "-test.v", "-test.timeout", "${TEST_TIMEOUT}"]
          # Every entry of the Secret is an environment variable: the
          # password plus whatever E2E_RUNNER_ENV_FILE added.
          envFrom:
            - secretRef:
                name: gibson-e2e-runner-env
          env:
            - name: GIBSON_TEST_FIXTURES_ENABLED
              value: "true"
            - name: DAEMON_GRPC_ADDR
              value: "gibson-gibson-workloads.${NS}.svc.cluster.local:50051"
            # The daemon's listener is SPIFFE mTLS. Name the socket the
            # csi.spiffe.io mount below carries (api.sock, the chart's
            # gibson.auth.spiffe.workloadAPISocket) so the runner never
            # guesses and never dials plaintext (gibson#14).
            - name: SPIFFE_ENDPOINT_SOCKET
              value: "unix:///run/spire/sockets/api.sock"
            - name: REDIS_ADDR
              value: "gibson-redis-stack.${NS}.svc.cluster.local:6379"
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: gibson-e2e-runner-env
                  key: REDIS_PASSWORD
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
      volumes:
        # The SPIRE Workload API arrives through the csi.spiffe.io driver, as
        # the daemon's own StatefulSet mounts it. A hostPath to
        # /run/spire/sockets does not exist on the kind node and wedges the
        # Pod in ContainerCreating.
        - name: spire-agent-socket
          csi:
            driver: csi.spiffe.io
            readOnly: true
YAML

# Stream the suite's output so a failure is readable here, then use the
# Job's own condition as the verdict. `kubectl wait` on Complete alone would
# hang the full timeout on a failed run.
kubectl -n "$NS" wait --for=condition=Ready pod \
  -l "job-name=${JOB}" --timeout=3m || true
kubectl -n "$NS" logs -f "job/${JOB}" --tail=-1 || true

for _ in $(seq 1 120); do
  ok=$(kubectl -n "$NS" get job "$JOB" -o jsonpath='{.status.succeeded}' 2>/dev/null || true)
  bad=$(kubectl -n "$NS" get job "$JOB" -o jsonpath='{.status.failed}' 2>/dev/null || true)
  [ "${ok:-0}" != "0" ] && [ -n "${ok:-}" ] && { echo "exit test ${JOB} PASSED"; exit 0; }
  [ "${bad:-0}" != "0" ] && [ -n "${bad:-}" ] && { echo "::error::the exit test ${JOB} FAILED"; exit 1; }
  sleep 10
done
echo "::error::the exit test ${JOB} did not finish"
exit 1
