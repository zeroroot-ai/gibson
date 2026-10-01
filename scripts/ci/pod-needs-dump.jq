# pod-needs-dump.jq — names the pods whose logs are worth printing.
#
# Reads `kubectl get pods -o json`. Prints one name per line.
#
# A Succeeded pod is excluded BEFORE the readiness tests, not just from the phase
# test. Its containers have terminated, so `ready` is false for every one of
# them. Measured against staging: 47 pods had a not-ready container and 46 were
# completed Jobs. Without that guard this selects every successful run.
#
# This file does NOT catch the case that cost three days. A pod whose probes were
# timing out twenty minutes ago reads 2/2 Running and restartCount 0 by the time
# anyone looks, so the caller unions these names with the pods named in Warning
# events. Neither half is sufficient alone.
.items[]
| select(.status.phase != "Succeeded")
| select(
    ((.status.containerStatuses // []) | map(.restartCount // 0) | add // 0) > 0
    or ((.status.containerStatuses // []) | any(.ready == false))
    or ((.status.initContainerStatuses // []) | any(.ready == false))
    or (.status.phase != "Running")
  )
| .metadata.name
