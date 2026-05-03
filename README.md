# 🔍 Kubernetes Egress Auditor

A lightweight **eBPF-based DaemonSet** that gives you real-time, pod-level egress visibility across every node in your Kubernetes cluster — without enabling VPC Flow Logs.

---

## Why This Exists

Kubernetes gives you excellent visibility into CPU and memory. It tells you almost nothing about network egress — the metric that shows up directly on your cloud bill.

Standard options are expensive (VPC Flow Logs) or complex (full service mesh). This tool takes a third path: hook `tcp_sendmsg` in the Linux kernel via eBPF, read the source IP, destination IP, and byte count for every TCP write, filter out internal traffic that doesn't cost anything, and log a clean per-pod report every 60 seconds.

---

## Features

- **Pod-level visibility** — pinpoints exactly which pod is generating egress, by name and namespace.
- **Kernel-accurate** — eBPF reads directly from the socket struct; no sampling, no approximation on pod attribution.
- **No VPC Flow Logs** — operates entirely at the kernel level on each node.
- **Zero application changes** — no sidecars, no annotations, no restarts.
- **Event-driven pod cache** — uses a `SharedInformer` instead of polling; short-lived pods are never missed and deleted pod IPs are removed immediately.
- **Internal traffic filtered** — RFC 1918, loopback, and link-local destinations are excluded; only billable egress is reported.
- **Namespace exclusion** — configure namespaces to exclude from reports via the `EXCLUDE_NAMESPACES` environment variable.
- **Clean shutdown** — blocking `rd.Read()` is unblocked on `SIGTERM` via a dedicated goroutine; no busy-wait, no stuck goroutines.
---

## Scope and Limitations

| What is monitored | What is NOT monitored |
|---|---|
| TCP egress (IPv4) | UDP traffic (DNS port 53, QUIC) |
| All pods on the node | HTTP/3 (runs over QUIC/UDP) |
| `hostNetwork` pods (with ambiguity warning) | IPv6 traffic (`skc_v6_rcv_saddr` not yet implemented) |
| Pod restarts and short-lived pods | Events dropped when perf buffer is full at very high send rates |

The perf ring buffer is initialised with 4096 pages. On a node with very high TCP send rates, events can be dropped — the `lost N samples` log line is the signal. See the [Roadmap](#roadmap) for the `BPF_MAP_TYPE_RINGBUF` upgrade that resolves this.

---

## Prerequisites

- Kubernetes cluster with `kubectl` access
- Go ≥ 1.26
- `clang` + `llvm`
- `bpftool` (for generating `vmlinux.h`)
- Linux kernel with BTF enabled (default on Kubernetes COS nodes)

---

## Quickstart

### 1. Clone

```bash
git clone https://github.com/PrathmeshWadje/pod-egress-auditor.git
cd pod-egress-auditor
```

### 2. Generate `vmlinux.h`

Run on a cluster node (or exec into a privileged debug pod):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
```

### 3. Initialise Go module and fetch dependencies

> `main.go` and the `ebpf/` directory must exist locally before running these commands — `go mod tidy` resolves imports by reading source files.

```bash
go mod init egress-auditor
go mod tidy
```

### 4. Build and push

```bash
docker build -t <your-registry>/egress-auditor:latest .
docker push <your-registry>/egress-auditor:latest
```

Update the `image:` field in `kubernetes/egress-auditor.yaml` to match your registry.

### 5. Deploy

```bash
kubectl apply -f kubernetes/egress-auditor.yaml
```

### 6. Tail the logs

```bash
kubectl logs -n egress-auditor -l app=egress-auditor -f
```

---

## Configuration

Configuration is via environment variables set in the DaemonSet manifest.

| Variable | Default | Description |
|---|---|---|
| `NODE_NAME` | *(required)* | The node this agent runs on. Injected automatically via the Kubernetes Downward API — set in the DaemonSet manifest using `fieldRef: fieldPath: spec.nodeName` exactly as shown. Do not hardcode a value. |
| `EXCLUDE_NAMESPACES` | `""` | Comma-separated list of namespaces to omit from egress reports. Example: `egress-auditor,kube-system` |

### Excluding the auditor's own namespace

In `kubernetes/egress-auditor.yaml`, under the container's `env` block:

```yaml
- name: EXCLUDE_NAMESPACES
  value: "egress-auditor"
```

Without this, the auditor pod itself — which runs with `hostNetwork: true` and communicates with the Kubernetes API server — will appear in its own egress reports as the top traffic source every minute. This is technically accurate but operationally misleading. Setting this variable removes the tool's own traffic from the output.

### ConfigMap

The ConfigMap included in the manifest defines four fields as **placeholders for future features**. None of them are read by the current version — editing them has no effect on runtime behaviour:

```yaml
poll_interval: 60s                  # not yet implemented
byte_threshold_warning: 1048576     # not yet implemented
byte_threshold_critical: 10485760   # not yet implemented
exclude_namespaces: [...]           # use EXCLUDE_NAMESPACES env var instead
```

---

## Understanding the Output

```
2026/05/02 07:23:13 --- Egress Traffic Report (last minute) ---
2026/05/02 07:23:13 Pod: kube-system/konnectivity-agent-5cc9bcb59b-bblmk | Source IP: 10.84.1.10 | Egress: 0.0101 MB
2026/05/02 07:23:13 Pod: kube-system/kube-dns-69d5488f8c-2hlll           | Source IP: 10.84.1.4  | Egress: 0.0139 MB
```

| Field | Meaning |
|---|---|
| `Pod` | `namespace/pod-name` resolved from the pod IP cache |
| `Source IP` | The pod's IP as seen by the kernel — node IP for `hostNetwork` pods |
| `Egress` | Application-layer bytes sent to public IPs in the last minute (not wire bytes; retransmissions are not double-counted) |
| `unknown/pod` | Source IP not yet in the cache — transient during pod restarts, resolves within one 60-second window |

### `hostNetwork` pods

Pods running with `hostNetwork: true` (e.g. `pdcsi-node`, `fluentbit-GKE`, `kube-proxy`) share the node's IP address. Multiple such pods on the same node map to the same source IP, making per-pod attribution ambiguous. The auditor logs a warning at startup and attributes egress to whichever pod was cached first:

```
WARNING: IP 10.0.6.210 is shared by "egress-auditor/egress-auditor-pkfgq"
and "kube-system/pdcsi-node-trrlj" (hostNetwork:true).
Egress for this source IP may be attributed to either pod.
```

### `unknown/pod` during pod restarts

When a pod is deleted and replaced, there is a brief window between the delete event and the new pod's IP appearing in the cache. Events during this window show as `unknown/pod` and resolve within one 60-second reporting interval. Across 12 live reporting windows in testing, only 2 `unknown/pod` entries appeared.

---

## Project Structure

```
pod-egress-auditor/
├── main.go                    # Go controller — eBPF loader, event loop, reporting
├── ebpf/
│   ├── tcp_monitor.c          # eBPF kprobe program (44 lines)
│   └── vmlinux.h              # generated — not committed, create per node OS
├── kubernetes/
│   └── egress-auditor.yaml    # DaemonSet, RBAC, Namespace, ConfigMap
├── Dockerfile                 # two-stage build: clang + go → debian:slim
└── go.mod
```

---

## Roadmap

- [ ] Prometheus `/metrics` endpoint — `egress_bytes_total{pod, namespace}`
- [ ] Webhook alerting (Slack / PagerDuty) when byte thresholds are exceeded
- [ ] Read `exclude_namespaces` and thresholds from ConfigMap at runtime
- [ ] UDP / QUIC support via `udp_sendmsg` hook
- [ ] IPv6 support via `skc_v6_rcv_saddr` / `skc_v6_daddr`
- [ ] `BPF_MAP_TYPE_RINGBUF` upgrade for improved throughput under high send rates
---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.