// main.go

package main

import (
    "bytes"
    "context"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/informers"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/tools/cache"
)

// Data mirrors the data_t struct in the eBPF program.
// Field order and sizes must match exactly — binary.Read is unforgiving.
type Data struct {
    Bytes      uint64
    SourceAddr uint32
    DestAddr   uint32
}

// internalCIDRs holds every address range representing non-billable traffic.
// RFC 1918 covers pod-to-pod and pod-to-service communication.
// Loopback (127.0.0.0/8) covers intra-process communication on the host.
// Link-local (169.254.0.0/16) covers GKE's internal metadata server (169.254.20.10).
// All three surfaced during real cluster testing as false positives.
var internalCIDRs []*net.IPNet

func init() {
    privateRanges := []string{
        "10.0.0.0/8",      // GKE pod CIDRs and node IPs
        "172.16.0.0/12",   // Alternate pod/service ranges
        "192.168.0.0/16",  // Cluster-internal service IPs
        "127.0.0.0/8",     // Loopback — intra-host communication
        "169.254.0.0/16",  // Link-local — GKE metadata server
    }
    for _, cidr := range privateRanges {
        _, network, err := net.ParseCIDR(cidr)
        if err == nil {
            internalCIDRs = append(internalCIDRs, network)
        }
    }
}

// isInternalIP returns true if the destination IP stays within the cluster or
// host and does not incur a GCP egress charge.
func isInternalIP(ipStr string) bool {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return false
    }
    for _, cidr := range internalCIDRs {
        if cidr.Contains(ip) {
            return true
        }
    }
    return false
}

func main() {
    log.Println("Starting Egress Auditor...")

    // NODE_NAME must be injected via the Downward API. Without it the agent
    // would have to list the entire cluster's pod inventory — an API server
    // anti-pattern that must never silently occur in a DaemonSet.
    nodeName := os.Getenv("NODE_NAME")
    if nodeName == "" {
        log.Fatal("NODE_NAME environment variable is not set. " +
            "Ensure the Downward API fieldRef for spec.nodeName is configured " +
            "in the DaemonSet manifest.")
    }

    // EXCLUDE_NAMESPACES is a comma-separated list of namespaces whose traffic
    // will be omitted from egress reports. At minimum, set this to the
    // auditor's own namespace so the tool doesn't report its own API traffic
    // as the loudest signal in the cluster.
    excludedNS := make(map[string]bool)
    if raw := os.Getenv("EXCLUDE_NAMESPACES"); raw != "" {
        for _, ns := range strings.Split(raw, ",") {
            if trimmed := strings.TrimSpace(ns); trimmed != "" {
                excludedNS[trimmed] = true
            }
        }
        log.Printf("Excluding namespaces from reports: %v", os.Getenv("EXCLUDE_NAMESPACES"))
    }

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    spec, err := ebpf.LoadCollectionSpec("ebpf/tcp_monitor.o")
    if err != nil {
        log.Fatalf("failed to load BPF program: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("failed to create BPF collection: %v", err)
    }
    defer coll.Close()

    prog := coll.Programs["kprobe__tcp_sendmsg"]
    if prog == nil {
        log.Fatal("eBPF program 'kprobe__tcp_sendmsg' not found")
    }

    kp, err := link.Kprobe("tcp_sendmsg", prog, nil)
    if err != nil {
        log.Fatalf("failed to attach kprobe: %v", err)
    }
    defer kp.Close()

    log.Println("eBPF program attached successfully.")

    eventsMap, ok := coll.Maps["events"]
    if !ok {
        log.Fatalf("events map not found in eBPF object")
    }

    rd, err := perf.NewReader(eventsMap, 4096)
    if err != nil {
        log.Fatalf("failed to open perf reader: %v", err)
    }
    defer rd.Close()

    config, err := rest.InClusterConfig()
    if err != nil {
        log.Fatalf("failed to get in-cluster config: %v", err)
    }

    kubeClient, err := kubernetes.NewForConfig(config)
    if err != nil {
        log.Fatalf("failed to create kube client: %v", err)
    }

    var cacheMu sync.RWMutex
    podIpToName := make(map[string]string)

    // SharedInformer scoped to this node via field selector.
    // Event-driven — reacts immediately to pod add, update, and delete events.
    // Advantages over the previous 30-second List() polling:
    //   - Short-lived pods (init containers, Jobs) are never missed.
    //   - Deleted pod IPs are evicted from the cache immediately.
    //   - No periodic full-list requests hit the API server.
    factory := informers.NewSharedInformerFactoryWithOptions(
        kubeClient,
        0, // no resync — watch events are sufficient
        informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
            opts.FieldSelector = "spec.nodeName=" + nodeName
        }),
    )

    podInformer := factory.Core().V1().Pods().Informer()
    podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(obj interface{}) {
            pod, ok := obj.(*corev1.Pod)
            if !ok || pod.Status.PodIP == "" {
                return
            }
            cacheMu.Lock()
            defer cacheMu.Unlock()
            podKey := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
            // Pods with hostNetwork:true share the node's IP. Multiple pods
            // can map to the same source IP. Keep the first and warn so the
            // operator is aware rather than silently overwriting.
            if existing, conflict := podIpToName[pod.Status.PodIP]; conflict && existing != podKey {
                log.Printf("WARNING: IP %s is shared by %q and %q (hostNetwork:true). "+
                    "Egress for this source IP may be attributed to either pod.",
                    pod.Status.PodIP, existing, podKey)
                return
            }
            podIpToName[pod.Status.PodIP] = podKey
        },
        UpdateFunc: func(_, newObj interface{}) {
            pod, ok := newObj.(*corev1.Pod)
            if !ok || pod.Status.PodIP == "" {
                return
            }
            cacheMu.Lock()
            defer cacheMu.Unlock()
            podIpToName[pod.Status.PodIP] = fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
        },
        DeleteFunc: func(obj interface{}) {
            pod, ok := obj.(*corev1.Pod)
            if !ok {
                return
            }
            cacheMu.Lock()
            defer cacheMu.Unlock()
            delete(podIpToName, pod.Status.PodIP)
        },
    })

    factory.Start(ctx.Done())

    log.Println("Waiting for pod informer cache to sync...")
    if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
        // WaitForCacheSync returns false when ctx is cancelled (e.g. SIGTERM
        // during a graceful restart) as well as on genuine sync failures.
        log.Fatal("pod informer cache sync did not complete — " +
            "context was cancelled or a shutdown signal was received")
    }
    log.Println("Pod informer synced. Listening for eBPF TCP events...")

    // trafficAggregator is written by the main eBPF read loop and read+reset
    // by the reporting goroutine. sync.Mutex guards only the map operations —
    // isInternalIP and intToIP run outside the lock so the high-throughput
    // event stream is never stalled longer than a single map write.
    var aggMu sync.Mutex
    trafficAggregator := make(map[string]uint64)

    // Goroutine: snapshot and flush the aggregator every minute, then reset.
    go func() {
        ticker := time.NewTicker(1 * time.Minute)
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                // Swap under lock so the read loop is blocked for as little
                // time as possible while we take ownership of the snapshot.
                aggMu.Lock()
                snapshot := trafficAggregator
                trafficAggregator = make(map[string]uint64)
                aggMu.Unlock()

                cacheMu.RLock()
                logAggregatedTraffic(snapshot, podIpToName, excludedNS)
                cacheMu.RUnlock()
            }
        }
    }()

    for {
        select {
        case <-ctx.Done():
            log.Println("Received stop signal, exiting.")
            return
        default:
            record, err := rd.Read()
            if err != nil {
                if err == perf.ErrClosed {
                    return
                }
                log.Printf("perf read error: %v", err)
                continue
            }

            if record.LostSamples > 0 {
                log.Printf("lost %d samples", record.LostSamples)
                continue
            }

            var data Data
            if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data); err != nil {
                log.Printf("failed to parse sample: %v", err)
                continue
            }

            // Perform IP checks BEFORE acquiring the lock — the mutex guards
            // only the minimal map write operation.
            destIp := intToIP(data.DestAddr).String()
            if isInternalIP(destIp) {
                continue
            }

            sourceIp := intToIP(data.SourceAddr).String()
            aggMu.Lock()
            trafficAggregator[sourceIp] += data.Bytes
            aggMu.Unlock()
        }
    }
}

func logAggregatedTraffic(aggregator map[string]uint64, ipCache map[string]string, excludedNS map[string]bool) {
    log.Println("--- Egress Traffic Report (last minute) ---")
    reported := 0
    for ip, bytes := range aggregator {
        podName, found := ipCache[ip]
        if !found {
            podName = "unknown/pod"
        }
        // Skip namespaces listed in EXCLUDE_NAMESPACES.
        // This prevents the auditor's own traffic (and any other
        // infrastructure namespace) from dominating the report.
        if len(excludedNS) > 0 {
            parts := strings.SplitN(podName, "/", 2)
            if len(parts) == 2 && excludedNS[parts[0]] {
                continue
            }
        }
        megabytes := float64(bytes) / (1024 * 1024)
        log.Printf("Pod: %-40s | Source IP: %-15s | Egress: %.4f MB", podName, ip, megabytes)
        reported++
    }
    if reported == 0 {
        log.Println("No external outbound traffic detected.")
    }
}

// intToIP converts a uint32 IP address into a net.IP for printing and CIDR matching.
//
// Byte-order note: skc_rcv_saddr and skc_daddr are __be32 (big-endian) in the kernel.
// BPF_CORE_READ assigns them to __u32 as a pure byte copy — no swap occurs.
// The perf buffer carries these bytes as-is to userspace.
// binary.Read with LittleEndian interprets the 4 bytes as a little-endian uint32
// (reversing the integer value). binary.LittleEndian.PutUint32 then reverses that
// back when writing into the net.IP slice, restoring the original network-order bytes.
// LittleEndian read + LittleEndian write = identity on the underlying bytes.
// This is correct and intentional. Changing PutUint32 to BigEndian without also
// changing binary.Read would produce byte-flipped IPs.
func intToIP(ip uint32) net.IP {
    result := make(net.IP, 4)
    binary.LittleEndian.PutUint32(result, ip)
    return result
}