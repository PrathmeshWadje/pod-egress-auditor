# Stage 1: Compile everything
FROM golang:1.26 AS builder

RUN apt-get update && apt-get install -y \
    clang llvm libelf-dev libbpf-dev dwarves gcc make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY ebpf ./ebpf

# Compile the eBPF C program to a BPF object file.
# -D__x86_64__ is non-obvious but required: without it, the preprocessor
# inside a generic golang container won't define the architecture macros
# that vmlinux.h depends on, producing a cryptic build failure.
RUN clang -g -O2 -Wall \
    -target bpf \
    -D__TARGET_ARCH_x86_64 \
    -D__x86_64__ \
    -I/app/ebpf \
    -c ebpf/tcp_monitor.c -o ebpf/tcp_monitor.o

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o egress-auditor main.go

# Stage 2: Lean runtime image — just the binary and the eBPF object
FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/egress-auditor ./
COPY --from=builder /app/ebpf/tcp_monitor.o ./ebpf/
VOLUME ["/sys/kernel/btf"]
ENTRYPOINT ["./egress-auditor"]