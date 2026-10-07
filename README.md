# TCP Packet Analyzer

A Go-based TCP packet analyzer built as a learning and experimentation project for understanding:

- Packet capture
- Network protocol parsing
- Packet validation
- TCP behavior
- IPv4 fragmentation and reassembly
- Network analysis
- Concurrent, stage-based packet processing

---

## 🛠️ Fresh macOS Setup

Follow these steps when setting up the project on a fresh macOS installation.

### 1. Verify Prerequisites

Check that Git, Go, and the Xcode Command Line Tools are installed:

```bash
git --version
go version
xcode-select -p
```

If the Xcode Command Line Tools are missing:

```bash
xcode-select --install
```

> **Note:** Use the Go version specified by `go.mod`.

---

### 2. Enter the Repository

If the repository is already cloned:

```bash
cd tcp_packet_analyzer
git status
```

If it has not been cloned yet:

```bash
git clone <repository-url>
cd tcp_packet_analyzer
```

---

### 3. Restore Dependencies

Download the project's Go dependencies:

```bash
go mod download
```

> **Important:** Do not run `go mod tidy` unless you intentionally want to reconcile or update `go.mod` and `go.sum`.

---

### 4. Build

Verify that the entire project builds successfully:

```bash
go build ./...
```

---

### 5. Test

Run the test suite:

```bash
go test ./...
```

For concurrency and data-race detection:

```bash
go test -race ./...
```

---

### 6. Run

The current executable entry point is:

```text
cmd/analyzer/main.go
```

Run the analyzer with:

```bash
go run ./cmd/analyzer
```

If packet-capture permissions require elevated privileges:

```bash
sudo go run ./cmd/analyzer
```

> **Note:** Use `sudo` only when necessary.

---

# 🔄 Current Packet Pipeline

The analyzer currently processes packets through the following pipeline:

```text
                    Packet Capture
                         │
                         ▼
                  ┌──────────────┐
                  │ CapturedFrame│
                  └──────┬───────┘
                         │
                         ▼
                  DataLink Worker
                         │
                         ▼
                     Ethernet
                         │
                         ▼
                   Network Worker
                         │
                         ▼
                       IPv4
                         │
                         ▼
                  Transport Worker
                         │
                         ▼
                       TCP
                         │
                         ▼
                    PacketStore
                         │
                         ▼
                   Output Worker
                         │
                         ▼
                     Formatter
                         │
                         ▼
                      Terminal
```

### Current Protocol Scope

The current protocol path is:

```text
Ethernet → IPv4 → TCP
```

Non-IPv4 and non-TCP packets are currently skipped.

---

# 🏗️ Project Architecture

The project is organized as a stage-based processing pipeline.

### Capture

Captures packets from the network interface and creates `CapturedFrame` objects containing the captured packet data and associated metadata.

### Protocol Parsers

Protocol parsers extract fields from the corresponding protocol headers.

Current protocol layers include:

- Ethernet
- IPv4
- TCP

### Validators

Validators perform structural and semantic validation of protocol data.

Validation is kept separate from parsing so that:

```text
Parsing    → Extract information
Validation → Determine whether information is structurally/semantically valid
```

### Workers

Workers process individual pipeline stages and communicate with other stages through typed channels.

The workers are responsible for execution, while protocol packages remain responsible for protocol-specific logic.

### PacketStore

`PacketStore` retains structured packet information after processing.

It acts as the source of truth for packet data.

### Output

The output subsystem is responsible for presenting packet information to the user.

Parsers, validators, workers, capture, and the store should **not** own user-facing packet presentation.

The `output` package owns that responsibility.

### Analysis

The analysis layer will provide higher-level TCP and network behavior analysis once the underlying packet-processing pipeline is complete.

---

# 💾 PacketStore and Output

Packets remain available in `PacketStore` after they have been printed.

The intended relationship is:

```text
                    PacketStore
                   /     |      \
                  ▼      ▼       ▼
              Output  Analysis  Export
```

The important architectural distinction is:

```text
PacketStore → Source of structured packet data
Output      → Presentation of that data
```

This allows the same stored packet information to later be consumed by:

- Terminal output
- Network/TCP analysis
- Export functionality
- Other future consumers

without coupling those consumers to the packet-processing pipeline.

---

# 🧩 Next Major Feature: IPv4 Fragmentation & Reassembly

The next major feature is **IPv4 fragmentation and reassembly**.

The future packet flow will be:

```text
CapturedFrame
      │
      ▼
   Ethernet
      │
      ▼
     IPv4
      │
      ▼
Fragment Detection
      │
      ▼
  Reassembly
      │
      ▼
Complete IPv4 Payload
      │
      ▼
     TCP
      │
      ▼
 PacketStore
      │
      ├──────────► Output
      │
      └──────────► Analysis
```

### Important IPv4 Fragmentation Rule

An IPv4 packet with:

```text
Protocol = 6
```

does **not** necessarily mean that the current fragment contains a TCP header.

Only the first fragment contains the beginning of the IPv4 payload, where the TCP header begins.

Therefore, for fragmented IPv4 datagrams:

```text
IPv4 Fragments
      │
      ▼
  Reassembly
      │
      ▼
Complete IPv4 Payload
      │
      ▼
   TCP Parser
```

TCP parsing must occur **after successful reassembly** for fragmented datagrams.

---

# 🧪 Useful Commands

### Format Code

```bash
gofmt -w .
```

### Build

```bash
go build ./...
```

### Run Tests

```bash
go test ./...
```

### Run Race Detector

```bash
go test -race ./...
```

### Run Analyzer

```bash
go run ./cmd/analyzer
```

### Inspect Changes

```bash
git diff
```

### Check Repository Status

```bash
git status
```

---

# 🔁 Fresh-Machine Restart Checklist

After setting up a fresh Mac or restoring the repository:

```bash
cd tcp_packet_analyzer

git pull

go version

go mod download

go build ./...

go test ./...

go run ./cmd/analyzer
```

If packet-capture permissions require elevation:

```bash
sudo go run ./cmd/analyzer
```

---

# 🌿 Git Workflow

### Before Starting Work

```bash
git pull
git status
```

### After Implementation

Run the verification steps:

```bash
go test ./...
go build ./...
git diff
```

Then commit and push:

```bash
git add .
git commit -m "Implement <feature>"
git push
```

---

# 🔄 Preferred Development Workflow

The project follows a feature-driven workflow:

```text
        GitHub Issue
             │
             ▼
       Implementation
             │
             ▼
          Testing
             │
             ▼
      Commit / Pull Request
             │
             ▼
           Merge
```

This keeps implementation, testing, and version control changes organized around individual project features.