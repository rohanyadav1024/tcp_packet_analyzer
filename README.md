TCP Packet Analyzer

A Go-based TCP packet analyzer for learning packet capture, protocol
parsing, validation, TCP behavior, IPv4 fragmentation/reassembly, and
network analysis.

Fresh macOS setup

1. Verify prerequisites

git --version
go version
xcode-select -p

If Xcode Command Line Tools are missing:

xcode-select --install

Use the Go version specified by go.mod.

2. Enter the repository

If already cloned:

cd tcp_packet_analyzer
git status

If not cloned:

git clone <repository-url>
cd tcp_packet_analyzer

3. Restore dependencies

go mod download

Do not run go mod tidy unless you intend to reconcile/update go.mod
and go.sum.

4. Build

go build ./...

5. Test

go test ./...

For concurrency testing:

go test -race ./...

6. Run

The executable entry point is currently:

cmd/analyzer/main.go

Run:

go run ./cmd/analyzer

If packet capture permissions require it:

sudo go run ./cmd/analyzer

Only use sudo when necessary.

Current pipeline

Packet Capture
      ↓
CapturedFrame
      ↓
DataLink Worker
      ↓
Ethernet
      ↓
Network Worker
      ↓
IPv4
      ↓
Transport Worker
      ↓
TCP
      ↓
PacketStore
      ↓
Output Worker
      ↓
Formatter
      ↓
Terminal

Current protocol scope is:

Ethernet → IPv4 → TCP

Non-IPv4 and non-TCP packets are currently skipped.

Project architecture

Capture reads packets and creates CapturedFrame.

Protocol parsers extract protocol fields.

Validators perform structural and semantic validation.

Workers process stages and communicate through typed channels.

PacketStore retains structured packet data.

Output presents packet data to the user.

Analysis will later provide higher-level TCP/network behavior
analysis.

Parsers, validators, workers, capture, and the store should not own
user-facing packet presentation. The output package owns that
responsibility.

PacketStore and output

Packets are retained in PacketStore after being printed.

The store is the source of structured packet data; output is only a
presentation of that data.

The intended relationship is:

PacketStore
   ├──→ Output
   ├──→ Analysis
   └──→ Export

Next major feature

The next major feature is IPv4 fragmentation and reassembly.

The future flow is:

CapturedFrame
      ↓
Ethernet
      ↓
IPv4
      ↓
Fragment detection
      ↓
Reassembly
      ↓
Complete IPv4 payload
      ↓
TCP
      ↓
PacketStore
      ↓
Output / Analysis

Important: an IPv4 packet with Protocol = 6 does not mean every
fragment contains a TCP header. TCP parsing must occur after successful
reassembly for fragmented datagrams.

Useful commands

Format code:

gofmt -w .

Build:

go build ./...

Test:

go test ./...

Run:

go run ./cmd/analyzer

Inspect changes:

git diff

Future restart checklist

After a fresh Mac setup:

cd tcp_packet_analyzer
git pull
go version
go mod download
go build ./...
go test ./...
go run ./cmd/analyzer

If capture permissions require elevation:

sudo go run ./cmd/analyzer

Git workflow

Before work:

git pull
git status

After implementation:

go test ./...
go build ./...
git diff

Then commit and push:

git add .
git commit -m "Implement <feature>"
git push

Preferred project workflow:

GitHub Issue
     ↓
Implementation
     ↓
Testing
     ↓
Commit / Pull Request
     ↓
Merge