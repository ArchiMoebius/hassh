#!/bin/bash
# SSH Connection Benchmark Runner
# Comprehensive performance testing for HASSH fingerprinting

set -e

BENCHMARK_DIR="./benchmark_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="${BENCHMARK_DIR}/benchmark_${TIMESTAMP}.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

mkdir -p "$BENCHMARK_DIR"

echo "========================================================================="
echo "SSH Connection Benchmark Suite"
echo "========================================================================="
echo "Timestamp: $TIMESTAMP"
echo "Go Version: $(go version)"
echo "System: $(uname -s) $(uname -m)"
echo "CPUs: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 'unknown')"
echo "========================================================================="
echo ""

# Function to run benchmark and capture results
run_benchmark() {
    local name=$1
    local bench_pattern=$2
    local extra_args=${3:-""}
    
    echo -e "${GREEN}Running: $name${NC}"
    echo "Pattern: $bench_pattern"
    echo "Args: $extra_args"
    echo ""
    
    go test -bench="$bench_pattern" -benchmem -benchtime=5s $extra_args | tee -a "$RESULT_FILE"
    
    echo ""
    echo "---"
    echo ""
}

# 1. Connection Setup Benchmarks
echo "========================================================================="
echo "1. SSH CONNECTION SETUP BENCHMARKS"
echo "========================================================================="
run_benchmark "Basic SSH Connection" "^BenchmarkSSHConnectionSetup$"
run_benchmark "SSH Connection with Fingerprinting" "^BenchmarkSSHConnectionSetup_WithFingerprinting$"

# 2. Real-World KEXINIT Parsing
echo "========================================================================="
echo "2. REAL-WORLD SSH CLIENT PARSING"
echo "========================================================================="
run_benchmark "All SSH Clients" "^BenchmarkKEXINITParsing_RealWorld$"

# 3. Connection Rate Testing
echo "========================================================================="
echo "3. CONNECTION RATE UNDER LOAD"
echo "========================================================================="
run_benchmark "Connection Rate (Various Concurrency)" "^BenchmarkConnectionRate$"

# 4. Cache Performance
echo "========================================================================="
echo "4. FINGERPRINT CACHE PERFORMANCE"
echo "========================================================================="
run_benchmark "Cache Lookup" "^BenchmarkFingerprintCacheLookup$"

# 5. Hash Algorithm Comparison
echo "========================================================================="
echo "5. HASH ALGORITHM COMPARISON (MD5 vs SHA-256)"
echo "========================================================================="
run_benchmark "Hash Algorithms" "^BenchmarkHashAlgorithms$"

# 6. Parsing Complexity
echo "========================================================================="
echo "6. PARSING COMPLEXITY ANALYSIS"
echo "========================================================================="
run_benchmark "Complexity Levels" "^BenchmarkParsingComplexity$"

# 7. Memory Allocation
echo "========================================================================="
echo "7. MEMORY ALLOCATION PATTERNS"
echo "========================================================================="
run_benchmark "Memory Analysis" "^BenchmarkMemoryAllocation$"

# 8. CPU Profiling (if requested)
if [[ "$1" == "--profile" ]]; then
    echo "========================================================================="
    echo "8. CPU PROFILING"
    echo "========================================================================="
    echo "Generating CPU profile..."
    go test -bench=BenchmarkKEXINITParsing_RealWorld -cpuprofile="${BENCHMARK_DIR}/cpu_${TIMESTAMP}.prof" -benchtime=10s
    echo "CPU profile saved to: ${BENCHMARK_DIR}/cpu_${TIMESTAMP}.prof"
    echo "View with: go tool pprof ${BENCHMARK_DIR}/cpu_${TIMESTAMP}.prof"
    echo ""
    
    echo "Generating memory profile..."
    go test -bench=BenchmarkMemoryAllocation -memprofile="${BENCHMARK_DIR}/mem_${TIMESTAMP}.prof" -benchtime=10s
    echo "Memory profile saved to: ${BENCHMARK_DIR}/mem_${TIMESTAMP}.prof"
    echo "View with: go tool pprof -alloc_space ${BENCHMARK_DIR}/mem_${TIMESTAMP}.prof"
    echo ""
fi

# 9. Race Detection (if requested)
if [[ "$1" == "--race" ]]; then
    echo "========================================================================="
    echo "9. RACE CONDITION DETECTION"
    echo "========================================================================="
    echo "Running benchmarks with race detector..."
    go test -bench=BenchmarkParseKexInit_ConcurrentSafety -race -benchtime=3s | tee -a "$RESULT_FILE"
    echo ""
fi

# Summary
echo "========================================================================="
echo "BENCHMARK SUMMARY"
echo "========================================================================="
echo "Results saved to: $RESULT_FILE"
echo ""

# Generate performance report
echo "Generating performance report..."
python3 - <<EOF
import re
import sys

with open('$RESULT_FILE', 'r') as f:
    content = f.read()

# Extract key metrics
benchmarks = re.findall(r'Benchmark\w+.*?(\d+)\s+(\d+\.?\d*)\s+ns/op', content)
conn_rates = re.findall(r'(\d+\.?\d*)\s+conn/sec', content)
parse_rates = re.findall(r'(\d+\.?\d*)\s+parses/sec', content)
hash_rates = re.findall(r'(\d+\.?\d*)\s+hashes/sec', content)

print("\n📊 Key Performance Indicators:")
print("="*60)

if parse_rates:
    avg_parse = sum(float(r) for r in parse_rates) / len(parse_rates)
    print(f"Average Parsing Rate: {avg_parse:,.0f} parses/sec")
    status = "✓ EXCELLENT" if avg_parse > 20000 else "⚠ REVIEW" if avg_parse > 10000 else "✗ CRITICAL"
    print(f"Status: {status}")
    print()

if conn_rates:
    max_conn = max(float(r) for r in conn_rates)
    print(f"Maximum Connection Rate: {max_conn:,.0f} conn/sec")
    status = "✓ EXCELLENT" if max_conn > 500 else "⚠ REVIEW" if max_conn > 200 else "✗ CRITICAL"
    print(f"Status: {status}")
    print()

if hash_rates:
    avg_hash = sum(float(r) for r in hash_rates) / len(hash_rates)
    print(f"Average Hash Rate: {avg_hash:,.0f} hashes/sec")
    status = "✓ EXCELLENT" if avg_hash > 200000 else "⚠ REVIEW" if avg_hash > 100000 else "✗ CRITICAL"
    print(f"Status: {status}")
    print()

print("="*60)
print("\nFor detailed analysis, see: $RESULT_FILE")
EOF

echo ""
echo "========================================================================="
echo "BENCHMARK COMPLETE"
echo "========================================================================="
echo ""
echo "Next steps:"
echo "1. Review results in: $RESULT_FILE"
if [[ "$1" == "--profile" ]]; then
    echo "2. Analyze CPU profile: go tool pprof ${BENCHMARK_DIR}/cpu_${TIMESTAMP}.prof"
    echo "3. Analyze memory profile: go tool pprof -alloc_space ${BENCHMARK_DIR}/mem_${TIMESTAMP}.prof"
fi
echo "4. Compare with previous runs: benchcmp old.txt new.txt"
echo "5. Monitor for regressions in CI/CD"
echo ""
echo "Usage:"
echo "  ./benchmark.sh              # Run all benchmarks"
echo "  ./benchmark.sh --profile    # Include CPU/memory profiling"
echo "  ./benchmark.sh --race       # Include race detection"
echo ""