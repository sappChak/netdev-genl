#!/bin/bash

# capture_netlink.sh - Script to capture Netlink traffic using nlmon

# Default configuration
INTERFACE="nlmon0"                            # Name of the nlmon interface
CAPTURE_FILE="netlink-traffic.pcap"           # Output file for captured traffic
DURATION=30                                   # Capture duration in seconds (default: 30s)
TCPDUMP_OPTS="-i $INTERFACE -w $CAPTURE_FILE" # tcpdump options

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (use sudo).${NC}"
    exit 1
fi

# Function to check if a command succeeded
check_status() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: $1 failed.${NC}"
        exit 1
    fi
}

# Function to clean up
cleanup() {
    echo "Cleaning up..."
    ip link set "$INTERFACE" down 2>/dev/null
    ip link del "$INTERFACE" 2>/dev/null
    rmmod nlmon 2>/dev/null
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null
    fi
    echo -e "${GREEN}Cleanup complete.${NC}"
}

# Trap Ctrl+C and exit to ensure cleanup
trap cleanup EXIT INT

# Check if nlmon module is available
if ! modinfo nlmon >/dev/null 2>&1; then
    echo -e "${RED}Error: nlmon module not found. Ensure your kernel supports it.${NC}"
    exit 1
fi

# Load nlmon module
echo "Loading nlmon module..."
modprobe nlmon
check_status "Loading nlmon module"

# Create nlmon interface
echo "Creating $INTERFACE interface..."
ip link add name "$INTERFACE" type nlmon
check_status "Creating $INTERFACE interface"

# Bring interface up
echo "Bringing $INTERFACE up..."
ip link set "$INTERFACE" up
check_status "Bringing $INTERFACE up"

# Verify interface is up
if ! ip link show "$INTERFACE" | grep -q "UP"; then
    echo -e "${RED}Error: $INTERFACE failed to come up.${NC}"
    cleanup
    exit 1
fi
echo -e "${GREEN}$INTERFACE is up.${NC}"

# Start tcpdump in the background
echo "Starting tcpdump to capture traffic for ${DURATION} seconds..."
tcpdump $TCPDUMP_OPTS &
TCPDUMP_PID=$!
check_status "Starting tcpdump"

# Wait for specified duration
sleep "$DURATION"

# Stop tcpdump
echo "Stopping tcpdump..."
kill "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null
TCPDUMP_PID=""
echo -e "${GREEN}Capture saved to $CAPTURE_FILE.${NC}"

# Cleanup (handled by trap, but explicit call here for clarity)
cleanup

# Instructions for analysis
echo "To analyze the captured traffic:"
echo "  - With tcpdump: tcpdump -r $CAPTURE_FILE"
echo "  - With Wireshark: wireshark $CAPTURE_FILE &"
echo "Done!"
