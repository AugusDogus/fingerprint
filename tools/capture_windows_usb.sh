#!/usr/bin/env bash
set -euo pipefail

vid="27c6"
pid="5584"

if ! command -v dumpcap >/dev/null 2>&1; then
    echo "dumpcap is missing; install the Arch package wireshark-cli" >&2
    exit 1
fi

device_line="$(lsusb -d "${vid}:${pid}" | head -n 1)"
if [[ -z "${device_line}" ]]; then
    echo "Goodix ${vid}:${pid} is not currently connected" >&2
    exit 1
fi

bus="$(awk '{print $2}' <<<"${device_line}")"
device="$(awk '{gsub(":", "", $4); print $4}' <<<"${device_line}")"
bus_number="$((10#${bus}))"

output="${1:-captures/windows-init-$(date +%Y%m%d-%H%M%S).pcapng}"
output="$(realpath -m "${output}")"
mkdir -p "$(dirname "${output}")"
temporary_output="/tmp/goodix-windows-usb-$(date +%Y%m%d-%H%M%S).pcapng"

cleanup() {
    if [[ -e "${temporary_output}" ]]; then
        sudo chown "$(id -u):$(id -g)" "${temporary_output}" 2>/dev/null || true
        mv -f "${temporary_output}" "${output}" 2>/dev/null || true
        echo "Capture saved to ${output}."
    fi
}
trap cleanup EXIT INT TERM

echo "Capturing USB bus ${bus_number}; Goodix is currently device ${device}."
echo "Writing ${output}. Stop capture with Ctrl-C after Windows initializes the reader."

sudo modprobe usbmon
sudo dumpcap -i "usbmon${bus_number}" -s 0 -w "${temporary_output}"
