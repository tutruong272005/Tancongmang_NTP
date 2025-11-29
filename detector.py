#!/usr/bin/env python3
"""
detector.py - NTP (monlist) flood detector (IDS-style)
Author: assistant (adapted for user's lab)
Purpose: sniff UDP/123, detect monlist payload and traffic spikes, log & alert.
SAFE: this script only sniffs/analyses; it does NOT send packets.
"""

import argparse
import logging
import json
import csv
import signal
import sys
import threading
import time
from collections import Counter, deque, defaultdict
from datetime import datetime
from typing import Deque, Dict, Tuple

from scapy.all import sniff, UDP, Raw, IP, IPv6, conf

# --- Configuration defaults ---
DEFAULT_WINDOW = 5            # sliding window in seconds to compute metrics
DEFAULT_INTERVAL = 1         # update interval (seconds)
DEFAULT_PPS_THRESHOLD = 200  # packets/sec threshold for alert
DEFAULT_SRC_THRESHOLD = 50   # unique source IPs threshold in window
DEFAULT_MONLIST_THRESHOLD = 50  # monlist pkts/sec threshold

MONLIST_PATTERN = b"\x17\x00\x03\x2a"  # NTP v2 monlist pattern (request)


# --- Helper logger setup ---
def setup_logger(verbose: bool):
    logger = logging.getLogger("NTPDetector")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh = logging.FileHandler("ntp_detector.log")
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# --- Detector class ---
class NTPDetector:
    def __init__(
        self,
        interface: str = None,
        window: int = DEFAULT_WINDOW,
        interval: int = DEFAULT_INTERVAL,
        pps_threshold: int = DEFAULT_PPS_THRESHOLD,
        src_threshold: int = DEFAULT_SRC_THRESHOLD,
        monlist_threshold: int = DEFAULT_MONLIST_THRESHOLD,
        json_out: str = None,
        csv_out: str = None,
        verbose: bool = False,
    ):
        self.iface = interface
        self.window = window
        self.interval = interval
        self.pps_threshold = pps_threshold
        self.src_threshold = src_threshold
        self.monlist_threshold = monlist_threshold
        self.json_out = json_out
        self.csv_out = csv_out
        self.verbose = verbose

        self.logger = setup_logger(verbose)

        # sliding window queues: timestamps of packets and monlist packets
        self.packet_times: Deque[float] = deque()
        self.monlist_times: Deque[float] = deque()

        # per-window source IP counter
        self.src_counter: Counter = Counter()

        # history for output
        self.history = []

        # thread control
        self.running = threading.Event()
        self.running.set()

        # lock for shared structures
        self.lock = threading.Lock()

        # sniff thread placeholder
        self.sniff_thread = None

    def start(self):
        self.logger.info("Starting NTPDetector")
        if self.iface:
            self.logger.info(f"Listening on interface: {self.iface}")
        else:
            self.logger.info("Listening on all available interfaces")

        # start stats thread
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()

        # start sniffing in main thread or in separate thread
        self.sniff_thread = threading.Thread(target=self._sniff, daemon=True)
        self.sniff_thread.start()

        # block until interrupted
        try:
            while self.running.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.logger.info("KeyboardInterrupt received, stopping detector...")
            self.stop()

        # join threads
        self.sniff_thread.join(timeout=2)
        stats_thread.join(timeout=2)
        self._finalize_outputs()

    def stop(self):
        self.running.clear()

    def _sniff(self):
        # Use BPF filter to reduce kernel->user overhead
        bpf = "udp port 123"
        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.running.is_set(),
            )
        except Exception as e:
            self.logger.error(f"Sniffer error: {e}")
            self.running.clear()

    def _packet_handler(self, pkt):
        # Called for each captured packet (from scapy)
        ts = time.time()

        src_ip = None
        payload = b""

        # extract source IP and payload safely
        try:
            if IP in pkt:
                src_ip = pkt[IP].src
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
            else:
                src_ip = "<unknown>"

            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
        except Exception:
            # ignore bad packets
            return

        is_monlist = MONLIST_PATTERN in payload

        with self.lock:
            # global packet time queue
            self.packet_times.append(ts)
            # increment src counter
            self.src_counter[src_ip] += 1
            if is_monlist:
                self.monlist_times.append(ts)

        # optional verbose per-packet log
        if self.verbose:
            self.logger.debug(
                f"Pkt: src={src_ip} monlist={is_monlist} len={len(payload)}"
            )

    def _prune_old(self, now: float):
        # remove events older than window
        cutoff = now - self.window
        with self.lock:
            while self.packet_times and self.packet_times[0] < cutoff:
                self.packet_times.popleft()
            while self.monlist_times and self.monlist_times[0] < cutoff:
                self.monlist_times.popleft()

            # prune src_counter: rebuild from scratch using remaining packets? simpler: rebuild from packet captures not stored
            # We don't store per-packet src list long-term to save memory. Here we'll remove zero-counts by filtering.
            # For accurate per-window unique count, a small local reconstruction would be needed; instead we expire counters heuristically:
            # If a source hasn't had increments in window, we cannot identify easily without storing per-packet src timestamps.
            # To keep correct unique sources, we maintain a timestamped list per src.
            # But for performance/simplicity, we will rebuild src_counter from packet_times not stored with src.
            # To implement accurate sliding window unique source counts, we maintain src_timestamps dict.

    def _stats_worker(self):
        # For accurate unique-src-in-window, maintain src->deque timestamps
        src_ts: Dict[str, Deque[float]] = defaultdict(deque)

        while self.running.is_set():
            now = time.time()
            # transfer current packet info into src_ts and cleanup
            with self.lock:
                # drain the packet_times and monlist_times are timestamps only; but we need per-packet src timestamps:
                # To be accurate, we must have recorded src with time. Let's restructure: store a small ring buffer of (ts, src, is_monlist).
                pass
            # We'll reimplement a correct approach: use event_buffer to hold recent events (ts, src, is_monlist)
            break  # break to rework correct implementation below

        # Rework: exit worker and start new properly implemented method
        self._stats_worker_v2()

    def _stats_worker_v2(self):
        """
        Correct sliding-window implementation:
        maintain event_buffer: deque of (ts, src, is_monlist)
        compute metrics from that.
        """
        event_buffer: Deque[Tuple[float, str, bool]] = deque()

        self.logger.info("Stats worker started")
        while self.running.is_set():
            start = time.time()

            # Move recent captured data into event_buffer
            # Unfortunately packet_handler didn't append (ts,src,is_monlist) previously; adapt: we'll maintain such buffer now.
            # To avoid double-capture issues, modify packet_handler to also append to self._event_tmp buffer if exists.
            # Implement event transfer: if packet_handler wrote to self._event_tmp, drain it here.
            if not hasattr(self, "_event_tmp"):
                self._event_tmp = deque()
            # drain tmp
            with self.lock:
                while self._event_tmp:
                    event_buffer.append(self._event_tmp.popleft())

            # prune old events beyond window
            cutoff = time.time() - self.window
            while event_buffer and event_buffer[0][0] < cutoff:
                event_buffer.popleft()

            # compute metrics
            total_pkts = len(event_buffer)
            monlist_pkts = sum(1 for (_, _, is_mon) in event_buffer if is_mon)
            unique_srcs = len({src for (_, src, _) in event_buffer})

            pps = total_pkts / max(1.0, self.window)
            monlist_pps = monlist_pkts / max(1.0, self.window)

            # prepare snapshot
            snapshot = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "total_pkts_window": total_pkts,
                "pps": round(pps, 2),
                "monlist_pkts_window": monlist_pkts,
                "monlist_pps": round(monlist_pps, 2),
                "unique_srcs_window": unique_srcs,
            }

            # store history
            self.history.append(snapshot)

            # Logging and alerting
            alert_msgs = []
            if pps > self.pps_threshold:
                alert_msgs.append(f"PPS {pps:.1f} > threshold {self.pps_threshold}")
            if unique_srcs > self.src_threshold:
                alert_msgs.append(
                    f"Unique sources {unique_srcs} > threshold {self.src_threshold}"
                )
            if monlist_pps > self.monlist_threshold:
                alert_msgs.append(
                    f"Monlist PPS {monlist_pps:.1f} > threshold {self.monlist_threshold}"
                )

            # Print summary line
            summary = (
                f"[{snapshot['timestamp']}] PPS={snapshot['pps']} "
                f"monlist_pks/s={snapshot['monlist_pps']} uniq_srcs={unique_srcs}"
            )
            if alert_msgs:
                self.logger.warning(summary + "  ALERT: " + " ; ".join(alert_msgs))
            else:
                self.logger.info(summary)

            # optionally save to JSON/CSV incrementally
            if self.json_out:
                try:
                    with open(self.json_out, "a") as jf:
                        jf.write(json.dumps(snapshot) + "\n")
                except Exception:
                    self.logger.exception("Failed to write JSON output")

            if self.csv_out:
                try:
                    write_header = False
                    try:
                        with open(self.csv_out, "r"):
                            pass
                    except FileNotFoundError:
                        write_header = True
                    with open(self.csv_out, "a", newline="") as cf:
                        writer = csv.DictWriter(
                            cf,
                            fieldnames=[
                                "timestamp",
                                "total_pkts_window",
                                "pps",
                                "monlist_pkts_window",
                                "monlist_pps",
                                "unique_srcs_window",
                            ],
                        )
                        if write_header:
                            writer.writeheader()
                        writer.writerow(snapshot)
                except Exception:
                    self.logger.exception("Failed to write CSV output")

            # sleep until next interval (account for processing time)
            elapsed = time.time() - start
            to_sleep = max(0.0, self.interval - elapsed)
            time.sleep(to_sleep)

        self.logger.info("Stats worker exiting")

    # Adjusted packet handler to store event tuples (ts,src,is_monlist) in a small tmp buffer
    def _packet_handler_with_events(self, pkt):
        ts = time.time()
        src_ip = "<unknown>"
        payload = b""
        try:
            if IP in pkt:
                src_ip = pkt[IP].src
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
        except Exception:
            return
        is_mon = MONLIST_PATTERN in payload
        # push event into a small temp buffer
        if not hasattr(self, "_event_tmp"):
            self._event_tmp = deque()
        with self.lock:
            self._event_tmp.append((ts, src_ip, is_mon))
        if self.verbose:
            self.logger.debug(f"Captured pkt src={src_ip} monlist={is_mon}")

    # We'll use this correct packet handler when starting sniff
    def _sniff(self):
        bpf = "udp port 123"
        # ensure packet handler exists
        handler = self._packet_handler_with_events
        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=handler,
                store=False,
                stop_filter=lambda x: not self.running.is_set(),
            )
        except Exception as e:
            self.logger.exception("Sniffer exception")
            self.running.clear()

    def _finalize_outputs(self):
        # On stop, dump history to json/csv full file if requested
        if not self.history:
            self.logger.info("No history to dump")
            return
        if self.json_out:
            try:
                with open(self.json_out + ".full.json", "w") as jf:
                    json.dump(self.history, jf, indent=2)
                self.logger.info(f"Full JSON history written to {self.json_out}.full.json")
            except Exception:
                self.logger.exception("Failed to write full JSON history")
        if self.csv_out:
            try:
                with open(self.csv_out + ".full.csv", "w", newline="") as cf:
                    writer = csv.DictWriter(
                        cf,
                        fieldnames=list(self.history[0].keys()),
                    )
                    writer.writeheader()
                    for row in self.history:
                        writer.writerow(row)
                self.logger.info(f"Full CSV history written to {self.csv_out}.full.csv")
            except Exception:
                self.logger.exception("Failed to write full CSV history")


# --- CLI parsing ---
def parse_args():
    p = argparse.ArgumentParser(description="NTP Monlist Flood Detector (lab-safe IDS)")
    p.add_argument(
        "-i", "--interface", help="Interface to capture (name). If omitted listens on all."
    )
    p.add_argument(
        "-w", "--window", type=int, default=DEFAULT_WINDOW, help="Sliding window seconds"
    )
    p.add_argument(
        "-t",
        "--pps-threshold",
        type=int,
        default=DEFAULT_PPS_THRESHOLD,
        help="Packets/sec threshold for alert",
    )
    p.add_argument(
        "-s",
        "--src-threshold",
        type=int,
        default=DEFAULT_SRC_THRESHOLD,
        help="Unique source IPs threshold in window",
    )
    p.add_argument(
        "-m",
        "--monlist-threshold",
        type=int,
        default=DEFAULT_MONLIST_THRESHOLD,
        help="Monlist packets/sec threshold for alert",
    )
    p.add_argument("--json", help="Append per-interval JSON lines to this file")
    p.add_argument("--csv", help="Append per-interval CSV to this file")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()


def main():
    args = parse_args()
    detector = NTPDetector(
        interface=args.interface,
        window=args.window,
        interval=1,
        pps_threshold=args.pps_threshold,
        src_threshold=args.src_threshold,
        monlist_threshold=args.monlist_threshold,
        json_out=args.json,
        csv_out=args.csv,
        verbose=args.verbose,
    )

    # Graceful shutdown on signals
    def _stop(signum, frame):
        detector.logger.info(f"Signal {signum} received — stopping")
        detector.stop()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    # Run detector
    detector.start()


if __name__ == "__main__":
    main()
