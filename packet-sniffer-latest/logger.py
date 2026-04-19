"""
logger.py — JSON Packet Logger for Packet Sniffer
Writes each captured packet as a newline-delimited JSON record (NDJSON).
"""

import json
import os
from datetime import datetime


class PacketLogger:
    """
    Logs structured packet data to a .json file in NDJSON format.
    Each line in the output file is a valid, self-contained JSON object.
    This makes the file easy to stream, grep, and load into tools like jq or pandas.
    """

    def __init__(self, filepath: str):
        self.filepath    = filepath
        self.total       = 0
        self._session_ts = datetime.now().isoformat()

        # Write a session-start header as the very first line
        header = {
            '__type':    'session_start',
            'timestamp': self._session_ts,
            'file':      os.path.abspath(filepath),
        }
        with open(self.filepath, 'w', encoding='utf-8') as f:
            f.write(json.dumps(header) + '\n')

    # ─────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────

    def log(self, packet: dict) -> None:
        """
        Append a single packet record to the log file.
        Automatically injects 'timestamp' and 'packet_number' fields.
        """
        self.total += 1
        record = {
            '__type':        'packet',
            'packet_number': self.total,
            'timestamp':     datetime.now().isoformat(),
        }
        record.update(packet)
        self._write(record)

    def close(self) -> None:
        """Write a session-end summary record."""
        footer = {
            '__type':        'session_end',
            'timestamp':     datetime.now().isoformat(),
            'total_packets': self.total,
        }
        self._write(footer)

    # ─────────────────────────────────────────
    #  Internal helpers
    # ─────────────────────────────────────────

    def _write(self, record: dict) -> None:
        """Serialize record to JSON and append to the log file."""
        try:
            with open(self.filepath, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, default=str) + '\n')
        except OSError as exc:
            # Non-fatal — print warning but don't crash the sniffer
            print(f'[logger] Could not write to {self.filepath}: {exc}')
