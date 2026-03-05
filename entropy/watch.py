"""Watch mode — re-run scans on a schedule or when files change."""
from __future__ import annotations

import hashlib
import signal
import sys
import time
from pathlib import Path
from typing import Callable, List, Optional


class EntropyWatcher:
    """
    Re-runs entropy scans on a schedule (cron-like) or when a spec file changes.
    Emits webhook alerts on new findings.
    """

    def __init__(
        self,
        config,
        interval_seconds:  int = 300,
        watch_files:       Optional[List[str]] = None,
        on_new_findings:   Optional[Callable] = None,
        max_runs:          Optional[int] = None,
        webhook_url:       Optional[str] = None,
        slack_webhook:     Optional[str] = None,
    ):
        self.config           = config
        self.interval         = interval_seconds
        self.watch_files      = [Path(f) for f in (watch_files or [])]
        self.on_new_findings  = on_new_findings
        self.max_runs         = max_runs
        self.webhook_url      = webhook_url
        self.slack_webhook    = slack_webhook
        self._file_hashes:    dict = {}
        self._run_count:      int  = 0
        self._stop:           bool = False

        signal.signal(signal.SIGINT,  self._handle_stop)
        signal.signal(signal.SIGTERM, self._handle_stop)

    # ------------------------------------------------------------------

    def start(self) -> None:
        print(f"\n👁  Entropy watch mode — interval: {self.interval}s")
        print("   Press Ctrl-C to stop\n")

        while not self._stop:
            if self.max_runs and self._run_count >= self.max_runs:
                print(f"   Max runs ({self.max_runs}) reached. Stopping.")
                break

            changed = self._detect_file_changes()
            should_run = changed or self._run_count == 0

            if should_run:
                if changed:
                    print(f"  📝 File changed: {changed} — re-running scan")
                self._run_scan()
            else:
                print(f"  ⏳ Waiting {self.interval}s… (run #{self._run_count}, Ctrl-C to stop)")
                self._interruptible_sleep(self.interval)

    # ------------------------------------------------------------------

    def _run_scan(self) -> None:
        from entropy.core.orchestrator import EntropyRunner
        from entropy.history import FindingHistory

        self._run_count += 1
        print(f"\n{'='*55}")
        print(f"  🔄 Watch run #{self._run_count} — {time.strftime('%H:%M:%S')}")
        print(f"{'='*55}\n")

        try:
            runner = EntropyRunner(self.config)
            report = runner.run()

            # Diff against history
            history = FindingHistory()
            diff    = history.diff_with_last(report)
            history.save_run(report)

            print(f"\n  📊 {diff.summary}")

            if diff.new_findings:
                print(f"\n  🚨 {len(diff.new_findings)} NEW findings detected!")
                for f in diff.new_findings:
                    print(f"     [{f.severity.value.upper()}] {f.title} @ {f.endpoint}")

                # Callbacks
                if self.on_new_findings:
                    self.on_new_findings(diff.new_findings, report)

                if self.webhook_url:
                    self._send_webhook(diff, report)

                if self.slack_webhook:
                    self._send_slack(diff, report)

            if diff.fixed_findings:
                print(f"\n  ✅ {len(diff.fixed_findings)} findings resolved since last run")

        except Exception as exc:
            print(f"\n  ✗ Run failed: {exc}")

        print(f"\n  ⏳ Next run in {self.interval}s…")
        self._interruptible_sleep(self.interval)

    # ------------------------------------------------------------------

    def _detect_file_changes(self) -> Optional[str]:
        for path in self.watch_files:
            if not path.exists():
                continue
            current_hash = hashlib.md5(path.read_bytes()).hexdigest()
            if self._file_hashes.get(str(path)) != current_hash:
                self._file_hashes[str(path)] = current_hash
                return str(path)
        return None

    def _interruptible_sleep(self, seconds: int) -> None:
        """Sleep in 1s chunks so Ctrl-C is responsive."""
        for _ in range(seconds):
            if self._stop:
                break
            time.sleep(1)

    def _send_webhook(self, diff, report) -> None:
        import json
        import urllib.request

        payload = {
            "event":       "entropy.new_findings",
            "target":      report.target,
            "run_id":      report.id,
            "new_count":   len(diff.new_findings),
            "fixed_count": len(diff.fixed_findings),
            "findings": [
                {"severity": f.severity.value, "title": f.title, "endpoint": f.endpoint}
                for f in diff.new_findings[:10]
            ],
        }
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            self.webhook_url,
            data    = data,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            print(f"  ⚠ Webhook failed: {exc}")

    def _send_slack(self, diff, report) -> None:
        import json
        import urllib.request

        lines = [f"🚨 *Entropy* — {len(diff.new_findings)} new finding(s) on `{report.target}`"]
        for f in diff.new_findings[:5]:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                f.severity.value, "⚪"
            )
            lines.append(f"{emoji} [{f.severity.value.upper()}] {f.title} — `{f.endpoint}`")

        payload = {"text": "\n".join(lines)}
        data    = json.dumps(payload).encode()
        req     = urllib.request.Request(
            self.slack_webhook,
            data    = data,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            print(f"  ⚠ Slack webhook failed: {exc}")

    def _handle_stop(self, *_) -> None:
        print("\n  🛑 Stopping watch mode…")
        self._stop = True
