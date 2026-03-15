#!/usr/bin/env python3
"""
FogJack CLI entry point

Usage examples:
  python fogjack.py scan hosts -t 10.0.0.0/24
  python fogjack.py scan ports -t 10.0.0.5 -p 1-1024 --syn
  python fogjack.py scan vulns -i output/reports/last_scan.json
  python fogjack.py flag cloud --provider aws --profile default
  python fogjack.py post persist --technique cron --target 10.0.0.5
  python fogjack.py cloud aws --check s3-public --profile default
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import signal
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Local imports
try:
    from config import SETTINGS  # dict-like, optional
except Exception:
    SETTINGS = {}

try:
    from core.logger import get_logger
except Exception:
    # Lightweight fallback logger
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    def get_logger(name: str):
        return logging.getLogger(name)

try:
    from core.banner import show_banner
except Exception:
    def show_banner():
        print("FogJack | Offensive Cloud and Post Exploitation Toolkit")

import argparse

LOG = get_logger("fogjack")

# -------- helpers --------

def resolve_output_dir() -> Path:
    base = Path(SETTINGS.get("OUTPUT_DIR", "output"))
    base.mkdir(parents=True, exist_ok=True)
    (base / "reports").mkdir(parents=True, exist_ok=True)
    (base / "logs").mkdir(parents=True, exist_ok=True)
    (base / "loot").mkdir(parents=True, exist_ok=True)
    return base

def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def import_or_die(module_path: str, symbol: str):
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, symbol)
    except Exception as e:
        LOG.error("Required module not available: %s.%s (%s)", module_path, symbol, e)
        sys.exit(2)

def async_entry(coro):
    async def runner():
        return await coro
    return asyncio.run(runner())

def setup_signal_handlers(loop: asyncio.AbstractEventLoop):
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, loop.stop)
        except NotImplementedError:
            # Windows fallback
            pass

# -------- argparse layout --------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fogjack",
        description="FogJack CLI"
    )
    p.add_argument("--quiet", action="store_true", help="Reduce log verbosity")
    p.add_argument("--debug", action="store_true", help="Enable debug logs")
    p.add_argument("--config", help="Path to config file")

    sub = p.add_subparsers(dest="command", required=True)

    # scan group
    scan = sub.add_parser("scan", help="Network and vulnerability scanning")
    scan_sub = scan.add_subparsers(dest="scan_cmd", required=True)

    hosts = scan_sub.add_parser("hosts", help="Enumerate hosts in a range or subnet")
    hosts.add_argument("-t", "--target", required=True, help="CIDR or range")
    hosts.add_argument("--method", choices=["arp", "icmp", "tcp"], default="icmp")
    hosts.add_argument("--timeout", type=float, default=1.0)
    hosts.add_argument("--rate", type=int, default=500)

    ports = scan_sub.add_parser("ports", help="Scan ports and fingerprint services")
    ports.add_argument("-t", "--target", required=True, help="IP or hostname")
    ports.add_argument("-p", "--ports", default="1-1000", help="Port list or range")
    ports.add_argument("--syn", action="store_true", help="Use TCP SYN if supported")
    ports.add_argument("--workers", type=int, default=500)

    vulns = scan_sub.add_parser("vulns", help="Map services to CVEs and misconfigs")
    vulns.add_argument("-i", "--input", required=True, help="Service JSON from port scan")
    vulns.add_argument("-o", "--output", help="Report path")

    # flag group
    flag = sub.add_parser("flag", help="Quick checks that flag risky findings")
    flag_sub = flag.add_subparsers(dest="flag_cmd", required=True)

    cloud_flag = flag_sub.add_parser("cloud", help="Cloud config checks")
    cloud_flag.add_argument("--provider", choices=["aws", "azure", "gcp"], required=True)
    cloud_flag.add_argument("--profile", help="Provider profile or credential name")
    cloud_flag.add_argument("--region", help="Cloud region")
    cloud_flag.add_argument("-o", "--output", help="Report path")

    # post group
    post = sub.add_parser("post", help="Post exploitation helpers")
    post_sub = post.add_subparsers(dest="post_cmd", required=True)

    persist = post_sub.add_parser("persist", help="Set persistence on a target")
    persist.add_argument("--technique", required=True, help="Technique name")
    persist.add_argument("--target", required=True, help="IP or hostname")

    privesc = post_sub.add_parser("privesc", help="Privilege escalation checks")
    privesc.add_argument("--target", required=True)

    lateral = post_sub.add_parser("lateral", help="Lateral movement actions")
    lateral.add_argument("--from-host", required=True)
    lateral.add_argument("--to-host", required=True)
    lateral.add_argument("--method", choices=["ssh", "psexec", "winrm", "smb"], required=True)

    # cloud group
    cloud = sub.add_parser("cloud", help="Deep cloud exploitation")
    cloud_sub = cloud.add_subparsers(dest="cloud_cmd", required=True)

    aws = cloud_sub.add_parser("aws", help="AWS checks and abuse paths")
    aws.add_argument("--check", required=True, help="s3-public, iam-priv-esc, metadata, etc")
    aws.add_argument("--profile", help="AWS profile")
    aws.add_argument("--region", help="AWS region")

    azure = cloud_sub.add_parser("azure", help="Azure checks and abuse paths")
    azure.add_argument("--check", required=True, help="blob-public, spn-abuse, etc")
    azure.add_argument("--tenant", help="Tenant ID")
    azure.add_argument("--subscription", help="Subscription ID")

    gcp = cloud_sub.add_parser("gcp", help="GCP checks and abuse paths")
    gcp.add_argument("--check", required=True, help="sa-key-leak, storage-public, etc")
    gcp.add_argument("--project", help="Project ID")

    return p

# -------- command handlers --------

async def cmd_scan_hosts(args: argparse.Namespace) -> None:
    host_enum = import_or_die("modules.network_scanning.host_enum", "enumerate_hosts")
    results = await host_enum(
        target=args.target,
        method=args.method,
        timeout=args.timeout,
        rate=args.rate
    )
    outdir = resolve_output_dir() / "reports"
    path = outdir / f"hosts_{args.target.replace('/', '_')}.json"
    write_json(path, {"target": args.target, "method": args.method, "results": results})
    LOG.info("Host enumeration saved to %s", path)

async def cmd_scan_ports(args: argparse.Namespace) -> None:
    port_scan = import_or_die("modules.network_scanning.port_scan", "scan_ports")
    fingerprint = import_or_die("modules.network_scanning.port_scan", "fingerprint_services")
    services = await port_scan(
        target=args.target,
        ports=args.ports,
        syn=args.syn,
        workers=args.workers
    )
    profiled = await fingerprint(services)
    outdir = resolve_output_dir() / "reports"
    path = outdir / f"services_{args.target}.json"
    write_json(path, {"target": args.target, "services": profiled})
    LOG.info("Service scan saved to %s", path)

async def cmd_scan_vulns(args: argparse.Namespace) -> None:
    vuln_scan = import_or_die("modules.network_scanning.vuln_scan", "map_services_to_cves")
    with open(args.input, "r", encoding="utf-8") as f:
        services_doc = json.load(f)
    findings = await vuln_scan(services_doc.get("services", []))
    outdir = resolve_output_dir() / "reports"
    path = Path(args.output) if args.output else outdir / "vuln_report.json"
    write_json(path, {"findings": findings})
    LOG.info("Vulnerability report saved to %s", path)

async def cmd_flag_cloud(args: argparse.Namespace) -> None:
    audit = import_or_die("modules.vulnerability_flagging.cloud_config_audit", "audit_cloud")
    findings = await audit(provider=args.provider, profile=args.profile, region=args.region)
    outdir = resolve_output_dir() / "reports"
    path = Path(args.output) if args.output else outdir / f"{args.provider}_flag_report.json"
    write_json(path, {"provider": args.provider, "findings": findings})
    LOG.info("Cloud flag report saved to %s", path)

async def cmd_post_persist(args: argparse.Namespace) -> None:
    persist = import_or_die("modules.post_exploitation.persistence", "set_persistence")
    result = await persist(technique=args.technique, target=args.target)
    LOG.info("Persistence result: %s", result)

async def cmd_post_privesc(args: argparse.Namespace) -> None:
    privesc = import_or_die("modules.post_exploitation.privilege_escalation", "check_privesc")
    result = await privesc(target=args.target)
    LOG.info("Privilege escalation result: %s", result)

async def cmd_post_lateral(args: argparse.Namespace) -> None:
    lm = import_or_die("modules.post_exploitation.lateral_movement", "move_laterally")
    result = await lm(src=args.from_host, dst=args.to_host, method=args.method)
    LOG.info("Lateral movement result: %s", result)

async def cmd_cloud_aws(args: argparse.Namespace) -> None:
    aws_enum = import_or_die("modules.cloud_exploitation.aws_enum", "run_check")
    result = await aws_enum(check=args.check, profile=args.profile, region=args.region)
    LOG.info("AWS check %s -> %s", args.check, result)

async def cmd_cloud_azure(args: argparse.Namespace) -> None:
    azure_enum = import_or_die("modules.cloud_exploitation.azure_enum", "run_check")
    result = await azure_enum(check=args.check, tenant=args.tenant, subscription=args.subscription)
    LOG.info("Azure check %s -> %s", args.check, result)

async def cmd_cloud_gcp(args: argparse.Namespace) -> None:
    gcp_enum = import_or_die("modules.cloud_exploitation.gcp_enum", "run_check")
    result = await gcp_enum(check=args.check, project=args.project)
    LOG.info("GCP check %s -> %s", args.check, result)

# -------- main --------

def apply_log_level(args: argparse.Namespace):
    import logging
    if args.debug:
        for h in logging.getLogger().handlers:
            h.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
        LOG.debug("Debug logging enabled")
    elif args.quiet:
        for h in logging.getLogger().handlers:
            h.setLevel(logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)

def main(argv: Optional[list[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    show_banner()

    parser = build_parser()
    args = parser.parse_args(argv)
    apply_log_level(args)

    # Optional external config file
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            SETTINGS.update(cfg)
            LOG.info("Loaded config from %s", args.config)
        except Exception as e:
            LOG.warning("Failed to load config %s (%s)", args.config, e)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    setup_signal_handlers(loop)

    try:
        if args.command == "scan":
            if args.scan_cmd == "hosts":
                loop.run_until_complete(cmd_scan_hosts(args))
            elif args.scan_cmd == "ports":
                loop.run_until_complete(cmd_scan_ports(args))
            elif args.scan_cmd == "vulns":
                loop.run_until_complete(cmd_scan_vulns(args))

        elif args.command == "flag":
            if args.flag_cmd == "cloud":
                loop.run_until_complete(cmd_flag_cloud(args))

        elif args.command == "post":
            if args.post_cmd == "persist":
                loop.run_until_complete(cmd_post_persist(args))
            elif args.post_cmd == "privesc":
                loop.run_until_complete(cmd_post_privesc(args))
            elif args.post_cmd == "lateral":
                loop.run_until_complete(cmd_post_lateral(args))

        elif args.command == "cloud":
            if args.cloud_cmd == "aws":
                loop.run_until_complete(cmd_cloud_aws(args))
            elif args.cloud_cmd == "azure":
                loop.run_until_complete(cmd_cloud_azure(args))
            elif args.cloud_cmd == "gcp":
                loop.run_until_complete(cmd_cloud_gcp(args))

        else:
            parser.print_help()
            return 2

        return 0

    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        finally:
            loop.close()

if __name__ == "__main__":
    sys.exit(main())
