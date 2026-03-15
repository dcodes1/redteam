#!/usr/bin/env python3
"""
CLI entry point for FogJack.
"""
import sys
import click

from fogjack.core.config import load_config
from fogjack.core.logger import init_logger
from fogjack.core.loader import ModuleLoader


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option('-c', '--config', 'config_path', default='~/.fogjack/config.yml',
              help='Path to the configuration file')
@click.option('-v', '--verbose', count=True,
              help='Increase output verbosity (can be stacked)')
@click.pass_context
def cli(ctx, config_path, verbose):
    """
    FogJack: Offensive security framework for network, cloud, and post-exploitation.
    """
    # Load configuration and initialize logging
    config = load_config(config_path)
    init_logger(verbosity=verbose)

    # Initialize module loader
    loader = ModuleLoader(config=config)

    # Store objects in context for subcommands
    ctx.obj = {
        'config': config,
        'loader': loader,
    }


# ---------------------- Scan Commands ----------------------
@cli.group()
@click.pass_context
def scan(ctx):
    """Run reconnaissance modules"""
    pass


@scan.command('network')
@click.option('-t', '--targets', required=True,
              help='Target IP addresses or CIDR ranges (comma-separated)')
@click.pass_context
def scan_network(ctx, targets):
    """Perform network scanning"""
    module = ctx.obj['loader'].get_module('network_scan')
    module.run(targets=targets.split(','))


@scan.group('cloud')
@click.pass_context
def scan_cloud(ctx):
    """Run cloud enumeration and misconfiguration checks"""
    pass


@scan_cloud.command('aws')
@click.option('-p', '--profile', default=None,
              help='AWS CLI profile name')
@click.pass_context
def scan_cloud_aws(ctx, profile):
    """Enumerate AWS resources and check misconfigurations"""
    aws_mod = ctx.obj['loader'].get_module('aws')
    aws_mod.authenticate(profile)
    aws_mod.enumerate_resources()
    aws_mod.check_misconfig()


@scan_cloud.command('azure')
@click.option('-c', '--credentials', default=None,
              help='Azure credentials/configuration reference')
@click.pass_context
def scan_cloud_azure(ctx, credentials):
    """Enumerate Azure resources and check misconfigurations"""
    az_mod = ctx.obj['loader'].get_module('azure')
    az_mod.authenticate(credentials)
    az_mod.enumerate_resources()
    az_mod.check_misconfig()


@scan_cloud.command('gcp')
@click.option('-k', '--keyfile', default=None,
              help='Path to GCP service account JSON keyfile')
@click.pass_context
def scan_cloud_gcp(ctx, keyfile):
    """Enumerate GCP resources and check misconfigurations"""
    gcp_mod = ctx.obj['loader'].get_module('gcp')
    gcp_mod.authenticate(keyfile)
    gcp_mod.enumerate_resources()
    gcp_mod.check_misconfig()


# ---------------------- Exploit Commands ----------------------
@cli.group()
@click.pass_context
def exploit(ctx):
    """Trigger exploitation modules"""
    pass


@exploit.command('aws-iam-escape')
@click.option('-r', '--role', 'role_name', required=True,
              help='IAM role ARN or name to abuse')
@click.option('-p', '--profile', default=None,
              help='AWS CLI profile name')
@click.pass_context
def exploit_aws_iam(ctx, role_name, profile):
    """Exploit AWS IAM role abuse"""
    aws_mod = ctx.obj['loader'].get_module('aws')
    aws_mod.authenticate(profile)
    aws_mod.exploit_iam(role_name=role_name)


# ---------------- Post-Exploitation Commands -------------------
@cli.group('post-exploit')
@click.pass_context
def post_exploit(ctx):
    """Run post-exploitation workflows"""
    pass


@post_exploit.command('persistence')
@click.option('-t', '--target', 'target_id', required=True,
              help='Identifier of compromised target (e.g., instance ID)')
@click.pass_context
def post_persistence(ctx, target_id):
    """Establish persistence on a compromised host"""
    mod = ctx.obj['loader'].get_module('persistence')
    mod.setup_persistence(target=target_id)


@post_exploit.command('priv-esc')
@click.option('-t', '--target', 'target_id', required=True,
              help='Identifier of compromised target')
@click.pass_context
def post_priv_esc(ctx, target_id):
    """Perform local privilege escalation"""
    mod = ctx.obj['loader'].get_module('priv_esc')
    mod.escalate_privileges(target=target_id)


@post_exploit.command('lateral')
@click.option('-t', '--target', 'target_id', required=True,
              help='Identifier of compromised host to move laterally from')
@click.pass_context
def post_lateral(ctx, target_id):
    """Attempt lateral movement from a compromised host"""
    mod = ctx.obj['loader'].get_module('lateral')
    mod.move_laterally(source=target_id)


if __name__ == '__main__':
    cli()
