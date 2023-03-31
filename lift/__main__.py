import argparse
import concurrent.futures
import ipaddress
import json
import logging
import pathlib
import sys

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import *

from lift import lift


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="lift", description="Low Impact Identification Tool")

    # runtime options
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="specifies the output verbosity (can specify multiple times)")
    parser.add_argument("-c", "--concurrency", type=int, default=1,
                        help="specifies how many concurrent scans to run")

    # target options
    parser.add_argument("-i", "--ip", action="append", type=str,
                         help="specifies an IP address to scan (can specify multiple times)")
    parser.add_argument("-s", "--subnet", action="append", type=str,
                         help="specifies a CIDR subnet to scan (can specify multiple times)")
    parser.add_argument("-f", "--ifile", type=str,
                         help="specifies a file containing targets to scan")
    parser.add_argument("-p", "--port", type=int, action="append",
                        help="specifies a port to scan (can specify multiple times)")
    parser.add_argument("-t", "--filetype", choices=["standard", "withport", "shodan"], default="standard",
                        help="specifies the format of the --ifile argument")

    # scanning options
    parser.add_argument("-S", "--ssl", action="store_true",
                        help="do SSL checks only")
    parser.add_argument("-r", "--recurse", action="store_true",
                        help="test for recursion and amplification")
    parser.add_argument("-R", "--recon", action="store_true",
                        help="run all tests")

    # output options
    parser.add_argument("-o", "--ofile",
                        help="specifies the output file (optional)")
    parser.add_argument("-e", "--efile", default="lift.error",
                        help="specifies the error file (default: lift.error)")

    args = parser.parse_args()

    if not args.ip and not args.subnet and not args.ifile:
        parser.error("at least one of --ip, --subnet, or --ifile is required")

    if args.port and args.filetype == "withport":
        parser.error("--port cannot be specified when --filetype is set to \"withport\"")
    elif not args.port:
        parser.error("--port is required unless --filetype is set to \"withport\"")

    return args


@dataclass
class Target:
    ip: str
    port: int


def make_target_list(args) -> List[Target]:
    targets = []

    if isinstance(args.ip, list):
        for ip in args.ip:
            for port in args.port:
                targets.append(Target(str(ipaddress.ip_address(ip)), int(port)))

    if isinstance(args.subnet, list):
        for subnet in args.subnet:
            for ip in ipaddress.ip_network(subnet):
                for port in args.port:
                    targets.append(Target(str(ipaddress.ip_address(ip)), int(port)))

    if isinstance(args.ifile, str) and isinstance(args.filetype, str):
        ifile = pathlib.Path(args.ifile).read_text()

        if args.filetype == "standard":
            for ip in [l.strip() for l in ifile.splitlines() if l.strip()]:
                for port in args.port:
                    targets.append(Target(str(ipaddress.ip_address(ip)), int(port)))

        if args.filetype == "withport":
            for ip in [l.strip() for l in ifile.splitlines() if l.strip()]:
                ip, port = ip.strip("[]").rsplit(":", maxsplit=1)
                targets.append(Target(str(ipaddress.ip_address(ip)), int(port)))

        if args.filetype == "shodan":
            js = json.loads(ifile)
            for port in args.port:
                targets.append(Target(str(ipaddress.ip_address(js["ip_str"])), int(port)))

    return targets


def check_target(args, target, output_handler):
    if not args.recurse and not args.recon:
        if target.port in [80, 8080, 81, 88, 8000, 8888, 7547, 8081]:
            lift.getheaders(target.ip, target.port, output_handler)
        else:
            lift.testips(target.ip, target.port, args.ssl, output_handler)
    elif args.recon:
        lift.testips(target.ip, target.port, args.ssl, output_handler)
        lift.recurse_dns_check(target.ip, args.verbose)
        lift.recurse_ssdp_check(target.ip, args.verbose)
        lift.ntp_monlist_check(target.ip, args.verbose)
    elif args.recurse:
        if target.port == 53:
            lift.recurse_dns_check(target.ip, args.verbose)
        elif target.port == 1900:
            lift.recurse_ssdp_check(target.ip, args.verbose)
        elif target.port == 123:
            lift.ntp_monlist_check(target.ip, args.verbose)
        else:
            lift.recurse_dns_check(target.ip, args.verbose)
            lift.recurse_ssdp_check(target.ip, args.verbose)
            lift.ntp_monlist_check(target.ip, args.verbose)
    return target


def main():
    args = parse_args()

    output_handler = lift.Output(
        verbosity=args.verbose,
        output_file=args.ofile
    )

    logging.basicConfig(
        filename=args.efile,
        level=logging.DEBUG,
        format="%(asctime)s %(name)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    targets = make_target_list(args)

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        try:
            futures = []

            for target in targets:
                futures.append(executor.submit(check_target, args, target, output_handler))

            for result in concurrent.futures.as_completed(futures):
                try:
                    result.result()
                except Exception as e:
                    print(f"Fatal error: {str(e)}")
                    logging.exception(e)
                finally:
                    executor.shutdown(cancel_futures=True)
                    sys.exit(1)
        except KeyboardInterrupt:
            print("Stopping scans...")
        finally:
            executor.shutdown(cancel_futures=True)
            sys.exit(0)


if __name__ == "__main__":
    main()
