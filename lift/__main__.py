import argparse
import concurrent.futures
import ipaddress
import json
import logging
import pathlib
import sys
import threading
import traceback

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from random import Random
from typing import *

try:
    import ctypes
    ctypes.CDLL('libgcc_s.so.1')
except:
    pass

from lift import lift


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="lift", description="Low Impact Identification Tool")

    # runtime options
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="specifies the output verbosity (can specify multiple times)")
    parser.add_argument("-c", "--concurrency", type=int, default=1,
                        help="specifies how many concurrent scans to run (default: 1)")
    parser.add_argument("-P", "--partition", type=str, default='1/1',
                        help="specifies which partition of the data to scan (default: 1/1)")
    parser.add_argument("-d", "--discreet", action="store_true",
                        help="try to avoid scanning the same IP multiple times in quick succession")

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
                        help="specifies the format of the --ifile argument (default: standard)")

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

    try:
        part, whole = args.partition.split('/', maxsplit=1)
        part, whole = int(part, base=10), int(whole, base=10)
        assert 0 < part <= whole
    except:
        parser.error("--partition must specify the current partition (P) "
                     "and the total number of partitions (N) as P/N (example: 2/4)")

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
            for ip in ipaddress.ip_network(subnet, False):
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

    if args.discreet:
        # use a fixed seed so that the target list is stable across multiple runs
        Random(0x3A43F693).shuffle(targets)

    part, whole = args.partition.split('/', maxsplit=1)
    part, whole = int(part, base=10), int(whole, base=10)
    if part > 1 or whole > 1:
        targets = [t for (i, t) in enumerate(targets) if (i % whole) == (part - 1)]

    return targets


def check_target(args, target, output_handler):
    if not args.recurse and not args.recon:
        if target.port not in [443, 8443]:
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


def panic(exc_type, exc_obj, exc_tb):
    if type(exc_obj) == SystemExit:
        return
    traceback.print_exception(exc_type, exc_obj, exc_tb, file=sys.stdout)
    logging.exception(f"{type(exc_obj).__name__}: {exc_obj}", exc_info=(exc_type, exc_obj, exc_tb))


def main():
    sys.excepthook = panic
    threading.excepthook = panic

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
    executor = ThreadPoolExecutor(max_workers=args.concurrency)

    try:
        futures = []

        for target in targets:
            futures.append(executor.submit(check_target, args, target, output_handler))

        for result in concurrent.futures.as_completed(futures):
            result.result()

    except KeyboardInterrupt:
        return 0
    except Exception as e:
        traceback.print_exception(*sys.exc_info(), file=sys.stdout)
        logging.exception(f"{type(e).__name__}: {e}")
        return 1
    finally:
        print("Finishing scans...")
        executor.shutdown(cancel_futures=True)


if __name__ == "__main__":
    main()
