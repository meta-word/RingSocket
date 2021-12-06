#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright © 2021 MetaWord Inc
# Copyright © 2019-2021 William Budd

RANDOM_PORT_MIN = 1024
RANDOM_PORT_MAX = 65535

TEST_PATH = "/tmp/rst"

SHAM_IO = "rst_preload_sham_io.so"

CLIENT_ECHO = "rst_client_echo"
CLIENT_BROWSER = "rst_client.html"
CLIENT_BROWSER_DST = "/tmp/rs.html"

APP_ECHO = "rst_app_echo.so"
APP_STRESS = "rst_app_stress.so"

import argparse
import json
import pathlib
import random
import re
import shutil
import sys
import subprocess
import time

def getRandomPortNumber():
    """Generate a random TCP port to list on in order to avoid triggering
    EADDRINUSE errors that may occur when RingSocket calls bind() after a
    previous instance of RingSocket on the same port was recently terminated
    (which is an unavoidable consequence of TCP_WAIT states being mandated by
    the TCP protocol, and enforced by the Linux kernel network stack)."""
    while True:
        random_port = random.randrange(RANDOM_PORT_MIN, RANDOM_PORT_MAX + 1)
        out = subprocess.run(["ss", "-HOant"], capture_output=True, text=True)
        if out.stderr or not re.search(f":{random_port}", out.stdout):
            # The presence of a stderr string may indicate that iproute2's "ss"
            # utility isn't installed, in which case just try the port and
            # hope for the best. A regex search result of None should mean that
            # the port is in fact currently not in use, so try it out.
            return random_port

def launchRingSocket(log_level, port, includeShamIO, includeAutobahn, worker_c,
                     stressApp_c):
    subprocess.run(["sudo", "killall", "ringsocket"], capture_output=True)
    subprocess.run(["make"]).check_returncode()
    path = pathlib.Path(f"{TEST_PATH}/rst.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    conf = {
        "log_level": log_level,
        "worker_c": worker_c,
        "ports": [{"port_number": port, "is_unencrypted": True}],
        "apps": []
    }
    if includeShamIO:
        shutil.copy2(SHAM_IO, f"{TEST_PATH}")
        preloadEnv = f"LD_PRELOAD={TEST_PATH}/{SHAM_IO} "
    else:
        preloadEnv = ""
    if includeAutobahn:
        shutil.copy2(APP_ECHO, f"{TEST_PATH}")
        conf["apps"].append({
            "name": "Echo",
            "app_path": f"{TEST_PATH}/{APP_ECHO}",
            "endpoints": [{
                "endpoint_id": 1,
                "url": f"ws://localhost:{port}/echo"
            }]
        })
    for i in range(stressApp_c):
        shutil.copy2(APP_STRESS, f"{TEST_PATH}")
        conf["apps"].append({
            "name": f"Stress#{i + 1}",
            "app_path": f"{TEST_PATH}/{APP_STRESS}",
            "endpoints": [{
                "endpoint_id": i + 1,
                "url": f"ws://localhost:{port}/stress{i + 1}",
                "allowed_origins": ["file://"]
            }]
        })
    path.write_text(json.dumps(conf, indent=1) + '\n')
    out = subprocess.run(["sudo"] + ([preloadEnv[:-1]] if preloadEnv else []) +
        ["ringsocket", f"{TEST_PATH}/rst.json"])
    out.check_returncode()
    print(f"RingSocket launched with "
          f"\"sudo {preloadEnv}ringsocket {TEST_PATH}/rst.json\".")

def launchClientEcho(log_level, port, app_c, client_c):
    time.sleep(1)
    shutil.copy2(CLIENT_ECHO, f"{TEST_PATH}")
    path = pathlib.Path(f"{TEST_PATH}/{CLIENT_ECHO}.json")
    conf = {
        "log_level": log_level,
        "epoll_buf_elem_c": 1000,
        "rwbuf_size": 100000000,
        "urls": [f"ws://localhost:{port}/stress{i + 1}" for i in range(app_c)],
        "client_c": client_c
    }
    path.write_text(json.dumps(conf, indent=1) + '\n')
    out = subprocess.run([f"{TEST_PATH}/{CLIENT_ECHO}",
        f"{TEST_PATH}/{CLIENT_ECHO}.json"])
    out.check_returncode()
    print(f"Echo client launched with {client_c} clients for each of "
          f"{app_c} backend stress test apps.")

def launchClientBrowser(port):
    with open(CLIENT_BROWSER, "r") as f:
        client_html = f.read()
    sub_html = re.sub("PORT_PLACEHOLDER", f"{port}", client_html)
    with open(CLIENT_BROWSER_DST, "w") as f:
        f.write(sub_html)
    print(f"You can now open (or reload) file://{CLIENT_BROWSER_DST} in a "
          f"browser to interactively spawn any number of test client "
          f"connections. To shut the current RingSocket server instance down, "
          f"issue \"sudo killall ringsocket\" (or run this script again).")

def launchClientAutobahn(port):
    path = pathlib.Path(f"{TEST_PATH}/autobahn_config/fuzzingclient.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "outdir": "./reports",
        "servers": [{"url": f"ws://localhost:{port}/echo"}],
        "cases": ["*"],
        "exclude-cases": [
            # See https://github.com/crossbario/autobahn-testsuite/issues/101
            "2.10", "2.11", "5.19", "5.20"
        ],
    }, indent=1) + '\n')
    pathlib.Path(f"{TEST_PATH}/autobahn_reports").mkdir(exist_ok=True)
    out = subprocess.run(["docker", "run", "-it", "--rm",
        "-v", f"{TEST_PATH}/autobahn_config:/config",
        "-v", f"{TEST_PATH}/autobahn_reports:/reports",
        "--network=host",
        "--name", "fuzzingclient",
        "crossbario/autobahn-testsuite", "/usr/local/bin/wstest",
        "--mode", "fuzzingclient", "--spec", "/config/fuzzingclient.json"])
    out.check_returncode()
    REPORT_PATH = f"{TEST_PATH}/autobahn_reports/index.html"
    with open(REPORT_PATH, "r") as f:
        report = f.read()
    if re.search(".html\">fail</a>", report, re.IGNORECASE):
        print("RingSocket seems to have failed one or more included "
              "autobahn-testsuite cases.")
    else:
        print("Success: RingSocket seems to have passed all included "
              "autobahn-testsuite cases.")
    print(f"The complete report can be viewed at: file://{REPORT_PATH}")

def main():
    argp = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Test descriptions:\n"
               "\"stress\": Stress test RingSocket's concurrent IO handling "
                           "accross multiple backend app's by bouncing off "
                           "rs_echo_client.\n"
               "\"browser\": Interactively spawn WebSocket clients from a "
                            "browser to test RingSocket's IO handling.\n"
               "\"autobahn\": Test RingSocket's conformance to every aspect of "
                             "the WebSocket protocol (RFC 6455) through use of "
                             "a fuzzing client provided by crossbar.io's "
                             "autobahn-testsuite. Requires docker.")
    argp.add_argument("test",
        choices=("stress", "browser", "autobahn"),
        help="test to perform: see below.")
    argp.add_argument("--log",
        choices=("debug", "info", "notice", "warning", "error"),
        help="The minimum message importance level to log to syslog/journalctl")
    argp.add_argument("-p", "--port",
        type=int, choices=range(1, 65535), metavar="[1-65535]",
        help="TCP port on which RingSocket should listen for WebSocket "
             "client connections for testing purposes "
             "(defaults to a random non-privileged port)")
    argp.add_argument("-s", "--sham-io",
        action="store_true",
        help="use LD_PRELOAD=rs_preload_sham_io.so to inject simulated "
             "\"would block\" and partial read/write events in between "
             "RingSocket and the actual read() and write() calls")
    argp.add_argument("-w", "--worker_c",
        type=int, choices=range(1, 255), metavar="[1-255]",
        help="The number of worker threads the RingSocket process should "
             "spawn. Default: 1")
    argp.add_argument("--app_c",
        type=int, choices=range(1, 255), metavar="[1-255]",
        help="Stress test only: the number of backend stress test apps to "
             "deploy. Default: 1")
    argp.add_argument("--client_c",
        type=int, choices=range(1, 65535), metavar="[1-65535]",
        help="Stress test only: the number of echo clients to deploy per "
             "stress test backend app. Default: 1")
    
    if len(sys.argv) < 2:
        argp.print_help()
        argp.exit()
    args = argp.parse_args()
    
    if not args.log:
        args.log = "debug"

    if not args.port:
        args.port = getRandomPortNumber()
    
    if not args.worker_c:
        args.worker_c = 1

    if args.test == "stress":
        if not args.app_c:
            args.app_c = 1
        if not args.client_c:
            args.client_c = 1
    else:
        if args.app_c:
            parser.error('--app_c can only be set for mode "stress".')
        if args.client_c:
            parser.error('--client_c can only be set for mode "stress".')
        args.app_c = 0
        args.client_c = 0
    
    launchRingSocket(args.log, args.port, args.sham_io, args.test == "autobahn",
        args.worker_c, args.app_c)
    if args.test == "stress":
        launchClientEcho(args.log, args.port, args.app_c, args.client_c)
    elif args.test == "browser":
        launchClientBrowser(args.port)
    else:
        launchClientAutobahn(args.port)

if __name__ == "__main__":
    main()
