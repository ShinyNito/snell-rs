#!/usr/bin/env python3
"""Measure separately spawned Snell endpoints. Uses only the Python standard library.

python3 scripts/bench_isolated.py --binary target/release/snell-rs --mode download
python3 scripts/bench_isolated.py --binary target/release/snell-rs --mode mixed --connections 8
Each stdout line is a JSON result. Loopback results are not WAN measurements.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

CHUNK = bytes([0xA5]) * 65536
PSK = "0123456789abcdef"


def emit(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


def process_stats(pid: int) -> dict:
    """Do not confuse process memory with cgroup-wide kernel/socket charges."""
    root = Path(f"/proc/{pid}")
    result = {"pid": pid}
    if not root.exists():
        return result
    stat = (root / "stat").read_text().rsplit(")", 1)[1].split()
    result["cpu_seconds"] = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
    result["threads"] = int(stat[17])
    result["fds"] = len(list((root / "fd").iterdir()))
    with contextlib.suppress(OSError):
        for line in (root / "smaps_rollup").read_text().splitlines():
            key, sep, value = line.partition(":")
            if sep and key in {"Rss", "Pss", "Private_Clean", "Private_Dirty", "Anonymous", "AnonHugePages", "Swap"}:
                result[key + "_bytes"] = int(value.split()[0]) * 1024
    return result


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def read_bytes(reader: asyncio.StreamReader, size: int, verify: bool = True) -> None:
    while size:
        buf = await reader.read(min(size, len(CHUNK)))
        if not buf:
            raise EOFError("payload truncated")
        if verify and buf != CHUNK[:len(buf)]:
            raise ValueError("payload mismatch")
        size -= len(buf)


async def write_bytes(writer: asyncio.StreamWriter, size: int) -> None:
    while size:
        take = min(size, len(CHUNK))
        writer.write(CHUNK[:take])
        await writer.drain()
        size -= take


async def target_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            head = await reader.readexactly(9)
            mode, size = head[:1], struct.unpack("!Q", head[1:])[0]
            if mode == b"E":
                # Echo small warm-up and latency messages without a bulk allocation.
                while size:
                    buf = await reader.readexactly(min(size, len(CHUNK)))
                    writer.write(buf)
                    await writer.drain()
                    size -= len(buf)
            elif mode == b"U":
                await read_bytes(reader, size)
                writer.write(b"K")
                await writer.drain()
            elif mode == b"D":
                await write_bytes(writer, size)
            elif mode == b"B":
                await asyncio.gather(read_bytes(reader, size), write_bytes(writer, size))
                writer.write(b"K")
                await writer.drain()
            else:
                raise ValueError("unknown workload command")
    except (asyncio.IncompleteReadError, ConnectionError, EOFError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def target() -> None:
    server = await asyncio.start_server(target_connection, "127.0.0.1", 0)
    print(server.sockets[0].getsockname()[1], flush=True)
    async with server:
        await server.serve_forever()


async def connect(socks: int, dest: int):
    reader, writer = await asyncio.open_connection("127.0.0.1", socks)
    writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise ValueError("SOCKS5 method rejected")
        writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", dest))
        await writer.drain()
        head = await reader.readexactly(4)
        if head[:2] != b"\x05\x00":
            raise ValueError(f"SOCKS5 CONNECT rejected: {head!r}")
        if head[3] == 1:
            await reader.readexactly(6)
        elif head[3] == 4:
            await reader.readexactly(18)
        elif head[3] == 3:
            await reader.readexactly((await reader.readexactly(1))[0] + 2)
        else:
            raise ValueError("invalid SOCKS5 reply address")
        return reader, writer
    except BaseException:
        writer.close()
        raise


async def close_connection(reader, writer) -> None:
    if writer.can_write_eof():
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 5)
    writer.close()
    with contextlib.suppress(ConnectionError):
        await writer.wait_closed()


async def echo(reader, writer, size: int) -> float:
    start = time.perf_counter()
    writer.write(b"E" + struct.pack("!Q", size))
    await write_bytes(writer, size)
    await read_bytes(reader, size)
    return time.perf_counter() - start


async def bulk(reader, writer, mode: str, size: int) -> None:
    command = {"upload": b"U", "download": b"D", "duplex": b"B", "mixed": b"B"}[mode]
    writer.write(command + struct.pack("!Q", size))
    await writer.drain()
    if command == b"U":
        await write_bytes(writer, size)
    elif command == b"D":
        await read_bytes(reader, size)
    else:
        await asyncio.gather(write_bytes(writer, size), read_bytes(reader, size))
    if command != b"D" and await reader.readexactly(1) != b"K":
        raise ValueError("upload acknowledgement mismatch")


async def wait_listener(port: int, process: subprocess.Popen) -> None:
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError(f"endpoint exited with {process.returncode}")
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.025)
        else:
            writer.close()
            await writer.wait_closed()
            return
    raise TimeoutError("endpoint did not listen")


async def run_once(args, binary: Path, repeat: int) -> None:
    procs = []
    connections = []
    env = os.environ.copy()
    env["RUST_LOG"] = "error"
    if args.workers:
        env["TOKIO_WORKER_THREADS"] = str(args.workers)
    with tempfile.TemporaryDirectory(prefix="snell-bench-") as work:
        logs = open(Path(work) / "endpoints.log", "w+")
        try:
            peer = subprocess.Popen([sys.executable, __file__, "--target"], stdout=subprocess.PIPE, stderr=logs, env=env, text=True)
            procs.append(peer)
            dest = int(await asyncio.to_thread(peer.stdout.readline))
            server_port, socks = unused_port(), unused_port()
            server_addr, socks_addr = f"127.0.0.1:{server_port}", f"127.0.0.1:{socks}"
            # Explicit INI files avoid positional CLI ambiguity and keep the PSK out of argv.
            server_cfg = Path(work) / "server.conf"
            client_cfg = Path(work) / "client.conf"
            server_cfg.write_text(f"[snell-server]\nlisten = {server_addr}\npsk = {PSK}\nversion = {args.version}\n" + ("mode = unshaped\n" if args.unshaped else ""))
            client_cfg.write_text(f"[snell-client]\nlisten = {socks_addr}\nserver = {server_addr}\npsk = {PSK}\nversion = {'v6-unshaped' if args.unshaped else ('v6-default' if args.version == '6' else 'v' + args.version)}\nreuse = {'true' if args.reuse else 'false'}\n")
            server = subprocess.Popen([str(binary), "server", "--config", str(server_cfg)], stderr=logs, stdout=logs, env=env)
            procs.append(server)
            await wait_listener(server_port, server)
            client = subprocess.Popen([str(args.client_binary or binary), "client", "--config", str(client_cfg)], stderr=logs, stdout=logs, env=env)
            procs.append(client)
            await wait_listener(socks, client)
            initial = process_stats(server.pid)
            for _ in range(args.connections):
                connections.append(await connect(socks, dest))
            for reader, writer in connections:
                await echo(reader, writer, 65536 if args.mode != "idle" else 64)
            warm = process_stats(server.pid)
            latencies = []
            total = 0
            rounds = 0
            started = time.perf_counter()
            cpu_start = process_stats(server.pid)
            if args.mode == "idle":
                await asyncio.sleep(args.seconds)
            elif args.mode == "churn":
                for reader, writer in connections:
                    await close_connection(reader, writer)
                connections.clear()
                while time.perf_counter() - started < args.seconds:
                    t = time.perf_counter()
                    reader, writer = await connect(socks, dest)
                    await echo(reader, writer, 1024)
                    await close_connection(reader, writer)
                    latencies.append(time.perf_counter() - t)
                    rounds += 1
                    total += 1024
            else:
                async def load(reader, writer):
                    nonlocal total, rounds
                    while time.perf_counter() - started < args.seconds:
                        await bulk(reader, writer, args.mode, args.bytes)
                        total += args.bytes * (2 if args.mode in {"duplex", "mixed"} else 1)
                        rounds += 1
                async def ping():
                    reader, writer = await connect(socks, dest)
                    try:
                        while time.perf_counter() - started < args.seconds:
                            latencies.append(await echo(reader, writer, 64))
                            await asyncio.sleep(0.001)
                    finally:
                        await close_connection(reader, writer)
                tasks = [load(r, w) for r, w in connections]
                if args.mode == "mixed":
                    tasks.append(ping())
                await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - started
            active = process_stats(server.pid)
            for reader, writer in connections:
                await close_connection(reader, writer)
            connections.clear()
            await asyncio.sleep(args.settle)
            idle = process_stats(server.pid)
            latencies.sort()
            quantiles = {f"p{q}_ms": latencies[min(len(latencies) - 1, int((len(latencies) - 1) * q / 100))] * 1000 for q in (50, 95, 99)} if latencies else {}
            cpu = active.get("cpu_seconds", 0) - cpu_start.get("cpu_seconds", 0)
            emit(type="measurement", binary=str(binary), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), repeat=repeat, mode=args.mode, connections=args.connections,
                 protocol="6-unshaped" if args.unshaped else args.version, reuse=args.reuse, workers=args.workers,
                 payload_bytes=total, elapsed_seconds=elapsed, rounds=rounds, goodput_MiB_s=total / elapsed / 2**20,
                 server_cpu_seconds=cpu, server_cpu_seconds_per_GiB=cpu * 2**30 / total if total else None,
                 latency_samples=len(latencies), **quantiles, cold=initial, warm=warm, active=active, idle=idle)
        except BaseException:
            logs.flush()
            logs.seek(0)
            sys.stderr.write(logs.read())
            raise
        finally:
            for _, writer in connections:
                writer.close()
            for proc in reversed(procs):
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
            for proc in reversed(procs):
                try:
                    await asyncio.to_thread(proc.wait, timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    await asyncio.to_thread(proc.wait)
            logs.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--baseline", type=Path, help="Alternate baseline/candidate order on repeated runs")
    parser.add_argument("--client-binary", type=Path, help="Use a fixed client when attributing server-only changes")
    parser.add_argument("--version", choices=("4", "5", "6"), default="4")
    parser.add_argument("--unshaped", action="store_true")
    parser.add_argument("--mode", choices=("upload", "download", "duplex", "mixed", "idle", "churn"), default="download")
    parser.add_argument("--reuse", action="store_true")
    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--bytes", type=int, default=8 * 1024 * 1024, help="Payload per bulk round, per connection")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--workers", type=int, default=0, help="0 preserves Tokio's default")
    parser.add_argument("--settle", type=float, default=1)
    args = parser.parse_args()
    if args.target:
        try:
            asyncio.run(target())
        except KeyboardInterrupt:
            pass
        return
    if not args.binary or not args.binary.is_file():
        parser.error("--binary must name an existing executable")
    if min(args.connections, args.seconds, args.bytes, args.repeat) <= 0 or args.workers < 0 or args.settle < 0:
        parser.error("invalid workload limit")
    if args.unshaped and args.version != "6":
        parser.error("--unshaped requires --version 6")
    args.binary = args.binary.resolve()
    args.client_binary = args.client_binary.resolve() if args.client_binary else None
    emit(type="environment", system=platform.platform(), python=platform.python_version(), libc=platform.libc_ver(),
         affinity=sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
         workers=args.workers, log_level="error", loopback=True)
    for repeat in range(args.repeat):
        binaries = [args.baseline.resolve(), args.binary] if args.baseline else [args.binary]
        if repeat % 2:
            binaries.reverse()
        for binary in binaries:
            asyncio.run(asyncio.wait_for(run_once(args, binary, repeat), args.seconds + 120))


if __name__ == "__main__":
    main()
