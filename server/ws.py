#!/usr/bin/env python3
import asyncio
import json
import sys
import threading

import websockets
from websockets.exceptions import ConnectionClosed

HOST = "0.0.0.0"
PORT = 8765

clients = set()
loop = None
server = None


async def handler(ws, path=None):
    clients.add(ws)
    peer = ws.remote_address
    print(f"\n[+] connected: {peer}  (total {len(clients)})")
    try:
        async for msg in ws:
            try:
                data = json.loads(msg)
            except Exception:
                print(f"[raw] {msg}")
                continue

            t = data.get("type")

            # heartbeat
            if t == "ping":
                try:
                    await ws.send(json.dumps({"type": "pong"}))
                except Exception:
                    pass
                continue
            if t == "pong":
                continue

            # hello handshake
            if t == "hello":
                print(
                    f"[hello] from {peer}  "
                    f"model={data.get('model')}  "
                    f"serial={data.get('serial')}  "
                    f"mac={data.get('mac')}  "
                    f"state={data.get('state')}  "
                    f"ua={(data.get('ua') or '?')[:60]}"
                )
                continue

            # eval results
            if t == "result":
                print(f"\n<<< {data.get('value')}\n")
                continue
            if t == "error":
                print(f"\n!!! {data.get('error')}\n")
                continue

            print(f"[{t}] {data}")
    except ConnectionClosed:
        pass
    except Exception as e:
        print(f"[handler error] {e}")
    finally:
        clients.discard(ws)
        print(f"[-] disconnected: {peer}  (remaining {len(clients)})")


async def broadcast(cmd: str):
    if not clients:
        print("[!] no connected set-top boxes")
        return

    payload = json.dumps({"type": "eval", "code": cmd})
    dead = []
    for c in list(clients):
        try:
            await c.send(payload)
        except Exception:
            dead.append(c)

    for d in dead:
        clients.discard(d)
        try:
            await d.close()
        except Exception:
            pass


def stdin_reader():
    global loop
    print("JS console ready. Enter an expression and press Enter. 'exit' to quit.")
    print("Examples:  gSTB.RDir('IPAddress')   |   viewModel.user.client_id")
    while True:
        try:
            line = sys.stdin.readline()
        except (KeyboardInterrupt, EOFError):
            break
        if not line:
            break
        cmd = line.rstrip("\n")
        if cmd.strip() in ("exit", "quit"):
            break
        if not cmd.strip():
            continue
        if loop is None or loop.is_closed():
            print("[!] server not ready yet")
            continue
        try:
            asyncio.run_coroutine_threadsafe(broadcast(cmd), loop)
        except Exception as e:
            print(f"[stdin error] {e}")
    # graceful shutdown
    if loop and not loop.is_closed():
        asyncio.run_coroutine_threadsafe(shutdown(), loop)


async def shutdown():
    global server
    print("\n[shutdown] closing server...")
    if server is not None:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
    for c in list(clients):
        try:
            await c.close()
        except Exception:
            pass
    clients.clear()


async def main():
    global loop, server
    loop = asyncio.get_running_loop()
    threading.Thread(target=stdin_reader, daemon=True).start()

    async with websockets.serve(
        handler, HOST, PORT,
        ping_interval=20,
        ping_timeout=20,
        max_size=4 * 1024 * 1024,   # 4 MB per message (eval + result)
    ) as srv:
        server = srv
        print(f"WS server on ws://{HOST}:{PORT}")
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nbye")
