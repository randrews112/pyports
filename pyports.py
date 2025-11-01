import asyncio
import argparse


async def tcp_port_scan(ip: str, port: int, timeout: float = 1.0) -> None:
        conn = asyncio.open_connection(ip, port) 
        try:
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            print(f"Open Port: {port}")
            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError):
            pass
        except Exception as e:
            print(f"[!] Error - Port {port}: {e}")

async def worker(host: str, queue: asyncio.Queue, timeout: float):
     while True:
        try: 
            port = await queue.get()
        except asyncio.CancelledError:
            break
        try:
            await tcp_port_scan(host, port, timeout)
        finally:
            queue.task_done()

async def main() -> None:
    parse = argparse.ArgumentParser(description='Simple python program to identify open TCP ports on a single host.')
    parse.add_argument("--target", "-t", help="IP address or hostname of target to scan.", required=True, type=str)
    parse.add_argument("--concurrency", "-c", help="Max concurrent connections (default: 9000). NOTE:" \
    "~10000 will start causing some ports to be missed when scanning from Windows.", default=9000, type=int)
    parse.add_argument("--timeout", help="Timeout value in seconds (default: 1.0).", default=1.0, type=float)
    args = parse.parse_args()

    queue: asyncio.Queue[int] = asyncio.Queue()
    for port in range(1, 65536):
        queue.put_nowait(port)

    workers = []
    for i in range(max(1, args.concurrency)):
        w = asyncio.create_task(worker(args.target, queue, args.timeout))
        workers.append(w)

    try:
        await queue.join()
    finally:
        for w in workers:
            w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

if __name__ == '__main__':
    asyncio.run(main())

#############################################
# this feels super slow still, 
# why am I garbage at this, 
# programming is the devil!
#############################################

# TODO:
    # figure out a faster way to scan (Win 11 25H2 only getting 9000)
    # add the option to scan specific ports, not all TCP
    # preset scan option for AD DCs
    # save results to text file
    # udp? 
    # service details? 
    # since you have no job, make a c2py and add it as a module for identifying new hosts/services when latmoving?  
