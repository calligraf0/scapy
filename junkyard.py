import asyncio
import time
import argparse
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
from glob import glob

async def readpcap_async(file: str, i, dump=False):
    start_time = time.time()
    print(f"[ASYNC] TID:{i} Reading file: {file}")
    reader = AsyncPcapReader(file)
    count=0
    async for pkt in reader:
        count+=1
        if dump:
            print(pkt)
            #pkt.show()
    print(f"[ASYNC] TID:{i} File: {file} took {time.time()-start_time}s")

def readpcap_sync(file, i=0, dump=False):
    start_time = time.time()
    print(f"[SYNC] TID:{i} Reading file: {file}")
    reader = PcapReader(file)
    count=0
    for pkt in reader:
        count+=1
        if dump:
            print(pkt)
            #pkt.show()

    print(f"[SYNC] TID:{i} File: {file} took {time.time()-start_time}s")    

async def run_tasks(files, verbose=False):
    tasks=[]
    i=0
    for file in files:
        tasks.append(asyncio.create_task(readpcap_async(file,i,verbose)))
        i+=1

    print("\n[ASYNC] Using AsyncPcapReader")
    start_time = time.time()
    await asyncio.gather(*tasks)
    print(f"[ASYNC] Took {time.time()-start_time}s")

def run_threads(files, threads=5, verbose=False):
    print("\n[SYNC] Using PcapReader")
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        i=0
        for file in files:
            pool.submit(readpcap_sync, file, i, verbose)
            i+=1
    print(f"[SYNC] Took {time.time()-start_time}s") 

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-t", "--threads", action="store", default=5, help="threads to run when not using async")
    p.add_argument("-v", "--verbose", action="store_true", default=False, help="dump packets")

    p.add_argument("folder", action="store", help="folder containing pcap/pcapng files to read")

    args = p.parse_args()   
    files = []
    print("Searching for valid files:")
    for ext in ["*.pcap", "*.cap", "*.pcap.gz", ".cap.gz"]: #, ".pcapng"
        to_collect = os.path.join(args.folder, ext)
        for file in glob(to_collect):
            print(f"\t{file}")
            files.append(file)      

    #run with async
    asyncio.run(run_tasks(files, verbose=args.verbose))

    #run with sync
    run_threads(files, threads=int(args.threads), verbose=args.verbose)

   


