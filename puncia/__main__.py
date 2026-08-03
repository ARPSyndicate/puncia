import os
import sys
import json
import asyncio
import aiohttp
from aiofiles import open as aio_open


API_URLS = {
    "subdomain": "https://api.subdomain.center/?domain=",
    "replica": "https://api.subdomain.center/?engine=octopus&domain=",
    "keyword": "https://api.subdomain.center/?engine=ammonites&keyword=",
    "exploit": "https://api.exploit.observer/?keyword=",
    "enrich": "https://api.exploit.observer/?enrich=True&keyword=",
    "noncve": "https://api.exploit.observer/noncve/",
    "watchlist_ides": "https://api.exploit.observer/watchlist/identifiers",
    "watchlist_info": "https://api.exploit.observer/watchlist/describers",
    "watchlist_tech": "https://api.exploit.observer/watchlist/technologies",
}

# per-mode delay to respect unauthenticated ratelimits (seconds)
NO_AUTH_SLEEP = {
    "subdomain": 5,
    "replica": 5,
    "keyword": 5,
    "exploit": 31,
    "enrich": 31,
}


async def store_key(key=""):
    home = os.path.expanduser("~")
    async with aio_open(home + "/.puncia", "w") as f:
        await f.write(key)


async def read_key():
    try:
        home = os.path.expanduser("~")
        async with aio_open(home + "/.puncia", "r") as f:
            return (await f.read()).strip()
    except FileNotFoundError:
        return ""


async def query_api(mode, query, output_file=None, cid=None, apikey=""):
    headers = {"X-API-Key": apikey} if apikey else {}

    async with aiohttp.ClientSession() as session:
        url = API_URLS.get(mode)
        if not url:
            print("Invalid Mode")
            return

        if not apikey and mode in NO_AUTH_SLEEP:
            await asyncio.sleep(NO_AUTH_SLEEP[mode])

        if "|" in query and mode in ["replica", "keyword", "exploit", "enrich"]:
            query, match = query.split("|", 1)
            url = url + query + f"&match={match}"
            query = ""

        if "^" in query and mode == "exploit":
            if query == "^WATCHLIST_IDES":
                url = API_URLS.get("watchlist_ides")
                query = ""
                mode = "spec_exploit"
                cid = "Vulnerability & Exploit Watchlist"
            elif query == "^WATCHLIST_INFO":
                url = API_URLS.get("watchlist_info")
                query = ""
                mode = "spec_exploit"
                cid = "Vulnerability & Exploit Watchlist (with descriptions)"
            elif query == "^WATCHLIST_TECH":
                url = API_URLS.get("watchlist_tech")
                query = ""
                mode = "spec_exploit"
                cid = "Vulnerable Technologies Watchlist"

        retries = 1
        counter = 0
        response_data = None

        while counter <= retries:
            try:
                async with session.get(url + query, headers=headers) as response:
                    response_data = await response.json()
                break
            except Exception as ne:
                response_data = None
                exc_type, exc_value, exc_tb = sys.exc_info()
                line_number = exc_tb.tb_lineno
                print(f"Error: {str(ne)} at line {line_number}")
            counter += 1
            await asyncio.sleep(2)

        if response_data is not None and output_file:
            async with aio_open(output_file, "w") as f:
                await f.write(json.dumps(response_data, indent=4, sort_keys=True))

        return response_data


def sbom_process(sbom):
    fingps = []

    def add_component(name, version):
        if name and version:
            fingps.append(f"{name}@{version}")

    metadata_component = sbom.get("metadata", {}).get("component", {})
    add_component(metadata_component.get("name"), metadata_component.get("version"))
    components = sbom.get("components", [])
    for subcom in components:
        add_component(subcom.get("name"), subcom.get("version"))
    return fingps


async def process_bulk(input_file, output_directory, apikey):
    tasks = []
    for mode, queries in input_file.items():
        for query in queries:
            output_file = f"{output_directory}/{mode}/{query}.json"
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            tasks.append(query_api(mode, query, output_file, apikey=apikey))
    await asyncio.gather(*tasks)


async def main():
    try:
        if len(sys.argv) < 3:
            print("---------")
            print("Panthera(P.)uncia [v0.35]")
            print("A.R.P. Syndicate [https://www.arpsyndicate.io]")
            print("---------")
            sys.exit(
                "usage: puncia <mode:subdomain/replica/keyword/exploit/enrich/noncve/bulk/sbom/storekey> <query:domain/domain/keyword/eoidentifier/eoidentifier/engine/jsonfile/apikey> [output_file/output_directory]\nrefer: https://github.com/ARPSyndicate/puncia#usage"
            )

        mode = sys.argv[1]
        query = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) == 4 else None
        apikey = await read_key()

        if mode == "storekey":
            await store_key(query)
            print("Key stored successfully!")
        elif mode == "bulk" or mode == "sbom":
            if not os.path.isfile(query):
                sys.exit("JSON file as QUERY input required for BULK mode")
            if not output_file:
                sys.exit("BULK & SBOM Mode requires an Output Directory")

            with open(query, "r") as f:
                input_file = json.load(f)

            if mode == "sbom":
                input_file = {"exploit": sbom_process(input_file)}

            await process_bulk(input_file, output_file, apikey)
        else:
            result = await query_api(mode, query, output_file, apikey=apikey)
            if result is not None:
                print(json.dumps(result, indent=4, sort_keys=True))
    except Exception as ne:
        exc_type, exc_value, exc_tb = sys.exc_info()
        line_number = exc_tb.tb_lineno
        print(f"Error: {str(ne)} at line {line_number}")


def scriptrun():
    asyncio.run(main())


if __name__ == "__main__":
    scriptrun()
