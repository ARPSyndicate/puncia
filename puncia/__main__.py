import os
import sys
import json
import asyncio
import aiohttp
from aiofiles import open as aio_open


API_URLS = {
    "subdomain": "https://api.subdomain.center/?domain=",
    "replica": "https://api.subdomain.center/?engine=octopus&domain=",
    "exploit": "https://api.exploit.observer/?keyword=",
    "enrich": "https://api.exploit.observer/?enrich=True&keyword=",
    "chat": "https://api.osprey.vision/",
    "auth_subdomain": "https://api.subdomain.center/beta/?auth={0}&domain=",
    "auth_replica": "https://api.subdomain.center/beta/?auth={0}&engine=octopus&domain=",
    "auth_exploit": "https://api.exploit.observer/beta/?auth={0}&keyword=",
    "auth_enrich": "https://api.exploit.observer/beta/?auth={0}&enrich=True&keyword=",
    "auth_chat": "https://api.osprey.vision/beta/",
    "auth_summarize": "https://api.osprey.vision/summarize/",
    "auth_advisory": "https://api.osprey.vision/advisory/",
    "russia": "https://api.exploit.observer/russia/",
    "china": "https://api.exploit.observer/china/",
    "watchlist_ides": "https://api.exploit.observer/watchlist/identifiers",
    "watchlist_info": "https://api.exploit.observer/watchlist/describers",
    "watchlist_tech": "https://api.exploit.observer/watchlist/technologies",
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
    async with aiohttp.ClientSession() as session:
        if len(apikey) > 0 and mode in [
            "exploit",
            "subdomain",
            "enrich",
            "replica",
            "chat",
            "summarize",
            "advisory",
        ]:
            url = API_URLS.get("auth_" + mode).format(apikey)
        else:
            await asyncio.sleep(5)
            url = API_URLS.get(mode)
            if not url:
                print("Invalid Mode / Missing Authentication")
                return

        if "^" in query and "exploit" in mode:
            if query == "^RU_NON_CVE":
                url = API_URLS.get("russia")
                query = "noncve"
                mode = "spec_exploit"
                cid = "Russian VIDs with no associated CVEs"
            elif query == "^CN_NON_CVE":
                url = API_URLS.get("china")
                query = "noncve"
                mode = "spec_exploit"
                cid = "Chinese VIDs with no associated CVEs"
            elif query == "^WATCHLIST_IDES":
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
                if mode in ["chat", "auth_chat"]:
                    reschat = ""
                    data = {"prompt": query}
                    if "/beta" in url:
                        data["auth"] = apikey
                    async with session.post(url, json=data) as response:
                        async for line in response.content:
                            if sys.argv[0].endswith("puncia"):
                                print(line.decode("utf-8"), flush=True, end="")
                            reschat += line.decode("utf-8")
                        if sys.argv[0].endswith("puncia"):
                            print("\n")
                        if output_file:
                            with open(output_file, "w") as f:
                                f.write(reschat)
                    counter = counter + 1
                    if reschat and len(reschat) > 1:
                        return reschat

                elif mode in ["summarize", "auth_summarize"]:
                    reschat = ""
                    data = {"links": query}
                    data["auth"] = apikey
                    async with session.post(url, json=data) as response:
                        async for line in response.content:
                            if sys.argv[0].endswith("puncia"):
                                print(line.decode("utf-8"), flush=True, end="")
                            reschat += line.decode("utf-8")
                        if sys.argv[0].endswith("puncia"):
                            print("\n")
                        if output_file:
                            with open(output_file, "w") as f:
                                f.write(reschat)
                    counter = counter + 1
                    if reschat and len(reschat) > 1:
                        return reschat
                elif mode in ["advisory", "auth_advisory"]:
                    reschat = ""
                    if len(query.split("|")) == 2:
                        data = {"vulnid": query.split("|")[0], "lang": query.split("|")[1].upper()}
                    else:
                        data = {"vulnid": query, "lang": "ENGLISH"}                   
                    data["auth"] = apikey
                    async with session.post(url, json=data) as response:
                        async for line in response.content:
                            if sys.argv[0].endswith("puncia"):
                                print(line.decode("utf-8"), flush=True, end="")
                            reschat += line.decode("utf-8")
                        if sys.argv[0].endswith("puncia"):
                            print("\n")
                        if output_file:
                            with open(output_file, "w") as f:
                                f.write(reschat)
                    counter = counter + 1
                    if reschat and len(reschat) > 1:
                        return reschat
                else:
                    async with session.get(url + query) as response:
                        response_data = await response.json()

                if response_data:
                    if len(response_data) > 1:
                        break
            except Exception as ne:
                exc_type, exc_value, exc_tb = sys.exc_info()
                line_number = exc_tb.tb_lineno
                print(f"Error: {str(ne)} at line {line_number}")
            counter += 1
            await asyncio.sleep(2)

        if response_data and mode == "spec_exploit" and output_file:
            try:
                async with aio_open(output_file, "w") as f:
                    await f.write(json.dumps(response_data, indent=4, sort_keys=True))
            except Exception as ne:
                exc_type, exc_value, exc_tb = sys.exc_info()
                line_number = exc_tb.tb_lineno
                print(f"Error: {str(ne)} at line {line_number}")
            return response_data

        if response_data and output_file:
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
            print("Panthera(P.)uncia [v0.32]")
            print("A.R.P. Syndicate [https://www.arpsyndicate.io]")
            print("---------")
            sys.exit(
                "usage: puncia <mode:chat/summarize/advisory/subdomain/replica/exploit/enrich/bulk/sbom/storekey> <query:prompt/domain/eoidentifier/eoidentifier|lang/jsonfile/apikey> [output_file/output_directory]\nrefer: https://github.com/ARPSyndicate/puncia#usage"
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
            if result and mode not in ["chat", "summarize", "advisory"]:
                print(json.dumps(result, indent=4, sort_keys=True))
    except Exception as ne:
        exc_type, exc_value, exc_tb = sys.exc_info()
        line_number = exc_tb.tb_lineno
        print(f"Error: {str(ne)} at line {line_number}")


def scriptrun():
    asyncio.run(main())


if __name__ == "__main__":
    scriptrun()
