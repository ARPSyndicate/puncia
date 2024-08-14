import os
import requests
import sys
import json
import time
import re

API_URLS = {
    "subdomain": "https://api.subdomain.center/?domain=",
    "exploit": "https://api.exploit.observer/?keyword=",
    "enrich": "https://api.exploit.observer/?enrich=True&keyword=",
    "auth_subdomain": "https://api.subdomain.center/beta/?auth={0}&domain=",
    "auth_exploit": "https://api.exploit.observer/beta/?auth={0}&keyword=",
    "auth_enrich": "https://api.exploit.observer/beta/?auth={0}&enrich=True&keyword=",
    "russia": "https://api.exploit.observer/russia/",
    "china": "https://api.exploit.observer/china/",
    "watchlist_ides": "https://api.exploit.observer/watchlist/identifiers",
    "watchlist_tech": "https://api.exploit.observer/watchlist/technologies",
}


def store_key(key=""):
    home = os.path.expanduser("~")
    with open(home + "/.puncia", "w") as f:
        f.write(key)


def read_key():
    try:
        home = os.path.expanduser("~")
        with open(home + "/.puncia", "r") as f:
            key = f.read()
        return key
    except:
        pass
    return ""


def query_api(mode, query, output_file=None, cid=None, akey=""):
    if len(akey) > 0 and mode in ["exploit", "subdomain", "enrich"]:
        url = API_URLS.get("auth_" + mode).format(akey)
    else:
        time.sleep(60)
        url = API_URLS.get(mode)
    if "^" in query and "exploit" in mode:
        if query == "^RU_NON_CVE":
            url = API_URLS.get("russia")
            query = "noncve"
            mode = "spec_exploit"
            cid = "Russian VIDs with no associated CVEs"
        if query == "^CN_NON_CVE":
            url = API_URLS.get("china")
            query = "noncve"
            mode = "spec_exploit"
            cid = "Chinese VIDs with no associated CVEs"
        if query == "^WATCHLIST_IDES":
            url = API_URLS.get("watchlist_ides")
            query = ""
            mode = "spec_exploit"
            cid = "Vulnerability & Exploit Watchlist"
        if query == "^WATCHLIST_TECH":
            url = API_URLS.get("watchlist_tech")
            query = ""
            mode = "spec_exploit"
            cid = "Vulnerable Technologies Watchlist"
    if not url:
        sys.exit("Invalid Mode")
    try:
        response = requests.get(url + query).json()
    except:
        print("An exception happened while requesting: " + query)
        return
    if not response or len(response) == 0:
        print("Null response from the API")
        return
    result = json.dumps(response, indent=4, sort_keys=True)
    print(result)
    if mode in ["spec_exploit"]:
        os.system("rm " + output_file)
        for reurl in response:
            query_api(
                "exploit",
                reurl,
                output_file,
                cid,
                akey,
            )
        return
    if output_file:
        existing_data = {}
        if os.path.isfile(output_file):
            with open(output_file, "r") as f:
                existing_data = json.load(f)
        if mode == "subdomain":
            if len(existing_data) == 0:
                existing_data = []
            existing_data.extend(response)
            existing_data = list(set(existing_data))
        elif mode == "enrich":
            existing_data = response
        elif mode == "exploit":
            if "entries" in existing_data and len(existing_data["entries"]) > 0:
                for lang in existing_data["entries"]:
                    response_entries = response.get("entries", {}).get(lang, [])
                    existing_data_entries = existing_data["entries"].get(lang, [])
                    existing_data["entries"][lang] = list(
                        set(existing_data_entries + response_entries)
                    )
                    existing_data["entries"][lang].sort()
            else:
                existing_data = response
            if "clusters" in existing_data:
                existing_data_clusters = existing_data.get("clusters", [])
                existing_data_clusters.extend(response.get("clusters", []))
                existing_data["clusters"] = list(set(existing_data_clusters))
                existing_data["clusters"].sort()
            total_entries = 0
            for lang in existing_data["entries"]:
                total_entries = len(existing_data["entries"][lang]) + total_entries
            if "priority" in existing_data:
                existing_data["priority"] = (
                    response.get("priority", 1) + existing_data["priority"]
                ) / 2
            if len(existing_data["description"]) > 0:
                if "description" in response and len(response["description"]) > 0:
                    existing_data["description"] = response["description"]
                existing_data["description"] = re.sub(
                    r"\b(\d+)\s+(?:entries in)\b",
                    str(total_entries) + " entries in",
                    existing_data["description"],
                )
                existing_data["description"] = re.sub(
                    r"\b(\d+)\s+(?:file formats)\b",
                    str(len(existing_data["entries"])) + " file formats",
                    existing_data["description"],
                )
                if cid:
                    existing_data["description"] = re.sub(
                        r"(?<=related to\s)[^.]+(?=\.)",
                        cid,
                        existing_data["description"],
                    )

        with open(output_file, "w") as f:
            json.dump(existing_data, f, indent=4, sort_keys=True)


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


def main():
    try:
        print("---------")
        print("Panthera(P.)uncia [v0.23]")
        print("A.R.P. Syndicate [https://www.arpsyndicate.io]")
        print("---------")

        if len(sys.argv) < 3:
            sys.exit(
                "usage: puncia <mode:subdomain/exploit/enrich/bulk/sbom/storekey> <query:domain/eoidentifier/jsonfile/apikey> [output_file/output_directory]\nrefer: https://github.com/ARPSyndicate/puncia#usage"
            )

        mode = sys.argv[1]
        query = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) == 4 else None
        akey = read_key()

        if (
            mode not in API_URLS
            and mode != "bulk"
            and mode != "sbom"
            and mode != "storekey"
        ):
            sys.exit("Invalid Mode")

        if mode == "bulk" or mode == "sbom":
            if not os.path.isfile(query):
                sys.exit("jsonfile as query input required for bulk mode")
            if output_file:
                os.makedirs(output_file + "/subdomain/", exist_ok=True)
                os.makedirs(output_file + "/exploit/", exist_ok=True)
                os.makedirs(output_file + "/enrich/", exist_ok=True)
            else:
                sys.exit("BULK & SBOM Mode require an Output Directory")
            with open(query, "r") as f:
                input_file = json.load(f)
            if mode == "sbom":
                new_input_file = {"exploit": []}
                new_input_file["exploit"] = sbom_process(input_file)
                input_file = new_input_file
            if "subdomain" in input_file:
                for bulk_query in input_file["subdomain"]:
                    try:
                        query_api(
                            "subdomain",
                            bulk_query,
                            output_file + "/subdomain/" + bulk_query + ".json",
                            akey=akey,
                        )
                    except Exception as ne:
                        sys.exit(f"Error: {str(ne)}")
                        continue
            if "exploit" in input_file:
                for bulk_query in input_file["exploit"]:
                    try:
                        query_api(
                            "exploit",
                            bulk_query,
                            output_file + "/exploit/" + bulk_query + ".json",
                            akey=akey,
                        )
                    except Exception as ne:
                        sys.exit(f"Error: {str(ne)}")
            if "enrich" in input_file:
                for bulk_query in input_file["enrich"]:
                    try:
                        query_api(
                            "enrich",
                            bulk_query,
                            output_file + "/enrich/" + bulk_query + ".json",
                            akey=akey,
                        )
                    except Exception as ne:
                        sys.exit(f"Error: {str(ne)}")

        elif mode == "storekey":
            store_key(query)
            print("Successful!")

        else:
            query_api(mode, query, output_file, akey=akey)
    except Exception as e:
        sys.exit(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
