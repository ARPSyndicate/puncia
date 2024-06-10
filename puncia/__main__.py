import os
import requests
import sys
import json
import time
import re

API_URLS = {
    "subdomain": "http://api.subdomain.center/?domain=",
    "exploit": "http://api.exploit.observer/?keyword=",
    "russia": "http://api.exploit.observer/russia/",
    "china": "http://api.exploit.observer/china/",
}


def query_api(mode, query, output_file=None, cid=None):
    time.sleep(8)
    url = API_URLS.get(mode)
    if "^" in query:
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
    if not url:
        sys.exit("Invalid Mode")

    response = requests.get(url + query).json()
    if not response:
        print("Null response from the API")
        return
    result = json.dumps(response, indent=4, sort_keys=True)
    print(result)
    if mode in ["spec_exploit"]:
        for reurl in response:
            query_api(
                "exploit",
                reurl.replace("https://api.exploit.observer/?keyword=", ""),
                output_file,
                cid,
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


def main():
    try:
        print("---------")
        print("Panthera(P.)uncia [v0.17]")
        print("A.R.P. Syndicate [https://arpsyndicate.io]")
        print("Subdomain Center [https://subdomain.center]")
        print("Exploit Observer [https://exploit.observer]")
        print("---------")

        if len(sys.argv) < 3:
            sys.exit(
                "usage: puncia <mode:subdomain/exploit/bulk> <query:domain/eoidentifier/jsonfile> [output_file/output_directory]\nrefer: https://github.com/ARPSyndicate/puncia#usage"
            )

        mode = sys.argv[1]
        query = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) == 4 else None

        if mode not in API_URLS and mode != "bulk":
            sys.exit("Invalid Mode")

        if mode == "bulk":
            if not os.path.isfile(query):
                sys.exit("jsonfile as query input required for bulk mode")
            if output_file:
                os.makedirs(output_file + "/subdomain/", exist_ok=True)
                os.makedirs(output_file + "/exploit/", exist_ok=True)
            with open(query, "r") as f:
                input_file = json.load(f)
            if "subdomain" in input_file:
                for bulk_query in input_file["subdomain"]:
                    try:
                        query_api(
                            "subdomain",
                            bulk_query,
                            output_file + "/subdomain/" + bulk_query + ".json",
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
                        )
                    except Exception as ne:
                        sys.exit(f"Error: {str(ne)}")
        else:
            query_api(mode, query, output_file)
    except Exception as e:
        sys.exit(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
