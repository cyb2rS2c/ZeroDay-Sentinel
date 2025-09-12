import json
from curl_cffi import requests
from datetime import datetime
from flatten_json import flatten
import pandas as pd
import os
from colorama import Fore, init
from pyfiglet import Figlet
import time
import re
import webbrowser
import time
init(autoreset=True)
def coloring(string, color=Fore.GREEN):
    return f"{color}{string}{Fore.RESET}"
# === Animated Banner ===
def animated_banner(text, font='poison', delay=0.0001):
    figlet = Figlet(font=font)
    banner = figlet.renderText(text)
    for line in banner.split('\n'):
        for char in line:
            print(Fore.RED + char, end='', flush=True)
            time.sleep(delay)
        print()

def print_banner():
    project_name = "ZeroDay Sentinel"  # unexpected project name
    animated_banner(project_name, delay=0.0001)
    print(coloring("Author: cyb2rS2c\n", Fore.MAGENTA))
    print(coloring("Advanced CVE Fetcher\n", Fore.GREEN))

# === CVE Utilities ===
def list_available_cves(year, limit=100):
    """
    Generate a list of CVEs for the year and return only valid/existing ones.
    Warning: checking many CVEs may take time due to API calls.
    """
    valid_cves = []
    for i in range(1, limit + 1):
        cve_id = f"CVE-{year}-{i:04d}"
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        try:
            resp = requests.get(url, impersonate="chrome", timeout=5)
            if resp.status_code == 200:
                valid_cves.append(cve_id)
        except Exception:
            pass 
        # Optional: stop early if you reach 10 valid CVEs
        if len(valid_cves) >= 10:
            break
    return valid_cves

def choose_cve(year, limit=100):
    """
    Let the user either enter a CVE manually or select from valid CVEs.
    """
    print(coloring("Choose CVE input method:", Fore.YELLOW))
    print(coloring("1: Enter CVE ID manually", Fore.BLACK))
    print(coloring("2: Select from available CVEs", Fore.BLACK))

    while True:
        choice = input(coloring("Enter 1 or 2: ", Fore.BLACK)).strip()
        if choice == "1":
            cve_id = input(coloring("Enter CVE ID (e.g., CVE-2025-0001): ", Fore.BLACK)).strip().upper()
            return cve_id
        elif choice == "2":
            print(coloring("Fetching valid CVEs...", Fore.YELLOW))
            available_cves = list_available_cves(year, limit=limit)
            if not available_cves:
                print(coloring("No valid CVEs found for this year.", Fore.RED))
                continue
            return select_cve(available_cves)
        else:
            print(coloring("Invalid choice. Please enter 1 or 2.", Fore.RED))

def select_cve(cve_list, display_limit=10):
    n_display = min(display_limit, len(cve_list))
    while True:
        print(coloring("\nAvailable CVEs:", Fore.YELLOW))
        for i, cve in enumerate(cve_list[:n_display], 1):
            print(coloring(f"{i}: {cve}", Fore.BLACK))
        try:
            cve_view = int(input(coloring(f"Enter the index of the CVE to view (1-{n_display}): ", Fore.BLACK)).strip())
            if 1 <= cve_view <= n_display:
                return cve_list[cve_view - 1]
            print(coloring(f"Index out of range. Please enter a number between 1 and {n_display}.", Fore.RED))
        except ValueError:
            print(coloring("Invalid input. Please enter a number.", Fore.RED))

def fetch_cve_data(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        resp = requests.get(url, impersonate="chrome", timeout=10)
        if resp.status_code == 200:
            return resp.json()
        print(coloring(f"Failed to fetch CVE data: {resp.status_code}", Fore.RED))
    except Exception as e:
        print(coloring(f"Error fetching data: {e}", Fore.RED))
    return None

def flatten_json_single(json_resp):
    if not json_resp:
        return {}
    flat = flatten(json_resp, separator="_")
    for k, v in flat.items():
        if isinstance(v, (dict, list)):
            flat[k] = json.dumps(v)
    return flat

# === Unique Data Utilities ===
def get_unique_data(data):
    seen = set()
    unique_data = {}
    for k, v in data.items():
        if v not in seen:
            unique_data[k.split('_')[-1]] = v
            seen.add(v)
    return unique_data

# === Hyperlink Coloring ===
def color_hyperlinks(text):
    # Detect URLs and color them blue
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.sub(lambda m: coloring(m.group(0), Fore.BLUE), text)

def print_colored(data):
    unique_data = get_unique_data(data)
    print(coloring("\n=== CVE Data ===\n", Fore.YELLOW))
    output_strings = []
    for k, v in unique_data.items():
        v_colored = color_hyperlinks(str(v))
        line = f"{coloring(k.split('_')[-1], Fore.BLACK)}: {v_colored}"
        print(line)
        output_strings.append(line)
    return unique_data, "\n".join(output_strings)

# === Save Utilities ===
def save_cve_data(flat_data, cve_id):
    unique_data, _ = print_colored(flat_data)

    json_filename = f"{cve_id}.json"
    csv_filename = f"{cve_id}.csv"

    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(unique_data, f, indent=2)
    print(coloring(f"JSON saved to {json_filename}", Fore.GREEN))

    df = pd.DataFrame([unique_data])
    df.to_csv(csv_filename, index=False, encoding="utf-8")
    print(coloring(f"CSV saved to {csv_filename}", Fore.GREEN))

def start_process(filename):
    try:
        os.startfile(filename)
    except AttributeError:
        print(coloring(f"Cannot open {filename} automatically on this OS.", Fore.RED))

def open_cve_urls(flat_data, delay=10):
    """
    Extract URLs from CVE data and open them in the default browser after 'delay' seconds.
    """
    urls = [v for k, v in flat_data.items() if k.lower().endswith("url") and v.startswith("http")]
    if not urls:
        return  # no URLs found

    print(coloring(f"\nOpening {len(urls)} URL(s) in {delay} seconds...", Fore.YELLOW))
    time.sleep(delay)

    for url in urls:
        try:
            webbrowser.open(url)
            print(coloring(f"Opened URL: {url}", Fore.GREEN))
        except Exception as e:
            print(coloring(f"Failed to open URL {url}: {e}", Fore.RED))


# === Main Execution ===
def main():
    print_banner()
    year = datetime.now().year
    selected_cve = choose_cve(year, limit=1000)

    print(coloring(f"\nFetching data for {selected_cve}...", Fore.YELLOW))
    cve_data = fetch_cve_data(selected_cve)
    if not cve_data:
        print(coloring("No data retrieved. Exiting.", Fore.RED))
        return

    flat_data = flatten_json_single(cve_data)
    save_cve_data(flat_data, selected_cve)

    # Open URLs in CVE data after 10 seconds
    open_cve_urls(flat_data, delay=10)

    # Open local JSON and CSV files correctly
    start_process(selected_cve + '.json')
    start_process(selected_cve + '.csv')

if __name__ == "__main__":
    main()
