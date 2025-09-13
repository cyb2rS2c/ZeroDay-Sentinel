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
import platform
import shutil
import subprocess

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
    project_name = "ZeroDay Sentinel"
    animated_banner(project_name, delay=0.0001)
    print(coloring("Author: cyb2rS2c\n", Fore.MAGENTA))
    print(coloring("Advanced CVE Fetcher\n", Fore.GREEN))

# === CVE Utilities ===
def list_available_cves(year, limit=100):
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
        if len(valid_cves) >= 10:
            break
    return valid_cves

def choose_cve(year, limit=100):
    print(coloring("Choose CVE input method:", Fore.YELLOW))
    print(coloring("1: Enter CVE ID manually", Fore.MAGENTA))
    print(coloring("2: Select from available CVEs", Fore.MAGENTA))
    while True:
        choice = input(coloring("Enter 1 or 2: ", Fore.MAGENTA)).strip()
        if choice == "1":
            cve_id = input(coloring("Enter CVE ID (e.g., CVE-2025-0001): ", Fore.BLUE)).strip().upper()
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
            print(coloring(f"{i}: {cve}", Fore.CYAN))
        try:
            cve_view = int(input(coloring(f"Enter the index of the CVE to view (1-{n_display}): ", Fore.CYAN)).strip())
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
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.sub(lambda m: coloring(m.group(0), Fore.BLUE), text)

def print_colored(data):
    unique_data = get_unique_data(data)
    print(coloring("\n=== CVE Data ===\n", Fore.YELLOW))
    output_strings = []
    for k, v in unique_data.items():
        v_colored = color_hyperlinks(str(v))
        line = f"{coloring(k.split('_')[-1], Fore.YELLOW)}: {v_colored}"
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

    return json_filename, csv_filename

# === Open Files Cross-Platform ===

def start_process(filename):
    system_platform = platform.system()
    try:
        if system_platform == "Windows":
            os.startfile(filename)

        elif system_platform == "Linux":
            file_ext = os.path.splitext(filename)[1].lower()
            editors_gui = ["code", "gedit", "kate", "xdg-open"]  
            editors_cli = ["nano", "less", "vim"]

            editor = next((e for e in editors_gui if shutil.which(e)), None)
            if editor:
                subprocess.Popen([editor, filename])
            else:
                editor_cli = next((e for e in editors_cli if shutil.which(e)), None)
                if editor_cli:
                    subprocess.call([editor_cli, filename])
                else:
                    print(coloring(f"Cannot auto-open {filename}. Please open manually:", Fore.RED))
                    print(coloring(f"  → cat {filename}", Fore.YELLOW))

        elif system_platform == "Darwin":  # macOS
            subprocess.Popen(["open", filename])

        else:
            print(coloring(f"Cannot open {filename} automatically on this OS.", Fore.RED))

    except Exception as e:
        print(coloring(f"Failed to open {filename}: {e}", Fore.RED))


# === Open URLs after delay ===
def open_cve_urls(flat_data, delay=10):
    urls = [v for k, v in flat_data.items() if k.lower().endswith("url") and v.startswith("http")]
    if not urls:
        return

    print(coloring(f"\nOpening {len(urls)} URL(s) in {delay} seconds...", Fore.YELLOW))
    time.sleep(delay)

    # Try to use Firefox explicitly if available
    firefox_path = shutil.which("firefox")
    browser = webbrowser.get(f"firefox") if firefox_path else webbrowser
    for url in urls:
        try:
            browser.open(url)
            print(coloring(f"Opened URL: {url}", Fore.GREEN))
        except Exception as e:
            print(coloring(f"Failed to open URL {url}: {e}", Fore.RED))
# === Main Execution ===
def main():
    try:
        print_banner()
        year = datetime.now().year
        selected_cve = choose_cve(year, limit=1000)
        if not selected_cve:
            return  # user chose to quit

        print(coloring(f"\nFetching data for {selected_cve}...", Fore.YELLOW))
        cve_data = fetch_cve_data(selected_cve)
        if not cve_data:
            print(coloring("No data retrieved. Exiting.", Fore.RED))
            return

        flat_data = flatten_json_single(cve_data)
        json_file, csv_file = save_cve_data(flat_data, selected_cve)

        open_cve_urls(flat_data, delay=10)
        start_process(json_file)
        start_process(csv_file)

    except KeyboardInterrupt:
        print("\n" + coloring("Process interrupted by user. Exiting.", Fore.RED))
        return

if __name__ == "__main__":
    main()
