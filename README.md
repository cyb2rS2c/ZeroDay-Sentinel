# ZeroDay Sentinel

**Author:** cyb2rS2c  
**Version:** 1.0  
**Date:** 2025  

---

## Overview

**ZeroDay Sentinel** is an advanced Command-Line Interface (CLI) tool designed to **fetch, flatten, and display CVE (Common Vulnerabilities and Exposures) data** in a clear, concise, and visually enhanced format.  
It supports **unique-value filtering, hyperlink highlighting, JSON/CSV export, and automated URL opening**, making it a powerful assistant for vulnerability analysts, security researchers, and penetration testers.  

---

## Features

- Fetch CVE data directly from [MITRE CVE API](https://cveawg.mitre.org/api/)
- Automatically list only **valid/existing CVEs**  
- Option to **manually enter a CVE ID** or **select from available valid CVEs**  
- **Flatten JSON data** for easier readability and CSV export  
- Display **unique key-value pairs** only (no duplicates)  
- Highlight **URLs in blue** and open them in your default browser after a delay  
- Save data in both **JSON** and **CSV** formats  
- Animated and colored CLI output for a modern hacker-style interface  
- Countdown before opening URLs for better user experience  

---

## Installation
Clone this repository: (windows)
```bash
curl -o ZeroDay-Sentinel-main.zip https://github.com/cyb2rS2c/ZeroDay-Sentinel/archive/refs/heads/main.zip
Expand-Archive -Force  .\ZeroDay-Sentinel-main.zip
cd ZeroDay-Sentinel-main/ZeroDay-Sentinel-main
```
Clone this repository: (linux)
```bash
git clone https://github.com/cyb2rS2c/ZeroDay-Sentinel.git
cd ZeroDay-Sentinel
```
**Requirements:**
- Python 3.8+
```bash (cmd)
python -m venv myvenv
myvenv\Scripts\Activate.bat
pip install -r requirements.txt
```
## Usage
1. Run the tool:
```bash
python zeroday_sentinel.py
```
2. The tool will:

* Fetch CVE data
* Display unique values in color
* Save JSON and CSV files
* Open associated URLs in your default browser after 10 seconds
* Open the generated files automatically (Windows and Linux) 

## Screenshots

<img width="637" height="491" alt="image" src="https://github.com/user-attachments/assets/253649fb-e155-4919-970a-c86370a4bc26" />
<img width="428" height="750" alt="image" src="https://github.com/user-attachments/assets/177e0d1a-bd3e-4cd2-8194-5e29928ce00c" />
<img width="1546" height="805" alt="image" src="https://github.com/user-attachments/assets/cc7d961e-3530-40e6-a073-e2d1e3d1a886" />




## 📝 Author

cyb2rS2c - [GitHub Profile](https://github.com/cyb2rS2c)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.


