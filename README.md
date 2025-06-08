# CloudTrail Triage Parser

A command-line utility that converts **AWS CloudTrail CSV logs** into an Excel workbook for quick incident-response triage — entirely **offline**.

## 🚀 Features

- **Offline analysis** – no AWS credentials or internet required  
- **Risk-based scoring** of every event (info / low / medium / high)  
- **ATT&CK-style categories** for common API calls  
- **Flags rare IPs & foreign sources** with configurable thresholds  
- **Implements AWS IR playbook checks** (e.g., `StopLogging`, root usage, failed console logins)  
- **One-click Excel output** with raw data, suspicious-events sheet, pivots, and top error codes  
- **Multi-file support** (`-i file1 file2 …`) or **whole-folder ingest** (`-d /logs`)  
- **Customisable output filename** with `-o`

---

## 📥 Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/<your-handle>/cloudtrail-triage.git
cd cloudtrail-triage
```

### **2️⃣ Install Dependencies**
Requires Python 3.8+
```bash
pip install -r requirements.txt
```
### **⚡ Usage**
### **🔹 Basic Command**
Process one or more CSVs:

```bash
python cloudtrail_triage.py -i 2025-06-07-us-east-1.csv 2025-06-07-us-west-2.csv
```
Ingest every CSV in a folder:

```bash
python cloudtrail_triage.py -d ./cloudtrail_logs/
```

Specify the output workbook:
```bash
python cloudtrail_triage.py -d ./cloudtrail_logs/ -o triage_results.xlsx
```

Running with no arguments or with -h shows the full help/usage text.

### **🔹 Arguments**
| Argument    | Short | Description                                         |
|------------|-------|-----------------------------------------------------|
|`--input` | `-i`  |	One or more CloudTrail CSV files (mutually exclusive with --directory)
|`--directory|	-d	|Directory containing CloudTrail CSVs (non-recursive)
|`--output|	-o|	Optional destination Excel file name (default cloudtrail_triage.xlsx)
|`--help|	-h	|Show help/usage text
