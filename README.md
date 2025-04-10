# 🛡️ Jaff Ransomware Campaign Analysis – Progress Report

## 📌 Objective

To perform **static and dynamic analysis** of the Jaff ransomware campaign, with a focus on:

- Infection vectors (malspam emails and attachments)
- Malicious document structures (PDFs and Word macros)
- Behavioral indicators from executable samples

> ⚠️ Note: Analysis was performed without executing the ransomware binary to avoid live infection.

---

## 📁 Collected Samples

Samples were obtained from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/):

- 📄 PCAP: `2017-06-01-Jaff-ransomware-infection-traffic.pcap`
- 📊 CSV Tracker: `2017-06-01-Jaff-ransomware-malspam-tracker.csv`
- 📧 Malspam EMLs + PDF and DOC attachments

### PDF SHA256 Hashes:

- `35418461.pdf` – `81ef38b0fb7c395c05f593847074021743b4b2a4b1b45478e25cf64194a67aef`
- `77586054.pdf` – `753550a1aa18b506693af9e1dd3af81de174cd88e820a7c87e9a8474456d3deb`
- `79443215.pdf` – `2ac01c6385135cc695abdf4e9e34d7618a7e0b81285e1f3123df54a9572982fd`
- `41021119.pdf` – `7cf89ac46a7bfcb8657c8b7bfa9f39c5396ec62ef9e86416f4780138c72e9040`

---

## 📧 Malspam Analysis

- **Spoofed Senders:** "Ana", "Marcos", "Lorene" with fake domains
- **Attachment Behavior:**
  - PDFs with embedded `.doc` files
  - Word docs contain macros that download and execute a payload

---

## 🧰 Static Analysis Tools Used

| Tool              | Purpose                                                 |
|-------------------|---------------------------------------------------------|
| `oletools` + `oleid` | Analyze and extract macros from Word documents       |
| `pdf-parser.py`   | Detect embedded objects and JavaScript inside PDF       |
| `Wireshark`       | Analyze PCAP traffic for infection behavior             |
| `binwalk`         | Entropy scan on binaries for encryption/packing detection |
| `VirusTotal`      | Scan for known malware signatures and domains           |

---

## 🔍 Key Findings

### 📄 PDF Analysis:

- Embedded `.doc` files like `XKDQK1N.doc`
- JavaScript auto-extracts and opens embedded files:

```js
var c = {};
c["cName"] = 'XKDQK1N.doc';
c["nLaunch"] = 2;
this.exportDataObject(c);
```

### 🧾 Word Macro Behavior
AutoOpen macros use:

- `CreateObject("WScript.Shell")`
- `Shell("powershell")`
- `rundll32.exe` → a known [LOLBin](https://lolbas-project.github.io/)

## 📥 Downloads payload from:

- `dsopro[.]com/7rvmnb`
- `fabriquekorea[.]com/7rvmnb`
- `katoconsulting[.]ro/7rvmnb`


### 🧠 PE32 Executable: `bruhadson8.exe`

- **Type:** Windows 32-bit GUI Executable  
- **Indicators:**  
  - High entropy → likely **packed/encrypted**

#### ⚙️ Behavior:
- 📄 Drops ransom note  
- 🌐 Connects to Tor hidden service: `rktazuzi7hbln7sy.onion`  
- 🔐 Uses **asymmetric encryption** (generates a unique key per victim)

```plaintext
Executable: bruhadson8.exe  
Type: PE32 (GUI)  
Entropy: High → possible packing or encryption  
C2: rktazuzi7hbln7sy.onion  
Encryption: Asymmetric (public-private key pair per victim)  
```
---

## 📦 Notable API Calls

| DLL           | Behavior                                 |
|---------------|------------------------------------------|
| `KERNEL32.dll`  | File manipulation (encryption)          |
| `ADVAPI32.dll`  | Security descriptor editing             |
| `USER32.dll`    | GUI elements or fake window use         |
| `NTDSAPI.dll`   | Possible domain/AD awareness            |
| `OPENGL32.dll`  | May be stub/evade detection             |

---

## 📊 Network Analysis

- 📁 **PCAP** showed signs of infection flow
- 🔁 **TCP RST packets** present – indicative of:
  - Connection resets (**anti-sandboxing?**)
  - Aborted or blocked connections

---

## 🧪 Entropy Analysis

Using `binwalk -E`:
- Entropy > **0.95** → Indicates **packed or encrypted binary**
- Suggests use of **crypter** or **packer** to evade detection

---

## 🔐 Ransom Note Behavior

- 📄 `.txt` file with **ransom instructions** dropped on Desktop  
- 🔗 Note references `.onion` domain for **payment & decryption**  
- 💰 Demands **Bitcoin** payment for decryptor

---

## 🚨 Mitre ATT&CK Tactics Observed

| Tactic           | Technique                           |
|------------------|-------------------------------------|
| Initial Access   | Phishing via Document               |
| Execution        | Macro Execution + LOLBins           |
| Defense Evasion  | Packed Binary, LOLBins usage        |
| Command & Control| Custom C2 via Tor `.onion`          |
| Impact           | File Encryption (Ransomware)        |

---

## ✅ Conclusion

The **Jaff ransomware** campaign was a **multi-stage attack** involving:
- 🎯 **Phishing** for initial access  
- ⚙️ **Macro abuse** in Word documents  
- 🕸️ **Tor-based C2 infrastructure**

⚠️ Indicators and behavior align with known ransomware families like **Locky**.  
🔬 All analysis conducted in an **isolated, non-execution environment**.

---

## 🧠 IOC Summary (Indicators of Compromise)

- **DOC Hash:** `42f438...`  
- **Payload URLs:**
  - `dsopro[.]com/7rvmnb`
  - `fabriquekorea[.]com/7rvmnb`
  - `katoconsulting[.]ro/7rvmnb`
- **Ransomware C2:** `rktazuzi7hbln7sy.onion`

---


