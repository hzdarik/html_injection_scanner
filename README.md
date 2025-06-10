# HTML Injection Scanner

A simple yet powerful command-line tool to automate the detection of HTML injection vulnerabilities in web applications. This tool scans a specified URL parameter using a wide range of HTML payloads to test for reflected HTML injection.

---

## Features

* ✅ Supports both `GET` and `POST` methods
* ✅ Allows parameter selection for targeted injection
* ✅ Uses BeautifulSoup to detect rendered HTML in server responses
* ✅ Color-coded output for clear identification of successful injections

---

## Requirements

* Python 3.x
* Modules:

  * `requests`
  * `bs4`
  * `colorama`

Install dependencies with:

```bash
pip install -r requirements.txt
```

You can also install dependencies individually:

```bash
pip install requests beautifulsoup4 colorama
```

---

## Usage

```bash
python3 html_scanner.py -u "https://example.com?parameter=" -p "parameter=" -method POST
```

### Arguments

| Argument              | Description                                     | Required |
| --------------------- | ----------------------------------------------- | -------- |
| `-u`, `--url`         | Target URL (parameter value should be empty)    | Yes      |
| `-p`, `--param`       | Parameter name with equal sign (e.g., `query=`) | Yes      |
| `-method`, `--method` | HTTP method: `GET` (default) or `POST`          | No       |

### Example

```bash
python3 html_scanner.py -u "http://test.com/search?query=" -p "query=" -method GET
```

---

## How It Works

* Injects various crafted HTML payloads into the specified parameter.
* Sends HTTP requests using the selected method.
* Analyzes the server response using BeautifulSoup to detect if the HTML was rendered or echoed back unescaped.
* Displays results using color-coded output:

  * 🟢 Green: Payload was successfully rendered (possible vulnerability)
  * 🔴 Red: Payload not rendered
  * 🟡 Yellow: Errors or warnings during request

---

## Disclaimer

This tool is intended **for educational and authorized security testing purposes only**. Unauthorized scanning or attacking of systems is illegal and unethical.

---

## Author

Developed by \[hzdarik] — Bug bounty hunter and security enthusiast 🛡️
