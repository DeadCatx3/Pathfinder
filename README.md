# Pathfinder: A Multi-threaded API & File Fuzzer

Pathfinder is a powerful, multi-threaded Python script designed for efficiently discovering API endpoints, hidden files, and directories on web applications. It supports recursive scanning, allows for custom "not found" keywords, and provides detailed real-time output.

## Features

* **Multi-threaded Fuzzing**: Utilizes `ThreadPoolExecutor` for high concurrency, significantly speeding up scan times.
* **Two Fuzzing Modes**:
    * **Endpoints Mode (`--mode endpoints`)**: Ideal for discovering API endpoints based on a wordlist, recursively exploring valid paths.
    * **Files Mode (`--mode files`)**: Designed for uncovering hidden files and directories, with recursive scanning into found paths. It can also append a separate "names" wordlist to found directories for deeper file discovery.
* **Recursive Scanning**: Explore multiple levels deep into discovered paths, controlled by the `--depth` parameter.
* **Customizable "Not Found" Keyword**: Define a string (`-k`) that indicates a "not found" response, allowing for flexible detection beyond just status codes. If not provided, it defaults to checking for the desired response code and a non-empty body.
* **Timeout Handling**: Configurable request timeouts (`-t`) and a `--timeout-threshold` to automatically skip URLs that consistently time out, preventing resource exhaustion.
* **Beautified Error Display**: Clear and concise output for various request statuses, including `[SUCCESS]`, `[NOT FOUND]`, `[TIMEOUT]`, `[ERROR]`, and specifically `[UNREACHABLE]` for connection issues.
* **Progress Bar**: Uses `tqdm` to provide a real-time progress bar, keeping you informed of the scan's advancement.
* **URL List Support**: Fuzz multiple base URLs by providing a file with one URL per line (`-l`).
* **Resume/Extend Scans**: In `files` mode, you can provide a file of previously found endpoints (`--found-endpoints-file`) to use as additional base URLs for new scans.

## Installation

Pathfinder requires Python 3 and a few libraries.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/pathfinder.git](https://github.com/your-username/pathfinder.git)
    cd pathfinder
    ```
2.  **Install dependencies:**
    ```bash
    pip install requests tqdm
    ```
## Usage

```bash
python3 pathfinder.py --help
```

### Basic Options

* `-f, --file <wordlist_file>`: Path to your wordlist file (e.g., `endpoints.txt`, `common_dirs.txt`).
* `-u, --url <base_url>`: Single base URL to fuzz (e.g., `https://api.example.com/`).
* `-l, --url-list <urls_file>`: Path to a file containing a list of base URLs, one per line. (Mutually exclusive with `-u`).
* `-k, --not-found-keyword <keyword>`: String to consider as a 'not found' indicator in the response.
* `-o, --output <output_file>`: Path to save successful discoveries.
* `-c, --concurrency <threads>`: Number of threads (default: 10).
* `-t, --timeout <milliseconds>`: Request timeout in milliseconds (default: 5000).
* `-r, --response <status_code>`: Desired HTTP response code for a successful hit (default: 200).
* `-d, --depth <levels>`: Maximum recursion depth (default: 1, i.e., no recursion beyond initial scan).
* `--timeout-threshold <count>`: Number of consecutive timeouts before skipping a URL (default: 20).

### Mode-Specific Options

* `--mode {endpoints, files}`: Fuzzing mode (`endpoints` or `files`, default: `endpoints`).
* `--found-endpoints-file <file>`: (Files Mode only) A file containing previously found endpoints to use as additional base URLs for the current scan.
* `-n, --names <names_wordlist_file>`: (Files Mode only) A wordlist for appending filenames to discovered directories/endpoints.

## Examples

### 1. Fuzzing API Endpoints (Default Mode)

This command will fuzz `https://api.example.com/api/` using `api_wordlist.txt`, looking for responses without "Not Found" and a 200 status code, with a recursion depth of 3.

```bash
python3 pathfinder.py --mode endpoints -u [https://api.example.com/api/](https://api.example.com/api/) -f api_wordlist.txt -o found_endpoints.txt -k "Not Found" -t 250 -c 3000 -r 200 -d 3
```

### 2. Fuzzing Files and Directories from a List of URLs

This will scan URLs from `target_urls.txt` for files and directories listed in `file_wordlist.txt`, going 2 levels deep recursively.

```bash
python3 pathfinder.py --mode files -l target_urls.txt -f file_wordlist.txt -o found_files.txt -k "File Not Found" -t 250 -c 3000 -r 200 -d 2
```

### 3. Fuzzing Files with Found Endpoints and Additional Names

This example starts fuzzing from `https://example.com/` and also uses URLs from `found_endpoints.txt` as starting points. It will discover directories using `common_dirs.txt` and then append entries from `common_filenames.txt` to all discovered paths (directories and initial base URLs).

```bash
python3 pathfinder.py --mode files --found-endpoints-file found_endpoints.txt -u [https://example.com/](https://example.com/) -f common_dirs.txt -n common_filenames.txt -o discovered_files.txt -r 200
```
