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
