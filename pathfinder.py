import argparse
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import os
from tqdm import tqdm
import threading

# Global flag for graceful shutdown
SHUTDOWN_REQUESTED = False

# ANSI escape codes for colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m' # Resets color

# Global set to store fuzzed URLs to avoid duplicates
FUZZED_URLS = set()

# Global dictionary to store timeout counts for each URL
TIMEOUT_COUNTS = {}
TIMEOUT_THRESHOLD = 20 # Define the timeout threshold
TIMEOUT_LOCK = threading.Lock() # Lock for synchronizing access to TIMEOUT_COUNTS

def print_ascii_art():
    """Prints the API Fuzzer ASCII art."""
    print(r"""

__________         __  .__     _____.__            .___            
\______   \_____ _/  |_|  |___/ ____\__| ____    __| _/_ __________ 
 |     ___/\__  \\   __\  |  \   __\|  |/    \  / __ |/ __ \\_  __ \
 |    |     / __ \|  | |   Y  \  |  |  |   |  \/ /_/ \  ___/|  | \/
 |____|    (____  /__| |___|  /__|  |__|___|  /\____ |\___  >__|   
                \/          \/              \/      \/    \/       

    Multi-threaded API Fuzzer
    """)

def fuzz_request(url, not_found_keyword, output_file, request_timeout_seconds, desired_response, pbar=None):
    """
    Sends a request to the URL and checks for conditions.
    Returns True if the request was successful, False otherwise.
    """
    if SHUTDOWN_REQUESTED:
        if pbar:
            pbar.close()
        return False # Indicate immediate exit due to shutdown

    with TIMEOUT_LOCK:
        # Check and update timeout count before attempting the request
        current_timeout_count = TIMEOUT_COUNTS.get(url, 0)
        if current_timeout_count >= TIMEOUT_THRESHOLD:
            if not SHUTDOWN_REQUESTED:
                # Use \r to return cursor to the beginning of the line, then clear line, then print
                print(f"\r{Colors.YELLOW}[SKIPPING]{Colors.ENDC} {url} (Too many concurrent timeouts){' ' * (os.get_terminal_size().columns - len(f'[SKIPPING] {url} (Too many concurrent timeouts)') - 10)}")
            if pbar:
                pbar.update(1)
            return False # Indicate that this URL was skipped

    # Add URL to fuzzed set before making the request to prevent duplicate work
    if url in FUZZED_URLS:
        if pbar:
            pbar.update(1)
        return False # Already fuzzed this URL, not a new successful hit

    FUZZED_URLS.add(url)

    try:
        response = requests.get(url, timeout=request_timeout_seconds)
        response_text_lower = response.text.strip().lower()
        response_code = int(response.status_code)

        is_success = False
        if not_found_keyword:
            not_found_keyword_lower = not_found_keyword.strip().lower()
            if not_found_keyword_lower not in response_text_lower and \
               response_code == desired_response and \
               response_text_lower:
                is_success = True
        else: # No not_found_keyword provided, just check response code and non-empty response
            if response_code == desired_response and response_text_lower:
                is_success = True
        
        if is_success:
            with TIMEOUT_LOCK:
                TIMEOUT_COUNTS[url] = 0 # Reset timeout count on success
            print(f"\r{Colors.GREEN}[SUCCESS]{Colors.ENDC} {url}{' ' * (os.get_terminal_size().columns - len(f'[SUCCESS] {url}') - 10)}")
            with open(output_file, 'a') as f:
                f.write(f"{url}\n")
            return True # Indicate success
        else:
            if not SHUTDOWN_REQUESTED:
                if not response_text_lower and response_code == desired_response:
                    print(f"\r{Colors.RED}[NOT FOUND]{Colors.ENDC} {url} (Empty Response Body){' ' * (os.get_terminal_size().columns - len(f'[NOT FOUND] {url} (Empty Response Body)') - 10)}")
                else:
                    print(f"\r{Colors.RED}[NOT FOUND]{Colors.ENDC} {url}{' ' * (os.get_terminal_size().columns - len(f'[NOT FOUND] {url}') - 10)}")
            return False # Indicate not found or other non-success

    except requests.exceptions.Timeout:
        with TIMEOUT_LOCK:
            TIMEOUT_COUNTS[url] = TIMEOUT_COUNTS.get(url, 0) + 1
        if not SHUTDOWN_REQUESTED:
            print(f"\r{Colors.YELLOW}[TIMEOUT]{Colors.ENDC} {url} (took longer than {request_timeout_seconds}s, consecutive timeouts: {TIMEOUT_COUNTS[url]}){' ' * (os.get_terminal_size().columns - len(f'[TIMEOUT] {url} (took longer than {request_timeout_seconds}s, consecutive timeouts: {TIMEOUT_COUNTS[url]})') - 10)}")
        return False # Indicate timeout
    except requests.exceptions.ConnectionError: # This block is added for unreachable sites
        with TIMEOUT_LOCK:
            TIMEOUT_COUNTS[url] = TIMEOUT_COUNTS.get(url, 0) + 1 # Increment for persistent connection issues
        if not SHUTDOWN_REQUESTED:
            print(f"\r{Colors.RED}[UNREACHABLE]{Colors.ENDC} {url} (Site Unreachable/Connection Error){' ' * (os.get_terminal_size().columns - len(f'[UNREACHABLE] {url} (Site Unreachable/Connection Error)') - 10)}")
        return False # Indicate connection error
    except requests.exceptions.RequestException as e:
        with TIMEOUT_LOCK:
            # For other general request exceptions, do not increment TIMEOUT_COUNTS
            pass
        if not SHUTDOWN_REQUESTED:
            print(f"\r{Colors.RED}[ERROR]{Colors.ENDC} {url}: {e}{' ' * (os.get_terminal_size().columns - len(f'[ERROR] {url}: {e}') - 10)}")
        return False # Indicate error
    finally:
        # Update progress bar only once per unique URL processed by fuzz_request
        if pbar and not SHUTDOWN_REQUESTED:
            pbar.update(1)


def fuzz_endpoints_mode(base_url, endpoint, not_found_keyword, output_file, request_timeout_seconds, desired_response, current_recursion_depth, max_recursion_depth, api_endpoints_wordlist, executor, pbar):
    """
    Fuzzing logic for 'endpoints' mode with recursive capability.
    """
    url = f"{base_url}{endpoint}"
    
    # fuzz_request now returns True on success, False otherwise
    if fuzz_request(url, not_found_keyword, output_file, request_timeout_seconds, desired_response, pbar):
        # If the current URL was successfully fuzzed and recursion depth allows
        if current_recursion_depth < max_recursion_depth:
            for next_endpoint in api_endpoints_wordlist:
                # Ensure correct URL concatenation: base_url/endpoint/next_endpoint
                new_base_for_recursion = f"{url}/" if not url.endswith('/') else url
                executor.submit(fuzz_endpoints_mode, new_base_for_recursion, next_endpoint,
                                not_found_keyword, output_file,
                                request_timeout_seconds, desired_response,
                                current_recursion_depth + 1, max_recursion_depth,
                                api_endpoints_wordlist, executor, pbar)


def fuzz_files_mode(base_url, file_entry, not_found_keyword, output_file, request_timeout_seconds, desired_response, current_recursion_depth, max_recursion_depth, file_wordlist, names_wordlist, executor, pbar):
    """
    Fuzzing logic for 'files' mode, automatically finding directories and files,
    and also appending names from a separate wordlist.
    """
    url_to_fuzz = f"{base_url}{file_entry}"

    # First, fuzz the current file_entry from the main wordlist
    if fuzz_request(url_to_fuzz, not_found_keyword, output_file, request_timeout_seconds, desired_response, pbar):
        # If the current URL (base_url + file_entry) was successful:

        # Stage 1: Append names from the --names wordlist to this found URL
        if names_wordlist:
            for name in names_wordlist:
                # Ensure correct URL concatenation for name appending
                # The found URL is now the base for these names
                name_fuzz_url = f"{url_to_fuzz}/{name}" if not url_to_fuzz.endswith('/') else f"{url_to_fuzz}{name}"
                # Submit a new fuzz_request for the name appended URL
                executor.submit(fuzz_request, name_fuzz_url, not_found_keyword, output_file,
                                request_timeout_seconds, desired_response, pbar)

        # Stage 2: Recursively fuzz deeper directories using the main file_wordlist
        if current_recursion_depth < max_recursion_depth:
            for next_file_entry in file_wordlist:
                # Ensure correct URL concatenation for nested paths
                new_base_for_recursion = f"{url_to_fuzz}/" if not url_to_fuzz.endswith('/') else url_to_fuzz
                executor.submit(fuzz_files_mode, new_base_for_recursion, next_file_entry,
                                not_found_keyword, output_file,
                                request_timeout_seconds, desired_response,
                                current_recursion_depth + 1, max_recursion_depth,
                                file_wordlist, names_wordlist, executor, pbar)


def main():
    global SHUTDOWN_REQUESTED

    print_ascii_art()

    parser = argparse.ArgumentParser(
        description="Multi-threaded API fuzzer with recursive capabilities.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the file containing API call endpoints (for 'endpoints' mode) or file/directory entries (for 'files' mode).")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Base URL of the API (e.g., https://example.com/api/) for initial scan.")
    group.add_argument("-l", "--url-list", help="Path to a file containing a list of base URLs, one per line, for initial scan.")

    # Make not-found-keyword optional
    parser.add_argument("-k", "--not-found-keyword", help="String to consider as a 'not found' keyword in the response. If not supplied, only checks for desired response code and non-empty body.")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file to save successful API calls.")
    parser.add_argument("-c", "--concurrency", type=int, default=10,
                        help="Number of threads to use (default: 10).")
    parser.add_argument("-t", "--timeout", type=int, default=5000,
                        help="Timeout for each request in milliseconds (default: 5000ms).")
    parser.add_argument("-r", "--response", type=int, default=200,
                        help="Desired response code (default: 200).")
    parser.add_argument("-d", "--depth", type=int, default=1,
                        help="Maximum recursion depth for fuzzing (default: 1, i.e., no recursion beyond initial scan).")
    parser.add_argument("--timeout-threshold", type=int, default=20,
                        help=f"Number of concurrent timeouts before skipping an endpoint (default: 20).")
    
    # New mode flag
    parser.add_argument("--mode", choices=['endpoints', 'files'], default='endpoints',
                        help="Fuzzing mode: 'endpoints' for API endpoints, 'files' for file discovery (default: 'endpoints').")
    parser.add_argument("--found-endpoints-file", 
                        help="Path to a file containing previously found endpoints (from a previous 'endpoints' scan) to be used as *additional* base URLs for 'files' mode. If not provided, initial -u or -l URLs are used.")
    
    # New argument for names to append in 'files' mode
    parser.add_argument("-n", "--names", help="Path to a file containing filenames to test on found directories/endpoints in 'files' mode.")


    parser.epilog = """
Examples:
  # Fuzz API endpoints
  python3 pathfinder.py --mode endpoints -u https://api.example.com/api/ -f api_wordlist.txt -o found_endpoints.txt -k "Not Found" -t 250 -c 3000 -r 200 -d 3

  # Fuzz files on a list of URLs and automatically discover directories
  python3 pathfinder.py --mode files -l target_urls.txt -f file_wordlist.txt -o found_files.txt -k "File Not Found" -t 250 -c 3000 -r 200 -d 2

  # Fuzz files on previously found API endpoints (from found_endpoints.txt) AND new initial URLs, then append names
  python3 pathfinder.py --mode files --found-endpoints-file found_endpoints.txt -u https://example.com/ -f common_dirs.txt -n common_filenames.txt -o discovered_files.txt -r 200
"""

    args = parser.parse_args()
    global TIMEOUT_THRESHOLD
    TIMEOUT_THRESHOLD = args.timeout_threshold

    desired_response = args.response
    request_timeout_seconds = args.timeout / 1000.0
    max_recursion_depth = args.depth
    fuzzing_mode = args.mode

    initial_base_urls = []
    if args.url:
        initial_base_urls.append(args.url)
    elif args.url_list:
        try:
            with open(args.url_list, 'r') as f:
                initial_base_urls = [line.strip() for line in f if line.strip()]
            if not initial_base_urls:
                print(f"Error: No URLs found in '{args.url_list}'.")
                sys.exit(1)
        except FileNotFoundError:
            print(f"Error: URL list file '{args.url_list}' not found.")
            sys.exit(1)

    # If in 'files' mode and a '--found-endpoints-file' is provided, load those as additional base URLs
    if fuzzing_mode == 'files' and args.found_endpoints_file:
        try:
            with open(args.found_endpoints_file, 'r') as f:
                found_urls_from_file = [line.strip() for line in f if line.strip()]
            if not found_urls_from_file:
                print(f"Warning: No URLs found in '--found-endpoints-file': '{args.found_endpoints_file}'.")
            initial_base_urls.extend(found_urls_from_file)
            initial_base_urls = list(set(initial_base_urls)) # Remove duplicates
        except FileNotFoundError:
            print(f"Error: Found endpoints file '{args.found_endpoints_file}' not found.")
            sys.exit(1)
    
    if not initial_base_urls:
        print("Error: No initial base URLs provided. Use -u, -l, or --found-endpoints-file (in 'files' mode).")
        sys.exit(1)

    # Ensure all base URLs end with a slash for consistent path concatenation
    initial_base_urls = [url + '/' if not url.endswith('/') else url for url in initial_base_urls]

    wordlist_entries = []
    try:
        with open(args.file, 'r') as f:
            wordlist_entries = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Wordlist file '{args.file}' not found.")
        sys.exit(1)

    if not wordlist_entries:
        print("No entries found in the specified wordlist file.")
        sys.exit(0)

    names_wordlist = []
    if fuzzing_mode == 'files' and args.names:
        try:
            with open(args.names, 'r') as f:
                names_wordlist = [line.strip() for line in f if line.strip()]
            if not names_wordlist:
                print(f"Warning: No entries found in names file '{args.names}'. Names appending will be skipped.")
        except FileNotFoundError:
            print(f"Error: Names file '{args.names}' not found.")
            sys.exit(1)


    print(f"Starting API fuzzing with {args.concurrency} threads...")
    print(f"Fuzzing Mode: {fuzzing_mode}")
    if args.url:
        print(f"Base URL: {args.url}")
    if args.url_list:
        print(f"Base URLs from file: {args.url_list}")
    if args.found_endpoints_file and fuzzing_mode == 'files':
        print(f"Additional Base URLs from found endpoints file: {args.found_endpoints_file}")
    
    if args.not_found_keyword:
        print(f"Not Found Keyword: '{args.not_found_keyword}' (case-insensitive check)")
    else:
        print(f"Not Found Keyword: Not supplied (will only check for desired response code and non-empty body)")
    
    print(f"Wordlist File (-f): {args.file}")
    if fuzzing_mode == 'files' and args.names:
        print(f"Names File (-n): {args.names}")
    
    print(f"Request Timeout: {args.timeout}ms ({request_timeout_seconds}s)")
    print(f"Desired Response Code: {desired_response}")
    print(f"Maximum Recursion Depth: {max_recursion_depth}")
    print(f"Timeout Threshold for Skipping: {TIMEOUT_THRESHOLD}")
    print(f"Output File: {args.output}")

    # Clear the output file if it exists from a previous run
    open(args.output, 'w').close()

    total_tasks = 0
    if fuzzing_mode == 'files':
        total_tasks += len(initial_base_urls) # For direct fuzzing of base_url itself
        if names_wordlist:
            total_tasks += len(initial_base_urls) * len(names_wordlist) # For base_url + name
    total_tasks += len(initial_base_urls) * len(wordlist_entries) # For regular initial fuzzing

    # Initialize tqdm progress bar with initial total tasks
    with tqdm(total=total_tasks, desc="Fuzzing Progress", unit="req", dynamic_ncols=True) as pbar:
        futures = []
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            try:
                # --- NEW LOGIC FOR DIRECT BASE_URL AND BASE_URL+NAMES FUZZING ---
                if fuzzing_mode == 'files':
                    for base_url in initial_base_urls:
                        # 1. Fuzz the base_url itself (no appended wordlist entry)
                        future = executor.submit(fuzz_request, base_url,
                                                 args.not_found_keyword, args.output,
                                                 request_timeout_seconds, desired_response, pbar)
                        futures.append(future)

                        # 2. Fuzz base_url with entries from the --names wordlist
                        if names_wordlist:
                            for name in names_wordlist:
                                # base_url already ends with '/', so just append name
                                name_fuzz_url = f"{base_url}{name}"
                                future = executor.submit(fuzz_request, name_fuzz_url,
                                                         args.not_found_keyword, args.output,
                                                         request_timeout_seconds, desired_response, pbar)
                                futures.append(future)
                # --- END NEW LOGIC ---

                # Existing loops for fuzzing with -f wordlist and recursion
                for base_url in initial_base_urls:
                    for entry in wordlist_entries:
                        if fuzzing_mode == 'endpoints':
                            future = executor.submit(fuzz_endpoints_mode, base_url, entry,
                                                     args.not_found_keyword, args.output,
                                                     request_timeout_seconds, desired_response,
                                                     0, max_recursion_depth, wordlist_entries, executor, pbar)
                        elif fuzzing_mode == 'files':
                            future = executor.submit(fuzz_files_mode, base_url, entry,
                                                     args.not_found_keyword, args.output,
                                                     request_timeout_seconds, desired_response,
                                                     0, max_recursion_depth, wordlist_entries, names_wordlist, executor, pbar)
                        futures.append(future)

                while futures:
                    done, not_done = wait(futures, timeout=1, return_when=FIRST_COMPLETED)
                    # No explicit pbar.update() here as it's done within fuzz_request
                    futures[:] = not_done 

                    if SHUTDOWN_REQUESTED:
                        print(f"\n{Colors.YELLOW}KeyboardInterrupt detected. Shutting down threads gracefully...{Colors.ENDC}")
                        break

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}KeyboardInterrupt detected. Setting shutdown flag...{Colors.ENDC}")
                SHUTDOWN_REQUESTED = True

    print(f"\n{Colors.GREEN}API fuzzing complete or gracefully interrupted.{Colors.ENDC}")

if __name__ == "__main__":
    main()
