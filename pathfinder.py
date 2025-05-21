import argparse
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import os

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

def print_ascii_art():
    """Prints the API Fuzzer ASCII art."""
    print(r"""

__________         __  .__     _____.__            .___            
\______   \_____ _/  |_|  |___/ ____\__| ____    __| _/___________ 
 |     ___/\__  \\   __\  |  \   __\|  |/    \  / __ |/ __ \_  __ \
 |    |     / __ \|  | |   Y  \  |  |  |   |  \/ /_/ \  ___/|  | \/
 |____|    (____  /__| |___|  /__|  |__|___|  /\____ |\___  >__|   
                \/          \/              \/      \/    \/       

    Multi-threaded API Fuzzer
    """)

def fuzz_api_call(base_url, endpoint, not_found_keyword, output_file, request_timeout_seconds, desired_response, current_recursion_depth, max_recursion_depth, api_endpoints_wordlist, executor):
    """
    Sends a request to the API endpoint and checks for the not_found_keyword and non-empty response.
    If the keyword is not found, the response is not empty, and the response code matches,
    the endpoint is written to the output file.
    If successful, it triggers recursive fuzzing if depth allows.
    Returns True if the request was processed, False if shutdown was requested.
    """
    if SHUTDOWN_REQUESTED:
        return False

    url = f"{base_url}{endpoint}"

    if url in FUZZED_URLS:
        return True # Already fuzzed this URL

    FUZZED_URLS.add(url)

    try:
        response = requests.get(url, timeout=request_timeout_seconds)
        response_text_lower = response.text.strip().lower()
        not_found_keyword_lower = not_found_keyword.strip().lower()
        response_code = int(response.status_code)

        # New condition: Check if the response text is not empty after stripping whitespace
        if not_found_keyword_lower not in response_text_lower and \
           response_code == desired_response and \
           response_text_lower: # Checks if the stripped response text is not an empty string
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} {url}")
            with open(output_file, 'a') as f:
                f.write(f"{url}\n")
            
            # Recursive fuzzing
            if current_recursion_depth < max_recursion_depth:
                for next_endpoint in api_endpoints_wordlist:
                    new_base_url = f"{url}/" if not url.endswith('/') else url
                    future = executor.submit(fuzz_api_call, new_base_url, next_endpoint,
                                             not_found_keyword, output_file,
                                             request_timeout_seconds, desired_response,
                                             current_recursion_depth + 1, max_recursion_depth,
                                             api_endpoints_wordlist, executor)

        else:
            if not SHUTDOWN_REQUESTED:
                # Add specific feedback for empty response if it was the reason for "NOT FOUND"
                if not response_text_lower and response_code == desired_response:
                    print(f"{Colors.RED}[NOT FOUND]{Colors.ENDC} {url} (Empty Response Body)")
                else:
                    print(f"{Colors.RED}[NOT FOUND]{Colors.ENDC} {url}")
    except requests.exceptions.Timeout:
        if not SHUTDOWN_REQUESTED:
            print(f"{Colors.YELLOW}[TIMEOUT]{Colors.ENDC} {url} (took longer than {request_timeout_seconds}s)")
    except requests.exceptions.RequestException as e:
        if not SHUTDOWN_REQUESTED:
            print(f"{Colors.RED}[ERROR]{Colors.ENDC} {url}: {e}")
    return True

def main():
    global SHUTDOWN_REQUESTED

    print_ascii_art()

    parser = argparse.ArgumentParser(
        description="Multi-threaded API fuzzer with recursive capabilities.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the file containing API call endpoints.")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Base URL of the API (e.g., https://example.com/api/).")
    group.add_argument("-l", "--url-list", help="Path to a file containing a list of base URLs, one per line.")

    parser.add_argument("-k", "--not-found-keyword", required=True, help="String to consider as a 'not found' keyword in the response.")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file to save successful API calls.")
    parser.add_argument("-c", "--concurrency", type=int, default=10,
                        help="Number of threads to use (default: 10).")
    parser.add_argument("-t", "--timeout", type=int, default=5000,
                        help="Timeout for each request in milliseconds (default: 5000ms).")
    parser.add_argument("-r", "--response", type=int, default=200,
                        help="Desired response code (default: 200).")
    parser.add_argument("-d", "--depth", type=int, default=1,
                        help="Maximum recursion depth for fuzzing (default: 1, i.e., no recursion beyond initial scan).")

    parser.epilog = """
Example:
  python3 pathfinder.py -u https://api.example.com/api/ -f endpoint_wordlist.txt -o found_endpoints.txt -k "Not Found" -t 250 -c 3000 -r 200 -d 3
  python3 pathfinder.py -l urls.txt -f endpoint_wordlist.txt -o found_endpoints.txt -k "Not Found" -t 250 -c 3000 -r 200 -d 3
"""

    args = parser.parse_args()

    desired_response = args.response
    request_timeout_seconds = args.timeout / 1000.0
    max_recursion_depth = args.depth

    base_urls = []
    if args.url:
        base_urls.append(args.url)
    elif args.url_list:
        try:
            with open(args.url_list, 'r') as f:
                base_urls = [line.strip() for line in f if line.strip()]
            if not base_urls:
                print(f"Error: No URLs found in '{args.url_list}'.")
                sys.exit(1)
        except FileNotFoundError:
            print(f"Error: URL list file '{args.url_list}' not found.")
            sys.exit(1)

    # Ensure all base URLs end with a slash for consistent path concatenation
    base_urls = [url + '/' if not url.endswith('/') else url for url in base_urls]

    api_endpoints = []
    try:
        with open(args.file, 'r') as f:
            api_endpoints = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: API endpoints file '{args.file}' not found.")
        sys.exit(1)

    if not api_endpoints:
        print("No API endpoints found in the specified file.")
        sys.exit(0)

    print(f"Starting API fuzzing with {args.concurrency} threads...")
    if args.url:
        print(f"Base URL: {args.url}")
    elif args.url_list:
        print(f"Base URLs from file: {args.url_list}")
    print(f"Not Found Keyword: '{args.not_found_keyword}' (case-insensitive check)")
    print(f"Request Timeout: {args.timeout}ms ({request_timeout_seconds}s)")
    print(f"Desired Response Code: {desired_response}")
    print(f"Maximum Recursion Depth: {max_recursion_depth}")
    print(f"Output File: {args.output}")

    # Clear the output file if it exists from a previous run
    open(args.output, 'w').close()

    futures = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        try:
            for base_url in base_urls:
                for endpoint in api_endpoints:
                    future = executor.submit(fuzz_api_call, base_url, endpoint,
                                             args.not_found_keyword, args.output,
                                             request_timeout_seconds, desired_response,
                                             0, max_recursion_depth, api_endpoints, executor)
                    futures.append(future)

            while futures:
                done, not_done = wait(futures, timeout=1, return_when=FIRST_COMPLETED)
                for f in done:
                    if f.done() and f.exception() is None and not f.result():
                        SHUTDOWN_REQUESTED = True
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
