import argparse
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

# Global flag for graceful shutdown
SHUTDOWN_REQUESTED = False

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

def fuzz_api_call(base_url, endpoint, not_found_keyword, output_file, request_timeout_seconds):
    """
    Sends a request to the API endpoint and checks for the not_found_keyword.
    If the keyword is not found, the endpoint is written to the output file.
    Returns True if the request was processed, False if shutdown was requested.
    """
    if SHUTDOWN_REQUESTED:
        return False

    url = f"{base_url}{endpoint}"
    try:
        # Perform case-insensitive comparison and strip whitespace from response text for robustness
        response = requests.get(url, timeout=request_timeout_seconds)
        response_text_lower = response.text.strip().lower()
        not_found_keyword_lower = not_found_keyword.strip().lower()
        response_code = int(response.status_code)
        if not_found_keyword_lower not in response_text_lower and response_code == desired_response:
            print(f"[SUCCESS] {url}")
            with open(output_file, 'a') as f:
                f.write(f"{url}\n")
        else:
            # Only print "NOT FOUND" if not in shutdown mode, to avoid clutter on exit
            if not SHUTDOWN_REQUESTED:
                print(f"[NOT FOUND] {url}")
    except requests.exceptions.Timeout:
        if not SHUTDOWN_REQUESTED:
            print(f"[TIMEOUT] {url} (took longer than {request_timeout_seconds}s)")
    except requests.exceptions.RequestException as e:
        if not SHUTDOWN_REQUESTED:
            print(f"[ERROR] {url}: {e}")
    return True

def main():
    global SHUTDOWN_REQUESTED

    print_ascii_art()

    parser = argparse.ArgumentParser(
        description="Multi-threaded API fuzzer.",
        formatter_class=argparse.RawTextHelpFormatter # For better example formatting
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the file containing API call endpoints.")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the API (e.g., https://example.com/api/).")
    parser.add_argument("-k", "--not-found-keyword", required=True, help="String to consider as a 'not found' keyword in the response.")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file to save successful API calls.")
    parser.add_argument("-c", "--concurrency", type=int, default=10,
                        help="Number of threads to use (default: 10). Renamed from -t to avoid conflict.")
    parser.add_argument("-t", "--timeout", type=int, default=5000,
                        help="Timeout for each request in milliseconds (default: 5000ms).")
    parser.add_argument("-r", "--response", type=int, default=200,
                        help="Desired response code (default: 200).")

    parser.epilog = """
Example:
  python3 fuzzer.py -u https://api.example.com/api/ -f endpoint_wordlist.txt -o endpointurls.txt -k "Not Found" -t 250 -c 3000 -r 200
"""

    args = parser.parse_args()

    desired_response = args.response
    # Convert milliseconds to seconds for requests.get timeout
    request_timeout_seconds = args.timeout / 1000.0

    # Ensure the URL ends with a '/'
    if not args.url.endswith('/'):
        args.url += '/'

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
    print(f"Base URL: {args.url}")
    print(f"Not Found Keyword: '{args.not_found_keyword}' (case-insensitive check)")
    print(f"Request Timeout: {args.timeout}ms ({request_timeout_seconds}s)")
    print(f"Output File: {args.output}")

    # Clear the output file if it exists from a previous run
    open(args.output, 'w').close()

    futures = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        try:
            for endpoint in api_endpoints:
                future = executor.submit(fuzz_api_call, args.url, endpoint,
                                         args.not_found_keyword, args.output,
                                         request_timeout_seconds)
                futures.append(future)

            # Keep the main thread alive while workers are busy, allowing for keyboard interrupt
            while futures:
                # wait returns two sets: done and not_done
                done, not_done = wait(futures, timeout=1, return_when=FIRST_COMPLETED)
                for f in done:
                    # Check if the task completed successfully and if shutdown was requested
                    # f.result() returns False if SHUTDOWN_REQUESTED was True in fuzz_api_call
                    if f.done() and f.exception() is None and not f.result():
                        SHUTDOWN_REQUESTED = True # Ensure global flag is set if a thread indicates it
                futures[:] = not_done # Update the list of pending futures

                if SHUTDOWN_REQUESTED:
                    print("\nKeyboardInterrupt detected. Shutting down threads gracefully...")
                    break # Exit the loop, allowing the executor to join threads

        except KeyboardInterrupt:
            print("\nKeyboardInterrupt detected. Setting shutdown flag...")
            SHUTDOWN_REQUESTED = True
            # No need to explicitly shutdown here, the `while futures` loop will handle it
            # or the `with` block will automatically join threads upon exiting

    print("\nAPI fuzzing complete or gracefully interrupted.")

if __name__ == "__main__":
    main()
