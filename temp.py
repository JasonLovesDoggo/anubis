import requests
import re
import time
import argparse

def fetch_head(url, full_request=False):
    try:
        start_time = time.time()

        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)

        if full_request:
            print(response.text)
        else:
            # Extract the <head> section using regex
            match = re.search(r"<head>(.*?)</head>", response.text, re.DOTALL | re.IGNORECASE)

            if match:
                head_content = match.group(1)
                formatted_head = re.sub(r">\s*<", ">\n<", head_content)  # Add new lines between tags
                print("<head>\n" + formatted_head + "\n</head>")
            else:
                print("<head> section not found.")

        end_time = time.time()
        print(f"Time taken: {end_time - start_time:.4f} seconds")
    except requests.RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--full", action="store_true", help="Print the full response body")
    args = parser.parse_args()

    fetch_head("http://localhost:8923/test.html", full_request=args.full)
