from flask import Flask, render_template, request
import ipaddress
import socket
from urllib.parse import urlparse, urljoin
import requests

app = Flask(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Restricts permitted sources for scripts, styles, images, and other page resources.",
        "recommendation": "Review the site's needs and configure a suitable Content-Security-Policy."
    },
    "Strict-Transport-Security": {
        "description": "Tells supporting browsers to use HTTPS for future connections.",
        "recommendation": "For HTTPS sites, configure HSTS with an appropriate max-age."
    },
    "X-Content-Type-Options": {
        "description": "Helps prevent MIME-type sniffing.",
        "recommendation": "Consider setting X-Content-Type-Options: nosniff."
    },
    "X-Frame-Options": {
        "description": "Controls whether the page can be embedded in frames.",
        "recommendation": "Consider DENY or SAMEORIGIN if compatible with the site."
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information browsers send.",
        "recommendation": "Consider a policy such as strict-origin-when-cross-origin."
    },
    "Permissions-Policy": {
        "description": "Controls access to supported browser features.",
        "recommendation": "Define a policy appropriate for the site's required features."
    }
}

def is_public_ip(address):
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False

def validate_url(url):
    """Basic educational SSRF safeguards; not sufficient for public deployment."""
    if not url or len(url) > 2048:
        return False, "Please enter a valid website URL."

    if any(ord(ch) < 32 or ch == "\\" for ch in url):
        return False, "The URL contains invalid characters."

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are allowed."
        if not parsed.hostname or parsed.username or parsed.password:
            return False, "Enter a valid URL without embedded credentials."
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return False, "The port number is invalid."
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname == "localhost" or hostname.endswith(".localhost"):
            return False, "Localhost destinations are not allowed."
        # Resolve host and reject any non-public address.
        infos = socket.getaddrinfo(
            hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )
        addresses = {info[4][0] for info in infos}
        if not addresses or any(not is_public_ip(addr) for addr in addresses):
            return False, "Private or non-public destinations are not allowed."
        return True, ""
    except (ValueError, OSError, socket.gaierror):
        return False, "The URL is invalid or its hostname could not be resolved."

def check_website(url):
    """Fetch response headers, checking each redirect destination."""
    current_url = url
    try:
        for _ in range(6):
            valid, message = validate_url(current_url)
            if not valid:
                return {"error": message}

            response = requests.get(
                current_url,
                timeout=(4, 8),
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": "FOIS-Website-Security-Header-Checker/1.0"}
            )

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                response.close()
                if not location:
                    return {"error": "The website returned a redirect without a Location header."}
                current_url = urljoin(current_url, location)
                continue

            status_code = response.status_code
            headers = response.headers
            results = []
            present_count = 0

            for name, details in SECURITY_HEADERS.items():
                value = headers.get(name)
                present = bool(value)
                if present:
                    present_count += 1
                results.append({
                    "name": name,
                    "status": "Present" if present else "Missing",
                    "value": value if present else "Not detected",
                    "description": details["description"],
                    "recommendation": details["recommendation"]
                })

            response.close()
            total = len(SECURITY_HEADERS)
            return {
                "url": current_url,
                "status_code": status_code,
                "results": results,
                "present_count": present_count,
                "total": total,
                "score": round(present_count / total * 100)
            }

        return {"error": "Too many redirects."}
    except requests.exceptions.SSLError:
        return {"error": "TLS certificate verification failed. Check the website certificate and your system configuration."}
    except requests.exceptions.Timeout:
        return {"error": "The website took too long to respond."}
    except requests.exceptions.RequestException:
        return {"error": "Unable to connect to the website. Check the URL and your internet connection."}
    except Exception:
        app.logger.exception("Unexpected error while checking website")
        return {"error": "An unexpected error occurred. Check the terminal for details."}

@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    url = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if "://" not in url:
            url = "https://" + url

        valid, message = validate_url(url)
        if not valid:
            error = message
        else:
            report = check_website(url)
            if "error" in report:
                error = report["error"]
                report = None

    return render_template("index.html", report=report, error=error, url=url)

if __name__ == "__main__":
    # Local development only. Do not expose this development server publicly.
    app.run(host="127.0.0.1", port=5000, debug=False)
