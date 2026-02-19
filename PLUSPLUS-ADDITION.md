  What was added

  src/requests/security.py (new)

  The core of the protection. When the module is imported it patches urllib3.util.connection.create_connection — the actual function urllib3 calls to open every TCP socket — with a thread-local-aware
  wrapper:

  1. Resolve the hostname via socket.getaddrinfo (once).
  2. Validate all resolved IPs against the configured block/allow lists.
  3. Connect directly to the validated sockaddr tuple without re-querying DNS — this is the key DNS-rebinding defence; an attacker cannot change the DNS record between validation and connect.

  The patch is a no-op (delegates to the original) when no SSRFValidator is active in the thread-local, so regular HTTPAdapter traffic is completely unaffected.

  SSRFValidator handles:
  - Default blocked ranges: all RFC-reserved/private/loopback ranges, IPv4 and IPv6 (including 169.254.0.0/16 for AWS IMDS, fc00::/7 for IPv6 ULA, 2001::/32 Teredo, etc.)
  - IPv4-mapped IPv6 (::ffff:192.168.1.1) is unwrapped before range checks
  - allowed_ranges overrides blocked_ranges for specific subnets

  src/requests/exceptions.py

  Added SSRFViolation(ConnectionError) — a subclass of requests.exceptions.ConnectionError, so existing except ConnectionError handlers still catch it.

  src/requests/adapters.py

  Added SSRFProtectedHTTPAdapter(HTTPAdapter) with:
  - Fast-path rejection of IP literals in the URL before DNS
  - Sets thread-local validator before each send(), clears it in finally (thread-safe for concurrent sessions)
  - Catches the _SSRFViolationSignal(BaseException) from the socket layer and converts it to the public SSRFViolation with the PreparedRequest attached

  Usage

  import requests
  from ipaddress import ip_network

  session = requests.Session()
  adapter = requests.SSRFProtectedHTTPAdapter(
      # Optional: permit one internal subnet while blocking everything else private
      allowed_ranges=[ip_network("10.0.1.0/24")],
  )
  session.mount("https://", adapter)
  session.mount("http://", adapter)

  try:
      session.get("http://169.254.169.254/latest/meta-data/")
  except requests.SSRFViolation as e:
      print(f"Blocked: {e}")
