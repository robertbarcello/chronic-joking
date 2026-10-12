"""Pull profile, body, recovery, cycle, sleep and workout data from the WHOOP v2 API.

Credentials come from the environment, never from this file:
    WHOOP_CLIENT_ID, WHOOP_CLIENT_SECRET   - from the WHOOP developer dashboard
    WHOOP_AUTH_CODE                        - only for the very first run
The authorize URL must request the "offline" scope, or no refresh token is issued.
"""
import json, os, time, urllib.error, urllib.parse, urllib.request

CLIENT_ID     = os.environ["WHOOP_CLIENT_ID"]
CLIENT_SECRET = os.environ["WHOOP_CLIENT_SECRET"]
AUTH_CODE     = os.environ.get("WHOOP_AUTH_CODE")   # only needed the first time

REDIRECT = os.environ.get("WHOOP_REDIRECT_URI", "https://localhost:8080/callback")
TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token"
BASE = "https://api.prod.whoop.com/developer"
STORE = "whoop_tokens.json"
UA = "whoop-dashboard/1.0"

def fetch(req):
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 4:   # rate limited (100 req/min)
                time.sleep(int(e.headers.get("Retry-After") or 2 ** (attempt + 2)))
                continue
            raise SystemExit(f"{e.code} {req.full_url}: {e.read().decode(errors='replace')}")

def post(data):
    return fetch(urllib.request.Request(
        TOKEN_URL, data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": UA}))

def save(t):
    # atomic + private: each refresh kills the old pair, so a torn write locks you out
    tmp = STORE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(t, f)
    os.replace(tmp, STORE)

def tokens():
    if os.path.exists(STORE):
        with open(STORE) as f:
            t = json.load(f)
        if t["expires_at"] > time.time() + 120:
            return t
        t = post({"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                  "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "scope": "offline"})
    else:
        if not AUTH_CODE:
            raise SystemExit("No token store yet: set WHOOP_AUTH_CODE (codes are single-use and expire in minutes)")
        t = post({"grant_type": "authorization_code", "code": AUTH_CODE,
                  "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
                  "redirect_uri": REDIRECT})
    if "refresh_token" not in t:
        print("warning: no refresh_token returned - add the 'offline' scope to your authorize URL")
    t["expires_at"] = time.time() + t["expires_in"]
    save(t)   # write BEFORE using
    return t

def get(path, at):
    return fetch(urllib.request.Request(BASE + path,
        headers={"Authorization": "Bearer " + at, "User-Agent": UA}))

def page(path, at, cap=2000):
    out, tok = [], None
    while True:
        sep = "&" if "?" in path else "?"
        url = f"{path}{sep}limit=25" + (f"&nextToken={urllib.parse.quote(tok)}" if tok else "")
        d = get(url, at)
        out += d.get("records", [])
        tok = d.get("next_token")
        if not tok or len(out) >= cap:
            return out
        time.sleep(0.15)

if __name__ == "__main__":
    at = tokens()["access_token"]
    data = {
        "profile":  get("/v2/user/profile/basic", at),
        "body":     get("/v2/user/measurement/body", at),
        "recovery": page("/v2/recovery", at),
        "cycles":   page("/v2/cycle", at),
        "sleep":    page("/v2/activity/sleep", at),
        "workouts": page("/v2/activity/workout", at),
    }
    with open("whoop_data.json", "w") as f:
        json.dump(data, f, indent=2)
    print({k: (len(v) if isinstance(v, list) else 1) for k, v in data.items()})
