#!/usr/bin/env python3
"""Pull the last N days of WHOOP data via the official v2 API and save a
cleaned, per-day joined result to whoop_data.json.

Credentials come from the environment (never hard-code them):
    export WHOOP_CLIENT_ID=...
    export WHOOP_CLIENT_SECRET=...
    python3 whoop_sync.py            # opens browser, catches localhost:8080/callback
    python3 whoop_sync.py --manual   # headless: paste the redirected URL instead

Requires: pip install requests
"""

import argparse
import json
import os
import secrets
import string
import sys
import threading
import time
import webbrowser
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import requests

AUTH_URL = "https://api.prod.whoop.com/oauth/oauth2/auth"
TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token"
API_BASE = "https://api.prod.whoop.com/developer/v2"
REDIRECT_URI = os.environ.get("WHOOP_REDIRECT_URI", "http://localhost:8080/callback")
SCOPES = [
    "read:recovery", "read:cycles", "read:sleep", "read:workout",
    "read:profile", "read:body_measurement", "offline",
]
TOKEN_FILE = ".whoop_tokens.json"
OUT_FILE = "whoop_data.json"

# Which scope each endpoint needs, so a 403 can be reported precisely.
ENDPOINT_SCOPE = {
    "/recovery": "read:recovery",
    "/cycle": "read:cycles",
    "/activity/sleep": "read:sleep",
    "/activity/workout": "read:workout",
    "/user/profile/basic": "read:profile",
    "/user/measurement/body": "read:body_measurement",
}


class ScopeError(Exception):
    pass


# --------------------------------------------------------------------------- auth

def client_creds():
    cid = os.environ.get("WHOOP_CLIENT_ID")
    secret = os.environ.get("WHOOP_CLIENT_SECRET")
    if not cid or not secret:
        sys.exit("Set WHOOP_CLIENT_ID and WHOOP_CLIENT_SECRET in your environment.")
    return cid, secret


def save_tokens(tok):
    tok["expires_at"] = time.time() + int(tok.get("expires_in", 3600)) - 60
    with open(TOKEN_FILE, "w") as f:
        json.dump(tok, f, indent=2)
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass
    return tok


def load_tokens():
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE) as f:
        return json.load(f)


def check_granted_scopes(tok):
    granted = set((tok.get("scope") or "").split())
    if not granted:
        return  # server didn't echo scopes; endpoint 403s will catch it
    missing = [s for s in SCOPES if s not in granted]
    if missing:
        print(f"WARNING: token is missing scopes: {', '.join(missing)}")
        if "offline" in missing:
            print("  -> no refresh token will be issued; you'll need to re-auth hourly.")


def random_state(n=8):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _wait_for_callback(state):
    """Run a one-shot server on the redirect URI's port and return the query dict."""
    parsed = urlparse(REDIRECT_URI)
    result = {}
    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            u = urlparse(self.path)
            if u.path != parsed.path:
                self.send_response(404)
                self.end_headers()
                return
            result.update({k: v[0] for k, v in parse_qs(u.query).items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            msg = "WHOOP authorised - you can close this tab." if "code" in result \
                else f"WHOOP auth failed: {result.get('error_description') or result.get('error')}"
            self.wfile.write(f"<html><body><h3>{msg}</h3></body></html>".encode())
            done.set()

        def log_message(self, *a):
            pass

    server = HTTPServer((parsed.hostname, parsed.port or 80), Handler)
    t = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.2), daemon=True)
    t.start()
    done.wait(timeout=300)
    server.shutdown()
    if not result:
        sys.exit("Timed out waiting for the OAuth callback.")
    return result


def authorize(manual=False):
    cid, secret = client_creds()
    state = random_state()
    url = AUTH_URL + "?" + urlencode({
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES),
        "state": state,
    })
    print("Open this URL to authorise:\n  " + url)

    if manual:
        pasted = input("\nAfter approving, paste the full URL your browser landed on:\n> ").strip()
        params = {k: v[0] for k, v in parse_qs(urlparse(pasted).query).items()}
    else:
        webbrowser.open(url)
        params = _wait_for_callback(state)

    if "error" in params:
        err = params.get("error")
        desc = params.get("error_description", "")
        if err == "invalid_scope":
            sys.exit(f"Auth refused a scope ({desc}). Enable all of {SCOPES} on your WHOOP app.")
        sys.exit(f"Auth error: {err} {desc}")
    if params.get("state") != state:
        sys.exit("State mismatch - possible CSRF, aborting.")

    r = requests.post(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "code": params["code"],
        "redirect_uri": REDIRECT_URI,
        "client_id": cid,
        "client_secret": secret,
    }, timeout=30)
    if r.status_code != 200:
        sys.exit(f"Token exchange failed: {r.status_code} {r.text}")
    tok = save_tokens(r.json())
    if not tok.get("refresh_token"):
        print("WARNING: no refresh_token returned (is the 'offline' scope granted?)")
    check_granted_scopes(tok)
    return tok


def refresh(tok):
    cid, secret = client_creds()
    r = requests.post(TOKEN_URL, data={
        "grant_type": "refresh_token",
        "refresh_token": tok["refresh_token"],
        "client_id": cid,
        "client_secret": secret,
        "scope": "offline",
    }, timeout=30)
    if r.status_code != 200:
        print(f"Refresh failed ({r.status_code}); starting a fresh login.")
        return None
    new = r.json()
    new.setdefault("refresh_token", tok["refresh_token"])
    return save_tokens(new)


class Client:
    def __init__(self, manual=False):
        self.manual = manual
        tok = load_tokens()
        if tok and time.time() >= tok.get("expires_at", 0):
            tok = refresh(tok) if tok.get("refresh_token") else None
        self.tok = tok or authorize(manual)

    def _refresh_or_reauth(self):
        new = refresh(self.tok) if self.tok.get("refresh_token") else None
        self.tok = new or authorize(self.manual)

    def get(self, path, params=None):
        if time.time() >= self.tok.get("expires_at", 0):
            self._refresh_or_reauth()
        for attempt in (1, 2):
            r = requests.get(API_BASE + path, params=params, timeout=30,
                             headers={"Authorization": f"Bearer {self.tok['access_token']}"})
            if r.status_code == 401 and attempt == 1:
                self._refresh_or_reauth()  # refresh and retry once
                continue
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 30))
                print(f"  rate limited, sleeping {wait}s")
                time.sleep(wait)
                continue
            if r.status_code == 403:
                raise ScopeError(ENDPOINT_SCOPE.get(path, path))
            r.raise_for_status()
            return r.json()
        r.raise_for_status()

    def collection(self, path, start, end):
        out, token = [], None
        while True:
            params = {"limit": 25, "start": start, "end": end}
            if token:
                params["nextToken"] = token
            page = self.get(path, params)
            out.extend(page.get("records", []))
            token = page.get("next_token")
            if not token:
                return out


# ---------------------------------------------------------------------- normalise

def ms_to_hm(ms):
    if ms is None:
        return None
    total_min = round(ms / 60000)
    return {"hours": round(ms / 3_600_000, 2), "hm": f"{total_min // 60}h {total_min % 60:02d}m"}


def kj_to_kcal(kj):
    return None if kj is None else round(kj / 4.184, 1)


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def local_date(ts, offset, shift_hours=0):
    """Calendar date of a UTC timestamp in the wearer's local offset (e.g. '-05:00')."""
    dt = parse_ts(ts) + timedelta(hours=shift_hours)
    if offset:
        sign = -1 if offset.startswith("-") else 1
        hh, mm = offset.lstrip("+-").split(":")
        dt = dt.astimezone(timezone(sign * timedelta(hours=int(hh), minutes=int(mm))))
    else:
        dt = dt.astimezone()  # fall back to this machine's timezone
    return dt.date().isoformat()


def r1(x, n=1):
    return None if x is None else round(x, n)


def norm_cycle(c):
    s = c.get("score") or {}
    return {
        "cycle_id": c["id"],
        "start": c.get("start"),
        "end": c.get("end"),
        "timezone_offset": c.get("timezone_offset"),
        "score_state": c.get("score_state"),
        "strain": r1(s.get("strain"), 2),
        "calories": kj_to_kcal(s.get("kilojoule")),
        "average_heart_rate": s.get("average_heart_rate"),
        "max_heart_rate": s.get("max_heart_rate"),
    }


def norm_recovery(r):
    s = r.get("score") or {}
    return {
        "cycle_id": r.get("cycle_id"),
        "sleep_id": r.get("sleep_id"),
        "score_state": r.get("score_state"),
        "recovery_score": s.get("recovery_score"),
        "resting_heart_rate": s.get("resting_heart_rate"),
        "hrv_rmssd_ms": r1(s.get("hrv_rmssd_milli"), 1),
        "spo2_percentage": r1(s.get("spo2_percentage")),
        "skin_temp_celsius": r1(s.get("skin_temp_celsius"), 2),
        "user_calibrating": s.get("user_calibrating"),
    }


def norm_sleep(sl):
    s = sl.get("score") or {}
    st = s.get("stage_summary") or {}
    asleep = None
    parts = [st.get(k) for k in ("total_light_sleep_time_milli",
                                 "total_slow_wave_sleep_time_milli",
                                 "total_rem_sleep_time_milli")]
    if all(p is not None for p in parts):
        asleep = sum(parts)
    return {
        "sleep_id": sl["id"],
        "cycle_id": sl.get("cycle_id"),
        "nap": sl.get("nap"),
        "start": sl.get("start"),
        "end": sl.get("end"),
        "score_state": sl.get("score_state"),
        "sleep_performance_percentage": s.get("sleep_performance_percentage"),
        "sleep_efficiency_percentage": r1(s.get("sleep_efficiency_percentage")),
        "sleep_consistency_percentage": s.get("sleep_consistency_percentage"),
        "respiratory_rate": r1(s.get("respiratory_rate")),
        "stages": {
            "in_bed": ms_to_hm(st.get("total_in_bed_time_milli")),
            "asleep": ms_to_hm(asleep),
            "light": ms_to_hm(st.get("total_light_sleep_time_milli")),
            "deep": ms_to_hm(st.get("total_slow_wave_sleep_time_milli")),
            "rem": ms_to_hm(st.get("total_rem_sleep_time_milli")),
            "awake": ms_to_hm(st.get("total_awake_time_milli")),
            "sleep_cycle_count": st.get("sleep_cycle_count"),
            "disturbance_count": st.get("disturbance_count"),
        },
    }


def norm_workout(w):
    s = w.get("score") or {}
    zones = s.get("zone_durations") or {}
    names = ["zero", "one", "two", "three", "four", "five"]
    return {
        "workout_id": w["id"],
        "date": local_date(w["start"], w.get("timezone_offset")),
        "start": w.get("start"),
        "end": w.get("end"),
        "duration": ms_to_hm((parse_ts(w["end"]) - parse_ts(w["start"])).total_seconds() * 1000)
        if w.get("end") else None,
        "sport_name": w.get("sport_name"),
        "score_state": w.get("score_state"),
        "strain": r1(s.get("strain"), 2),
        "average_heart_rate": s.get("average_heart_rate"),
        "max_heart_rate": s.get("max_heart_rate"),
        "calories": kj_to_kcal(s.get("kilojoule")),
        "distance_km": r1(s["distance_meter"] / 1000, 2) if s.get("distance_meter") is not None else None,
        "zone_durations": {f"zone_{n}": ms_to_hm(zones.get(f"zone_{n}_milli")) for n in names},
    }


def build(raw, start_day, end_day):
    cycles = [norm_cycle(c) for c in raw["cycles"]]
    rec_by_cycle = {r["cycle_id"]: norm_recovery(r) for r in raw["recoveries"]}
    sleeps = [norm_sleep(s) for s in raw["sleeps"]]
    sleep_by_id = {s["sleep_id"]: s for s in sleeps}
    main_sleep_by_cycle, naps_by_cycle = {}, {}
    for s in sleeps:
        if s["nap"]:
            naps_by_cycle.setdefault(s["cycle_id"], []).append(s)
        else:
            main_sleep_by_cycle.setdefault(s["cycle_id"], s)
    workouts = [norm_workout(w) for w in raw["workouts"]]
    workouts_by_day = {}
    for w in workouts:
        workouts_by_day.setdefault(w["date"], []).append(w)

    days = {}
    for c in sorted(cycles, key=lambda c: c["start"]):
        # A cycle starts at sleep onset (usually late evening), so the day it belongs
        # to is the one you wake into - the same labelling the WHOOP app uses.
        d = local_date(c["start"], c["timezone_offset"], shift_hours=12)
        rec = rec_by_cycle.get(c["cycle_id"])
        # Prefer the sleep the recovery was computed from; else the cycle's main sleep.
        sl = (sleep_by_id.get(rec["sleep_id"]) if rec else None) or main_sleep_by_cycle.get(c["cycle_id"])
        days.setdefault(d, {
            "date": d,
            "cycle": c,
            "recovery": rec,
            "sleep": sl,
            "naps": naps_by_cycle.get(c["cycle_id"], []),
            "workouts": workouts_by_day.get(d, []),
        })

    # Gap report over the full requested window.
    all_days, d = [], start_day
    while d <= end_day:
        all_days.append(d.isoformat())
        d += timedelta(days=1)
    gaps = {
        "no_cycle": [x for x in all_days if x not in days],
        "no_recovery": [x for x in all_days if x in days and not days[x]["recovery"]],
        "no_sleep": [x for x in all_days if x in days and not days[x]["sleep"]],
        "unscored_recovery": [x for x, v in days.items()
                              if v["recovery"] and v["recovery"]["score_state"] != "SCORED"],
    }
    keys = sorted(days)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window": {"start": start_day.isoformat(), "end": end_day.isoformat(), "days_requested": len(all_days)},
        "coverage": {
            "first_day_with_data": keys[0] if keys else None,
            "last_day_with_data": keys[-1] if keys else None,
            "days_with_data": len(keys),
            "counts": {k: len(v) for k, v in raw.items() if isinstance(v, list)},
        },
        "gaps": gaps,
        "profile": raw.get("profile"),
        "body_measurement": raw.get("body"),
        "days": {k: days[k] for k in sorted(days, reverse=True)},
    }


# ---------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=180)
    ap.add_argument("--manual", action="store_true",
                    help="paste the redirect URL instead of running a local callback server")
    args = ap.parse_args()

    client = Client(manual=args.manual)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=args.days)
    iso = lambda dt: dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    raw, missing = {}, []
    for key, path in [("recoveries", "/recovery"), ("cycles", "/cycle"),
                      ("sleeps", "/activity/sleep"), ("workouts", "/activity/workout")]:
        try:
            raw[key] = client.collection(path, iso(start), iso(now))
            print(f"{path:20s} {len(raw[key]):4d} records")
        except ScopeError as e:
            missing.append(str(e))
            raw[key] = []
    for key, path in [("profile", "/user/profile/basic"), ("body", "/user/measurement/body")]:
        try:
            raw[key] = client.get(path)
        except ScopeError as e:
            missing.append(str(e))
            raw[key] = None

    if missing:
        print(f"MISSING SCOPES (403): {', '.join(missing)} - enable them on your app and re-auth.")

    local_today = datetime.now().astimezone().date()
    result = build(raw, local_today - timedelta(days=args.days), local_today)
    result["missing_scopes"] = missing
    with open(OUT_FILE, "w") as f:
        json.dump(result, f, indent=2)

    cov, gaps = result["coverage"], result["gaps"]
    print(f"\nSaved {OUT_FILE}")
    print(f"Window:     {result['window']['start']} -> {result['window']['end']} "
          f"({result['window']['days_requested']} days)")
    print(f"Data range: {cov['first_day_with_data']} -> {cov['last_day_with_data']} "
          f"({cov['days_with_data']} days with a cycle)")
    for k, v in gaps.items():
        print(f"  {k:18s} {len(v):3d}" + (f"  e.g. {', '.join(v[:8])}" if v else ""))


if __name__ == "__main__":
    main()
