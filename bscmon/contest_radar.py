#!/usr/bin/env python3
"""
contest_radar.py v3 — LIVE audit-contest monitor across platforms.

Strategy: in a contest, a valid H/M pays even if duplicated (no "hardened deployment = $0"
problem of cold-hunting). The binding constraint is *being in a live EVM contest on Day 1*
(max time, freshest code, best dup odds). This radar finds them and alerts on NEW ones.

Sources (parsing actually correct this time):
  - Sherlock : https://mainnet-contest.sherlock.xyz/contests  (paginated, data under `items`;
               classify LIVE/UPCOMING via starts_at/ends_at vs now; has prize_pool + dates)
  - Cantina  : https://cantina.xyz/api/v0/competitions          (status=='live'; totalRewardPot)
  - Code4rena: GitHub org `code-423n4` repo-creation feed       (a public repo is created when an
               audit goes live; the /audits HTML hides live ones behind JS — the org feed doesn't)

Run: python contest_radar.py [--state D:/CLAUDE/contest_state.json] [--days 25]
State tracks seen ids; prints a full LIVE/UPCOMING board + flags NEW since last run.
"""
import argparse, json, sys, time, urllib.request
from pathlib import Path

UA = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
GH_UA = {"User-Agent": "contest-radar", "Accept": "application/vnd.github+json"}


def _get(url, hdr=UA, timeout=45):
    return urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout).read().decode("utf-8", "replace")


def _safe(s):
    return str(s).encode("ascii", "replace").decode("ascii")


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def scan_sherlock(now):
    out, page = [], 1
    while page <= 8:
        try:
            d = json.loads(_get(f"https://mainnet-contest.sherlock.xyz/contests?page={page}"))
        except Exception as e:
            sys.stderr.write(f"[sherlock] page {page} err: {_safe(e)[:80]}\n"); break
        items = d.get("items", [])
        for c in items:
            s, e = c.get("starts_at"), c.get("ends_at")
            if not (s and e):
                continue
            status = "LIVE" if s <= now < e else ("UPCOMING" if s > now else "ended")
            if status == "ended":
                continue
            out.append({
                "source": "sherlock", "id": f"sherlock-{c.get('id')}",
                "title": c.get("title") or c.get("name") or "?",
                "status": status, "prize_pool_usd": c.get("prize_pool"),
                "starts_at": s, "ends_at": e,
                "url": f"https://audits.sherlock.xyz/contests/{c.get('id')}",
            })
        if not d.get("next_page"):
            break
        page += 1
    return out


def scan_cantina(now):
    out = []
    try:
        d = json.loads(_get("https://cantina.xyz/api/v0/competitions"))
    except Exception as e:
        sys.stderr.write(f"[cantina] err: {_safe(e)[:80]}\n"); return out
    comps = d if isinstance(d, list) else d.get("competitions", [])
    for c in comps:
        st = str(c.get("status", "")).lower()
        if st not in ("live", "active", "open", "upcoming"):
            continue
        out.append({
            "source": "cantina", "id": f"cantina-{c.get('id')}",
            "title": c.get("name") or c.get("title") or "?",
            "status": st.upper(), "prize_pool_usd": c.get("totalRewardPot"),
            "starts_at": None, "ends_at": None,
            "url": c.get("url") or f"https://cantina.xyz/competitions/{c.get('id')}",
        })
    return out


def scan_c4(now, days):
    """A code-423n4 repo is created when an audit goes live. Newest repos within `days` = live/recent."""
    out = []
    try:
        repos = json.loads(_get("https://api.github.com/orgs/code-423n4/repos?sort=created&direction=desc&per_page=20", hdr=GH_UA))
    except Exception as e:
        sys.stderr.write(f"[c4] err: {_safe(e)[:80]}\n"); return out
    cutoff = now - days * 86400
    for r in repos:
        created = r.get("created_at", "")
        try:
            ts = time.mktime(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            continue
        if ts < cutoff:
            continue
        nm = r.get("name", "").lower()
        if any(k in nm for k in ("submissions-tmp", "bug-bounty", "-tmp-")):
            continue  # skip bounty/temp repos
        out.append({
            "source": "c4", "id": f"c4-{r.get('name')}", "title": r.get("name"),
            "status": "LIVE?", "prize_pool_usd": None,
            "starts_at": int(ts), "ends_at": None,
            "url": r.get("html_url"),
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default="D:/CLAUDE/contest_state.json")
    ap.add_argument("--days", type=int, default=25, help="C4: treat repos created within N days as live/recent")
    args = ap.parse_args()
    now = time.time()

    state_path = Path(args.state)
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {"seen": [], "last_run": None}
    seen = set(state.get("seen", []))

    contests = []
    for nm, fn in [("sherlock", lambda: scan_sherlock(now)), ("cantina", lambda: scan_cantina(now)), ("c4", lambda: scan_c4(now, args.days))]:
        sys.stderr.write(f"[{nm}] scanning...\n")
        try:
            contests += fn()
        except Exception as e:
            sys.stderr.write(f"[{nm}] FAILED: {_safe(e)[:80]}\n")

    live = [c for c in contests if c["status"] in ("LIVE", "LIVE?")]
    upcoming = [c for c in contests if c["status"] == "UPCOMING"]
    new = [c for c in contests if c["id"] not in seen]
    for c in contests:
        seen.add(c["id"])

    def line(c):
        pz = c.get("prize_pool_usd")
        pzs = f"${_num(pz):,.0f}" if pz not in (None, "") else "?"
        ends = time.strftime("%Y-%m-%d", time.gmtime(c["ends_at"])) if c.get("ends_at") else "?"
        return f"  [{c['source']:8}] {c['status']:9} {pzs:>10}  ends {ends}  {_safe(c['title'])[:42]}\n     {c['url']}"

    print("=" * 64)
    print(f"CONTEST RADAR v3 — {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))}")
    print("=" * 64)
    print(f"\nLIVE NOW ({len(live)}):")
    for c in sorted(live, key=lambda x: -_num(x.get("prize_pool_usd"))):
        print(line(c))
    if not live:
        print("  (none -- contest lull; cold-hunt or wait for the monitor to fire)")
    print(f"\nUPCOMING ({len(upcoming)}):")
    for c in sorted(upcoming, key=lambda x: x.get("starts_at") or 0):
        print(line(c))
    if not upcoming:
        print("  (none announced)")
    if new:
        print(f"\n*** {len(new)} NEW since last run ***")
        for c in new:
            print(line(c))

    # ---- Telegram: STRIKE signal on newly-LIVE + heads-up on newly-announced ----
    def _txt(c):
        pz = c.get("prize_pool_usd"); pzs = f"${_num(pz):,.0f}" if pz not in (None, "") else "?"
        ends = time.strftime("%Y-%m-%d", time.gmtime(c["ends_at"])) if c.get("ends_at") else "?"
        return f"{c['source']} {pzs} ends {ends} — {_safe(c['title'])[:60]}\n{c['url']}"
    alerted = set(state.get("alerted_live", []))
    alerts = []
    for c in sorted(live, key=lambda x: -_num(x.get("prize_pool_usd"))):
        if c["id"] not in alerted:                      # first time we see it LIVE
            alerts.append("\U0001F7E2 CONTEST LIVE — audit + fork-confirm now:\n" + _txt(c))
            alerted.add(c["id"])
    for c in new:
        if c.get("status") == "UPCOMING":               # new announcement = prep window
            alerts.append("\U0001F7E1 New contest announced (prep):\n" + _txt(c))
    if alerts:
        notify("CONTEST RADAR\n\n" + "\n\n".join(alerts))
    state["alerted_live"] = sorted(alerted)[-2000:]

    state["seen"] = sorted(seen)[-4000:]
    state["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def notify(text):
    """push to Telegram (same bot as the BSC monitor); no-op if creds absent."""
    import os, urllib.request, urllib.parse
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (tok and chat):
        return
    try:
        data = urllib.parse.urlencode({"chat_id": chat, "text": text,
                                       "disable_web_page_preview": "true"}).encode()
        urllib.request.urlopen(urllib.request.Request(
            "https://api.telegram.org/bot%s/sendMessage" % tok, data), timeout=15)
    except Exception:
        pass


if __name__ == "__main__":
    main()
