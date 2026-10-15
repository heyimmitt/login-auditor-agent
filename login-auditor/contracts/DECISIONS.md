# Decisions (frozen unless both agree)

1. Target OS: Ubuntu (/var/log/auth.log).
2. Timezone: Asia/Kolkata. All datetimes in code are timezone-aware.
3. Business hours: Mon-Fri, 09:00 inclusive to 18:00 exclusive (config/policy.yaml).
4. Windows: this_week = Mon 00:00 -> now; yesterday = prev day 00:00-24:00;
   last_night = 18:00 yesterday -> 06:00 today; last_7_days = now-7d -> now.
5. "Logged in as root" = direct root login. sudo/su to root are separate event types.
6. Sources: `last -F` and auth.log; no dedup in MVP (events keep a `source` label).
7. Event types: login_success, login_failure, sudo_root, su_root.
8. audit() statuses: ok, no_matches, needs_clarification, error.
9. Handoff: A's run_query returns ALL events for user/type/window; B applies business hours.
10. Escalations: for sudo_root and su_root, `user` = "root" and `actor` = the account that ran
    sudo/su. `actor` is None for login events.
