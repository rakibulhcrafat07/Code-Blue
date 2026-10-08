-- Chrome history (times are WebKit epoch: microseconds since 1601-01-01)
SELECT datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS visit_utc,
       url, title, visit_count
FROM urls ORDER BY last_visit_time DESC;

-- Chrome downloads with source URL
SELECT datetime(start_time/1000000 - 11644473600, 'unixepoch') AS started_utc,
       target_path, tab_url, total_bytes
FROM downloads ORDER BY start_time DESC;
