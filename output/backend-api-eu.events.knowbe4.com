FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
events,https://backend-api-eu.events.knowbe4.com/events,,7211,401,0,1,1,text/html,155.083453ms,
groups,https://backend-api-eu.events.knowbe4.com/groups,,8645,401,0,1,1,text/html,153.527081ms,
health,https://backend-api-eu.events.knowbe4.com/health,,8822,200,31,2,1,application/json; charset=utf-8,151.547871ms,
robots.txt,https://backend-api-eu.events.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,151.245586ms,
sources,https://backend-api-eu.events.knowbe4.com/sources,,16905,401,0,1,1,text/html,149.295338ms,
stats,https://backend-api-eu.events.knowbe4.com/stats,,17194,401,0,1,1,text/html,156.390272ms,
statuses,https://backend-api-eu.events.knowbe4.com/statuses,,17204,401,0,1,1,text/html,152.943794ms,
