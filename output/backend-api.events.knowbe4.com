FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
events,https://backend-api.events.knowbe4.com/events,,7211,401,0,1,1,text/html,72.005394ms,
groups,https://backend-api.events.knowbe4.com/groups,,8645,401,0,1,1,text/html,71.837689ms,
health,https://backend-api.events.knowbe4.com/health,,8822,200,31,2,1,application/json; charset=utf-8,69.785344ms,
robots.txt,https://backend-api.events.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,68.682919ms,
sources,https://backend-api.events.knowbe4.com/sources,,16905,401,0,1,1,text/html,69.98938ms,
stats,https://backend-api.events.knowbe4.com/stats,,17194,401,0,1,1,text/html,71.063772ms,
statuses,https://backend-api.events.knowbe4.com/statuses,,17204,401,0,1,1,text/html,70.085491ms,
