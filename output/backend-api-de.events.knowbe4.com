FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
events,https://backend-api-de.events.knowbe4.com/events,,7211,401,0,1,1,text/html,150.634237ms,
groups,https://backend-api-de.events.knowbe4.com/groups,,8645,401,0,1,1,text/html,153.810578ms,
health,https://backend-api-de.events.knowbe4.com/health,,8822,200,31,2,1,application/json; charset=utf-8,147.685176ms,
robots.txt,https://backend-api-de.events.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,150.753933ms,
sources,https://backend-api-de.events.knowbe4.com/sources,,16905,401,0,1,1,text/html,152.400874ms,
stats,https://backend-api-de.events.knowbe4.com/stats,,17194,401,0,1,1,text/html,150.516298ms,
statuses,https://backend-api-de.events.knowbe4.com/statuses,,17204,401,0,1,1,text/html,144.948588ms,
