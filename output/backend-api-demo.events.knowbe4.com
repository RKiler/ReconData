FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
events,https://backend-api-demo.events.knowbe4.com/events,,7211,401,0,1,1,text/html,145.841333ms,
groups,https://backend-api-demo.events.knowbe4.com/groups,,8645,401,0,1,1,text/html,144.839556ms,
health,https://backend-api-demo.events.knowbe4.com/health,,8822,200,31,2,1,application/json; charset=utf-8,142.272636ms,
robots.txt,https://backend-api-demo.events.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,143.089711ms,
sources,https://backend-api-demo.events.knowbe4.com/sources,,16905,401,0,1,1,text/html,142.582032ms,
stats,https://backend-api-demo.events.knowbe4.com/stats,,17194,401,0,1,1,text/html,146.020888ms,
statuses,https://backend-api-demo.events.knowbe4.com/statuses,,17204,401,0,1,1,text/html,143.215781ms,
