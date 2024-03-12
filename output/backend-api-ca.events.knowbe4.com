FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
events,https://backend-api-ca.events.knowbe4.com/events,,7211,401,0,1,1,text/html,78.843547ms,
groups,https://backend-api-ca.events.knowbe4.com/groups,,8645,401,0,1,1,text/html,79.351175ms,
health,https://backend-api-ca.events.knowbe4.com/health,,8822,200,31,2,1,application/json; charset=utf-8,80.296888ms,
robots.txt,https://backend-api-ca.events.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,78.953315ms,
sources,https://backend-api-ca.events.knowbe4.com/sources,,16905,401,0,1,1,text/html,79.306776ms,
stats,https://backend-api-ca.events.knowbe4.com/stats,,17194,401,0,1,1,text/html,79.429213ms,
statuses,https://backend-api-ca.events.knowbe4.com/statuses,,17204,401,0,1,1,text/html,79.674009ms,
