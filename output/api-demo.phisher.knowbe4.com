FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
404,https://api-demo.phisher.knowbe4.com/404,,577,200,1722,310,68,text/html,150.793183ms,
422,https://api-demo.phisher.knowbe4.com/422,,598,200,1705,305,68,text/html,149.007484ms,
500,https://api-demo.phisher.knowbe4.com/500,,660,200,1635,289,67,text/html,151.575148ms,
favicon.ico,https://api-demo.phisher.knowbe4.com/favicon.ico,,7429,200,0,1,1,image/vnd.microsoft.icon,151.639095ms,
health,https://api-demo.phisher.knowbe4.com/health,,8822,200,31,2,1,application/json; charset=utf-8,149.400501ms,
robots.txt,https://api-demo.phisher.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,148.736086ms,
