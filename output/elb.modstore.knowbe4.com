FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
404,https://elb.modstore.knowbe4.com/404,,577,200,1935,527,104,text/html,70.203662ms,
403,https://elb.modstore.knowbe4.com/403,,576,200,1896,516,103,text/html,76.163882ms,
422,https://elb.modstore.knowbe4.com/422,,598,200,1916,521,104,text/html,74.854335ms,
500,https://elb.modstore.knowbe4.com/500,,660,200,2030,551,105,text/html,69.431771ms,
favicon.ico,https://elb.modstore.knowbe4.com/favicon.ico,,7429,200,341,1,5,image/vnd.microsoft.icon,83.408403ms,
health,https://elb.modstore.knowbe4.com/health,,8822,200,47,6,1,text/plain; charset=utf-8,73.389711ms,
logout,https://elb.modstore.knowbe4.com/logout,https://training.knowbe4.com/spa/auth/logout?resource_type=admin,11080,302,130,5,1,text/html; charset=utf-8,76.233385ms,
robots.txt,https://elb.modstore.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,70.298634ms,
