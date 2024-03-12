FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
404,https://elb-od-courseware-cm.modstore.internal.knowbe4.com/404,,577,200,1935,527,104,text/html,92.816996ms,
403,https://elb-od-courseware-cm.modstore.internal.knowbe4.com/403,,576,200,1896,516,103,text/html,101.12597ms,
422,https://elb-od-courseware-cm.modstore.internal.knowbe4.com/422,,598,200,1916,521,104,text/html,106.746309ms,
500,https://elb-od-courseware-cm.modstore.internal.knowbe4.com/500,,660,200,2030,551,105,text/html,107.803861ms,
favicon.ico,https://elb-od-courseware-cm.modstore.internal.knowbe4.com/favicon.ico,,7429,200,341,1,5,image/vnd.microsoft.icon,98.310917ms,
health,https://elb-od-courseware-cm.modstore.internal.knowbe4.com/health,,8822,200,47,6,1,text/plain; charset=utf-8,197.45272ms,
logout,https://elb-od-courseware-cm.modstore.internal.knowbe4.com/logout,https://od-courseware-cm.kmsat.internal.knowbe4.com/spa/auth/logout?resource_type=admin,11080,302,153,5,1,text/html; charset=utf-8,204.294937ms,
robots.txt,https://elb-od-courseware-cm.modstore.internal.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,95.777435ms,
