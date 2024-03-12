FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
403,https://elb-od-starfield.modstore.internal.knowbe4.com/403,,576,200,1896,516,103,text/html,94.131667ms,
404,https://elb-od-starfield.modstore.internal.knowbe4.com/404,,577,200,1935,527,104,text/html,164.259916ms,
422,https://elb-od-starfield.modstore.internal.knowbe4.com/422,,598,200,1916,521,104,text/html,106.716758ms,
500,https://elb-od-starfield.modstore.internal.knowbe4.com/500,,660,200,2030,551,105,text/html,88.406571ms,
favicon.ico,https://elb-od-starfield.modstore.internal.knowbe4.com/favicon.ico,,7429,200,341,1,5,image/vnd.microsoft.icon,175.389127ms,
health,https://elb-od-starfield.modstore.internal.knowbe4.com/health,,8822,200,47,6,1,text/plain; charset=utf-8,256.599752ms,
logout,https://elb-od-starfield.modstore.internal.knowbe4.com/logout,https://od-starfield.kmsat.internal.knowbe4.com/spa/auth/logout?resource_type=admin,11080,302,149,5,1,text/html; charset=utf-8,614.196745ms,
robots.txt,https://elb-od-starfield.modstore.internal.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,94.975329ms,
