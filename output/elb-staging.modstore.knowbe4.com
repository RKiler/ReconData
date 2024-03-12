FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile
403,https://elb-staging.modstore.knowbe4.com/403,,576,200,1896,516,103,text/html,70.316222ms,
404,https://elb-staging.modstore.knowbe4.com/404,,577,200,1935,527,104,text/html,70.215574ms,
422,https://elb-staging.modstore.knowbe4.com/422,,598,200,1916,521,104,text/html,68.572358ms,
500,https://elb-staging.modstore.knowbe4.com/500,,660,200,2030,551,105,text/html,69.495926ms,
favicon.ico,https://elb-staging.modstore.knowbe4.com/favicon.ico,,7429,200,341,1,5,image/vnd.microsoft.icon,72.084808ms,
health,https://elb-staging.modstore.knowbe4.com/health,,8822,200,47,6,1,text/plain; charset=utf-8,70.10603ms,
logout,https://elb-staging.modstore.knowbe4.com/logout,https://training-staging.knowbe4.com/spa/auth/logout?resource_type=admin,11080,302,138,5,1,text/html; charset=utf-8,73.007963ms,
robots.txt,https://elb-staging.modstore.knowbe4.com/robots.txt,,15556,200,98,12,2,text/plain,70.648543ms,
