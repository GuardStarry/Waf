nohup /usr/servers/redis-2.8.19/src/redis-server /usr/openresty/waf/conf/redis_6660.conf &
nohup /usr/servers/redis-2.8.19/src/redis-server /usr/openresty/waf/conf/redis_6661.conf &
nohup /usr/servers/redis-2.8.19/src/redis-server /usr/openresty/waf/conf/redis_6662.conf &
nohup /usr/servers/ssdb-master/ssdb-server /usr/openresty/waf/conf/ssdb_waf_7770.conf &
nohup /usr/servers/ssdb-master/ssdb-server /usr/openresty/waf/conf/ssdb_waf_7771.conf &
nohup /usr/servers/ssdb-master/ssdb-server /usr/openresty/waf/conf/ssdb_waf_7772.conf &
nohup /usr/servers/ssdb-master/ssdb-server /usr/openresty/waf/conf/ssdb_waf_7773.conf &
nohup /usr/servers/twemproxy-0.4.0/src/nutcracker -d -c /usr/openresty/waf/conf/nutcracker.yml &
/usr/servers/nginx/sbin/nginx
