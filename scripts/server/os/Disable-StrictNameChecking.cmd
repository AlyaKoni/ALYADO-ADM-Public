set aname=ServerHostName
set cname=srv
set domain=localdomain.xx

setspn -a host/%cname% %aname%
setspn -a host/%cname%.%domain% %aname%
setspn -L %aname%
