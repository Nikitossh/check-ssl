# check-ssl
Forked from https://github.com/wycore/check-ssl and refactored to check file with list of FQDN 

## POST file to check with curl
curl  -H "multipart/form-data; boundary=" http://localhost:8080/upload -F data=@1.txt

## Usage
Usage of ./check-ssl:
  -V    print version and exit
  -connection-timeout duration
        timeout connection - see: https://golang.org/pkg/time/#ParseDuration (default 10s)
  -d uint
        warning validity in days (default 28)
  -file string
        file with domain names of hosts to check
  -lookup-timeout duration
        timeout for DNS lookups - see: https://golang.org/pkg/time/#ParseDuration (default 30s)
  -rest
        run as a daemon with REST handlers
  -w int
        number of parallel workers (default 15)