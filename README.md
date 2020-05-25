# check-ssl
Forked from https://github.com/wycore/check-ssl

## Usage

    Usage of ./check-ssl:
      -V	print version and exit
      -connection-timeout duration
            timeout connection - see: https://golang.org/pkg/time/#ParseDuration (default 30s)
      -host string
            the domain name of the host to check
      - file string
            the file with list of domain names to check
      -lookup-timeout duration
            timeout for DNS lookups - see: https://golang.org/pkg/time/#ParseDuration (default 10s)
      -d uint
            warning validity in days (default 28)
      -w int
            workers count (default CPU numbers)