package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"math"
	"net"
	"net/smtp"
	"os"
	"runtime/debug"
	"time"

	log "github.com/Sirupsen/logrus"
)

// check exit codes
const (
	OK       = iota
	Warning  = iota
	Critical = iota
	Unknown  = iota
)

var exitCode = OK
var lookupTimeout, connectionTimeout, warningValidity, criticalValidity time.Duration
var warningFlag, criticalFlag uint
var version string
var printVersion bool

func updateExitCode(newCode int) (changed bool) {
	if newCode > exitCode {
		exitCode = newCode
		return true

	}
	return false
}

func main() {
	defer catchPanic()

	var host string
	var file string

	flag.StringVar(&host, "host", "", "the domain name of the host to check")
	flag.StringVar(&file, "file", "", "file with domain names of hosts to check")
	flag.DurationVar(&lookupTimeout, "lookup-timeout", 5*time.Second, "timeout for DNS lookups - see: https://golang.org/pkg/time/#ParseDuration")
	flag.DurationVar(&connectionTimeout, "connection-timeout", 5*time.Second, "timeout connection - see: https://golang.org/pkg/time/#ParseDuration")
	flag.UintVar(&warningFlag, "w", 30, "warning validity in days")
	flag.UintVar(&criticalFlag, "c", 14, "critical validity in days")
	flag.BoolVar(&printVersion, "V", false, "print version and exit")
	flag.Parse()

	log.SetLevel(log.InfoLevel)

	if printVersion {
		log.Infof("Version: %s", version)
		os.Exit(0)
	}

	if host == "" && file == "" {
		flag.Usage()
		log.Error("-host or -file is required")
		os.Exit(Critical)
	}

	if warningFlag < criticalFlag {
		log.Warn("-c is higher than -w, i guess thats a bad i idea")
		updateExitCode(Warning)
	}

	warningValidity = time.Duration(warningFlag) * 24 * time.Hour
	criticalValidity = time.Duration(criticalFlag) * 24 * time.Hour

	if file != "" {
		certsSoonExpire := processFile(file)
		report := prepareForSendReport(certsSoonExpire)
		log.Info("---------------------")
		log.Info(report)
	}

	os.Exit(exitCode)
}

func processFile(filename string) (result []string) {
	hosts := readFileToArr(filename)
	results := checkCertificates(hosts)
	for _, r := range results {
		if r == "" {
			continue
		}
		result = append(result, r)
	}
	return result
}

func prepareForSendReport(domains []string) (bigString string) {
	for _, d := range domains {
		bigString += fmt.Sprintf("%s\n", d)
	}
	return bigString
}

func readFileToArr(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	result := make([]string, 0)

	for scanner.Scan() {
		result = append(result, scanner.Text())
	}
	return result
}

func checkCertificates(hosts []string) []string {
	result := make([]string, 0)
	for _, h := range hosts {
		result = append(result, checkHostCert(h))
	}
	return result
}

// Check if certificate is close to expire date
func checkHostCert(host string) (result string) {
	ips := lookupIPWithTimeout(host, lookupTimeout)
	log.Debugf("lookup result: %v", ips)

	for _, ip := range ips {
		dialer := net.Dialer{Timeout: connectionTimeout, Deadline: time.Now().Add(connectionTimeout + 5*time.Second)}
		connection, err := tls.DialWithDialer(&dialer, "tcp", fmt.Sprintf("[%s]:443", ip), &tls.Config{ServerName: host})
		// skip errors
		if err != nil {
			continue
		}
		// rembember the checked certs based on their Signature
		checkedCerts := make(map[string]struct{})
		// loop to all certs we get
		// there might be multiple chains, as there may be one or more CAs present on the current system, so we have multiple possible chains
		for _, chain := range connection.ConnectionState().VerifiedChains {
			for _, cert := range chain {
				if _, checked := checkedCerts[string(cert.Signature)]; checked {
					continue
				}
				checkedCerts[string(cert.Signature)] = struct{}{}
				// filter out CA certificates
				if cert.IsCA {
					log.Debugf("%-15s - ignoring CA certificate %s", ip, cert.Subject.CommonName)
					continue
				}

				var certificateStatus int
				remainingValidity := cert.NotAfter.Sub(time.Now())
				if remainingValidity < criticalValidity {
					certificateStatus = Critical
				} else if remainingValidity < warningValidity {
					certificateStatus = Warning
				} else {
					certificateStatus = OK
				}
				updateExitCode(certificateStatus)
				if certificateStatus == Critical || certificateStatus == Warning {
					result = fmt.Sprintf("%s valid for %s", cert.Subject.CommonName, formatDuration(remainingValidity))
				}
				logWithSeverity(certificateStatus, "%-15s - %s valid until %s (%s)", ip, cert.Subject.CommonName, cert.NotAfter, formatDuration(remainingValidity))
			}
		}
		connection.Close()
	}
	return result
}

func send(body string) {
	from := "gitlab.icebreakrr@gmail.com"
	pass := "XdiQK3R6iT"
	to := "nikita@dotin.us"

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Certificates problems\n\n" +
		body

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}
	log.Print("report sent")
}

func lookupIPWithTimeout(host string, timeout time.Duration) []net.IP {
	timer := time.NewTimer(timeout)
	ch := make(chan []net.IP, 1)

	go func() {
		r, err := net.LookupIP(host)
		if err != nil {
			log.Fatal(err)
		}
		ch <- r
	}()

	select {
	case ips := <-ch:
		return ips
	case <-timer.C:
		log.Errorf("timeout resolving %s", host)
		updateExitCode(Critical)
	}
	return make([]net.IP, 0)
}

func catchPanic() {
	if r := recover(); r != nil {
		log.Errorf("Panic: %+v", r)
		log.Error(string(debug.Stack()[:]))
		os.Exit(Critical)
	}
}

func formatDuration(in time.Duration) string {
	var daysPart, hoursPart string

	days := math.Floor(in.Hours() / 24)
	hoursRemaining := math.Mod(in.Hours(), 24)
	if days > 0 {
		daysPart = fmt.Sprintf("%.fd", days)
	} else {
		daysPart = ""
	}

	hours, hoursRemaining := math.Modf(hoursRemaining)
	if hours > 0 {
		hoursPart = fmt.Sprintf("%.fh", hours)
	} else {
		hoursPart = ""
	}

	return fmt.Sprintf("%s %s", daysPart, hoursPart)
}

func logWithSeverity(severity int, format string, args ...interface{}) {
	switch severity {
	case OK:
		log.Infof(format, args...)
	case Warning:
		log.Warnf(format, args...)
	case Critical:
		log.Errorf(format, args...)
	default:
		log.Panicf("Invalid severity %d", severity)
	}
}
