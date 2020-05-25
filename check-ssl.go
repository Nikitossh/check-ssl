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
	"runtime"
	"runtime/debug"
	"time"

	log "github.com/Sirupsen/logrus"
)

var lookupTimeout, connectionTimeout, warningValidity, criticalValidity time.Duration
var warningFlag, criticalFlag uint
var version string
var printVersion bool
var workers int

func main() {
	defer catchPanic()

	var host string
	var file string

	flag.StringVar(&host, "host", "", "the domain name of the host to check")
	flag.StringVar(&file, "file", "", "file with domain names of hosts to check")
	flag.DurationVar(&lookupTimeout, "lookup-timeout", 30*time.Second, "timeout for DNS lookups - see: https://golang.org/pkg/time/#ParseDuration")
	flag.DurationVar(&connectionTimeout, "connection-timeout", 10*time.Second, "timeout connection - see: https://golang.org/pkg/time/#ParseDuration")
	flag.UintVar(&warningFlag, "d", 28, "warning validity in days")
	flag.IntVar(&workers, "w", runtime.NumCPU(), "number of parallel workers")
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
		os.Exit(1)
	}

	warningValidity = time.Duration(warningFlag) * 24 * time.Hour

	if file != "" {
		hosts := readFileToArr(file)
		result := processCheckCertificates(hosts)
		send(result, "nikita@dotin.us")
	}
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

func processCheckCertificates(hosts []string) string {
	log.Infof("Processing certificates check with %v workers", workers)
	domains := make(chan string, workers)
	report := make(chan string, len(hosts))
	done := make(chan struct{}, workers)

	go addHost(domains, hosts)

	for i := 0; i < workers; i++ {
		go checkHosts(done, report, domains)
	}
	go awaitCompletion(done, report)
	result := prepareReport(report)
	return result
}

func prepareReport(report <-chan string) string {
	var result string
	for line := range report {
		result += line
	}
	return result
}

func addHost(domains chan<- string, hosts []string) {
	for _, host := range hosts {
		domains <- host
	}
	close(domains)
}

func checkHosts(done chan<- struct{}, report chan string, domains <-chan string) {
	for domain := range domains {
		checkCertificateExpireDate(domain, report)
	}
	done <- struct{}{}
}

func awaitCompletion(done <-chan struct{}, report chan string) {
	for i := 0; i < workers; i++ {
		<-done
	}
	close(report)
}

func checkCertificateExpireDate(host string, report chan string) (result string) {
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

				remainingValidity := cert.NotAfter.Sub(time.Now())
				if remainingValidity < warningValidity {
					report <- fmt.Sprintf("%s will expire for %s\n", cert.Subject.CommonName, formatDuration(remainingValidity))
				}
				log.Infof("%s was checked", host)
			}
		}
		connection.Close()
	}
	return result
}

func send(body string, sendTo string) {
	from := "gitlab.icebreakrr@gmail.com"
	pass := "XdiQK3R6iT"
	to := sendTo

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
		log.Warningf("timeout resolving %s", host)
	}
	return make([]net.IP, 0)
}

func catchPanic() {
	if r := recover(); r != nil {
		log.Errorf("Panic: %+v", r)
		log.Error(string(debug.Stack()[:]))
		os.Exit(1)
	}
}

func formatDuration(in time.Duration) string {
	var daysPart string

	days := math.Floor(in.Hours() / 24)
	if days > 0 {
		daysPart = fmt.Sprintf("%.fd", days)
	} else {
		daysPart = ""
	}

	return fmt.Sprintf("%s", daysPart)
}
