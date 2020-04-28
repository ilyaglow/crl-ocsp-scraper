package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	extractDomains = flag.Bool("ed", true, "Extract domains")
	routines       = flag.Int("routines", 100, "Number of goroutines")
	timeout        = flag.Duration("t", 5*time.Second, "Connection timeout")
	pluswww        = flag.Bool("pluswww", true, "Additionally prepend www to the domain if needed")
	insecureTLS    = flag.Bool("insecure", false, "Allow insecure TLS connections")
)

func main() {
	flag.Parse()

	var wg sync.WaitGroup
	wg.Add(*routines)
	defer wg.Wait()

	proc := func(ss []string) string {
		return lowerjoin(ss)
	}
	if *extractDomains {
		proc = extrDomains
	}

	dialer := &net.Dialer{Timeout: *timeout}
	domains := make(chan string)

	for i := 0; i < *routines; i++ {
		go func() {
			for d := range domains {
				conn, err := tls.DialWithDialer(dialer, "tcp", d+":443", &tls.Config{
					InsecureSkipVerify: *insecureTLS,
				})
				if err != nil {
					log.Printf("failed to connect: " + err.Error())
					continue
				}
				conn.Close()

				for _, c := range conn.ConnectionState().PeerCertificates {
					if len(c.OCSPServer) > 0 {
						fmt.Println(proc(c.OCSPServer))
					}
					if len(c.IssuingCertificateURL) > 0 {
						fmt.Println(proc(c.IssuingCertificateURL))
					}
					if len(c.CRLDistributionPoints) > 0 {
						fmt.Println(proc(c.CRLDistributionPoints))
					}
				}
			}
			wg.Done()
		}()
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		entry := scanner.Text()
		domains <- entry
		if *pluswww && !strings.HasPrefix(entry, "www.") {
			domains <- "www." + entry
		}
	}
	close(domains)

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}

func lowerjoin(ss []string) string {
	return strings.ToLower(strings.Join(ss, "\n"))
}

func extrDomains(ss []string) string {
	var parsed []string
	for _, s := range ss {
		u, err := url.Parse(s)
		if err != nil {
			log.Println(err)
			continue
		}

		h := strings.Split(u.Host, ":")
		parsed = append(parsed, h[0])
	}

	return lowerjoin(parsed)
}
