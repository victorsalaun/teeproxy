package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
	"sync"
	"fmt"
)

// Console flags
var (
	listen                = flag.String("l", ":8888", "port to accept requests")
	targetProduction      = flag.String("a", "localhost:8080", "where production traffic goes. http://localhost:8080/production")
	altTarget             = flag.String("b", "localhost:8081", "where testing traffic goes. response are skipped. http://localhost:8081/test")
	debug                 = flag.Bool("debug", false, "more logging, showing ignored output")
	productionTimeout     = flag.Int("a.timeout", 2500, "timeout in milliseconds for production traffic")
	alternateTimeout      = flag.Int("b.timeout", 1000, "timeout in milliseconds for alternate site traffic")
	productionHostRewrite = flag.Bool("a.rewrite", false, "rewrite the host header when proxying production traffic")
	alternateHostRewrite  = flag.Bool("b.rewrite", false, "rewrite the host header when proxying alternate site traffic")
	percent               = flag.Float64("p", 100.0, "float64 percentage of traffic to send to testing")
	tlsPrivateKey         = flag.String("key.file", "", "path to the TLS private key file")
	tlsCertificate        = flag.String("cert.file", "", "path to the TLS certificate file")
	forwardClientIP       = flag.Bool("forward-client-ip", false, "enable forwarding of the client IP to the backend using the 'X-Forwarded-For' and 'Forwarded' headers")
	closeConnections      = flag.Bool("close-connections", false, "close connections to the clients and backends")
)

// Sets the request URL.
//
// This turns a inbound request (a request without URL) into an outbound request.
func setRequestTarget(request *http.Request, target *string) {
	URL, err := url.Parse(*target + request.URL.String())
	if err != nil {
		log.Println(err)
	}
	request.URL = URL
}

// Sends a request and returns the response.
func handleRequest(request *http.Request, timeout time.Duration) (*http.Response) {
	transport := &http.Transport{
		// NOTE(girone): DialTLS is not needed here, because the teeproxy works
		// as an SSL terminator.
		Dial: (&net.Dialer{ // go1.8 deprecated: Use DialContext instead
			Timeout: timeout,
			KeepAlive: 10 * timeout,
		}).Dial,
		// Close connections to the production and alternative servers?
		DisableKeepAlives: *closeConnections,
		//IdleConnTimeout: timeout,  // go1.8
		TLSHandshakeTimeout:   timeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: timeout,
	}
	// Do not use http.Client here, because it's higher level and processes
	// redirects internally, which is not what we want.
	/*client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	response, err := client.Do(request)
	if err != nil {
		log.Println("Request failed:", err)
	}*/
	response, err := transport.RoundTrip(request)
	if err != nil {
		log.Println("Request failed:", err)
	}
	return response
}

// handler contains the address of the main Target and the one for the Alternative target
type handler struct {
	Target      string
	Alternative string
	Randomizer  rand.Rand
}

// ServeHTTP duplicates the incoming request (req) and does the request to the
// Target and the Alternate target discading the Alternate response
func (h handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var wg sync.WaitGroup
	wg.Add(1)
	var productionRequest, alternativeRequest *http.Request
	var alternativeResponse *http.Response
	var alternativeResponseBodyString string
	if *forwardClientIP {
		updateForwardedHeaders(req)
	}
	if *percent == 100.0 || h.Randomizer.Float64()*100 < *percent {
		alternativeRequest, productionRequest = DuplicateRequest(req)
		go func() {
			defer func() {
				if r := recover(); r != nil && *debug {
					log.Println("Recovered in ServeHTTP(alternate request) from:", r)
				}
			}()
			defer wg.Done()

			setRequestTarget(alternativeRequest, altTarget)

			if *alternateHostRewrite {
				alternativeRequest.Host = h.Alternative
			}

			timeout := time.Duration(*alternateTimeout) * time.Millisecond
			// This keeps responses from the alternative target away from the outside world.
			alternateResponse := handleRequest(alternativeRequest, timeout)
			if alternateResponse != nil {
				// NOTE(girone): Even though we do not care about the second
				// response, we still need to close the Body reader. Otherwise
				// the connection stays open and we would soon run out of file
				// descriptors.
				body, _ := ioutil.ReadAll(alternateResponse.Body)
				bodyString := string(body)
				alternateResponse.Body.Close()
				alternativeResponse = alternateResponse
				alternativeResponseBodyString = bodyString
			}
		}()
	} else {
		productionRequest = req
	}
	defer func() {
		if r := recover(); r != nil && *debug {
			log.Println("Recovered in ServeHTTP(production request) from:", r)
		}
	}()

	setRequestTarget(productionRequest, targetProduction)

	if *productionHostRewrite {
		productionRequest.Host = h.Target
	}

	timeout := time.Duration(*productionTimeout) * time.Millisecond
	resp := handleRequest(productionRequest, timeout)

	if resp != nil {
		defer resp.Body.Close()

		// Forward response headers.
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)

		wg.Wait()
		// Forward response body.
		body, _ := ioutil.ReadAll(resp.Body)
		w.Write(body)
		productionResponseBodyString := string(body)

		compareResponse(*resp, productionResponseBodyString, *alternativeResponse, alternativeResponseBodyString)
	}
}

func compareResponse(productionResponse http.Response, productionResponseBodyString string, alternativeResponse http.Response, alternativeResponseBodyString string) {
	// Compare response status code
	if strings.Compare(productionResponse.Status, alternativeResponse.Status) != 0 {
		fmt.Println("NOT SAME")
		fmt.Println(productionResponse.Status)
		fmt.Println(alternativeResponse.Status)
	} else {
		fmt.Println("STATUS CODE SAME " + productionResponse.Status)
	}
	// Compare response body type
	if strings.Compare(productionResponse.Header.Get("Content-type"), alternativeResponse.Header.Get("Content-type")) != 0 {
		fmt.Println("NOT SAME")
		fmt.Println(productionResponse.Header.Get("Content-type"))
		fmt.Println(alternativeResponse.Header.Get("Content-type"))
	} else {
		fmt.Println("CONTENT-TYPE SAME " + productionResponse.Header.Get("Content-type"))
	}
	// Compare response body content
	if strings.Compare(productionResponseBodyString, alternativeResponseBodyString) != 0 {
		fmt.Println("NOT SAME")
		fmt.Println("redirected response: " + productionResponseBodyString)
		fmt.Println("main response: " + alternativeResponseBodyString)
	} else {
		fmt.Println("BODY SAME")
	}
}

func main() {
	flag.Parse()

	log.Printf("Starting teeproxy at %s sending to A: %s and B: %s",
		*listen, *targetProduction, *altTarget)

	runtime.GOMAXPROCS(runtime.NumCPU())

	var err error

	var listener net.Listener

	if len(*tlsPrivateKey) > 0 {
		cer, err := tls.LoadX509KeyPair(*tlsCertificate, *tlsPrivateKey)
		if err != nil {
			log.Fatalf("Failed to load certficate: %s and private key: %s", *tlsCertificate, *tlsPrivateKey)
		}

		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		listener, err = tls.Listen("tcp", *listen, config)
		if err != nil {
			log.Fatalf("Failed to listen to %s: %s", *listen, err)
		}
	} else {
		listener, err = net.Listen("tcp", *listen)
		if err != nil {
			log.Fatalf("Failed to listen to %s: %s", *listen, err)
		}
	}

	h := handler{
		Target:      *targetProduction,
		Alternative: *altTarget,
		Randomizer:  *rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	server := &http.Server{
		Handler: h,
	}
	if *closeConnections {
		// Close connections to clients by setting the "Connection": "close" header in the response.
		server.SetKeepAlivesEnabled(false)
	}
	server.Serve(listener)
}

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

func DuplicateRequest(request *http.Request) (request1 *http.Request, request2 *http.Request) {
	b1 := new(bytes.Buffer)
	b2 := new(bytes.Buffer)
	w := io.MultiWriter(b1, b2)
	io.Copy(w, request.Body)
	defer request.Body.Close()
	request1 = &http.Request{
		Method:        request.Method,
		URL:           request.URL,
		Proto:         request.Proto,
		ProtoMajor:    request.ProtoMajor,
		ProtoMinor:    request.ProtoMinor,
		Header:        request.Header,
		Body:          nopCloser{b1},
		Host:          request.Host,
		ContentLength: request.ContentLength,
		Close:         true,
	}
	request2 = &http.Request{
		Method:        request.Method,
		URL:           request.URL,
		Proto:         request.Proto,
		ProtoMajor:    request.ProtoMajor,
		ProtoMinor:    request.ProtoMinor,
		Header:        request.Header,
		Body:          nopCloser{b2},
		Host:          request.Host,
		ContentLength: request.ContentLength,
		Close:         true,
	}
	return
}

func updateForwardedHeaders(request *http.Request) {
	positionOfColon := strings.LastIndex(request.RemoteAddr, ":")
	var remoteIP string
	if positionOfColon != -1 {
		remoteIP = request.RemoteAddr[:positionOfColon]
	} else {
		log.Printf("The default format of request.RemoteAddr should be IP:Port but was %s\n", remoteIP)
		remoteIP = request.RemoteAddr
	}
	insertOrExtendForwardedHeader(request, remoteIP)
	insertOrExtendXFFHeader(request, remoteIP)
}

const XffHeader = "X-Forwarded-For"

func insertOrExtendXFFHeader(request *http.Request, remoteIP string) {
	header := request.Header.Get(XffHeader)
	if header != "" {
		// extend
		request.Header.Set(XffHeader, header+", "+remoteIP)
	} else {
		// insert
		request.Header.Set(XffHeader, remoteIP)
	}
}

const ForwardedHeader = "Forwarded"

// Implementation according to rfc7239
func insertOrExtendForwardedHeader(request *http.Request, remoteIP string) {
	extension := "for=" + remoteIP
	header := request.Header.Get(ForwardedHeader)
	if header != "" {
		// extend
		request.Header.Set(ForwardedHeader, header+", "+extension)
	} else {
		// insert
		request.Header.Set(ForwardedHeader, extension)
	}
}
