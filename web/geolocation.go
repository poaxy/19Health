package web

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"19health/logger"
)

var (
	countryCache struct {
		mu          sync.RWMutex
		countryCode string
		flag        string
		initialized bool
	}
)

// GetCountryFromIP fetches the country code for a given IP address using ipapi.co
func GetCountryFromIP(ip string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("IP address is empty")
	}

	url := fmt.Sprintf("https://ipapi.co/%s/country_code/", ip)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", "19Health")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch country: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	countryCode := strings.TrimSpace(string(body))
	if len(countryCode) != 2 {
		return "", fmt.Errorf("invalid country code: %s", countryCode)
	}

	return strings.ToUpper(countryCode), nil
}

// CountryCodeToFlag converts an ISO 3166-1 alpha-2 country code to a flag emoji
func CountryCodeToFlag(countryCode string) string {
	if len(countryCode) != 2 {
		return ""
	}

	countryCode = strings.ToUpper(countryCode)
	var flag strings.Builder

	for _, char := range countryCode {
		// Convert letter to regional indicator symbol
		// A (U+0041) -> 🇦 (U+1F1E6)
		// Offset: U+1F1E6 - U+0041 = 0x1F1A5
		flag.WriteRune(0x1F1E6 + (char - 'A'))
	}

	return flag.String()
}

// GetCachedCountryFlag returns the cached country flag and code, or fetches it if not cached
func GetCachedCountryFlag(ip string) string {
	countryCache.mu.RLock()
	if countryCache.initialized {
		result := countryCache.flag
		countryCache.mu.RUnlock()
		return result
	}
	countryCache.mu.RUnlock()

	// Acquire write lock to prevent multiple simultaneous fetches
	countryCache.mu.Lock()
	// Double-check after acquiring write lock
	if countryCache.initialized {
		result := countryCache.flag
		countryCache.mu.Unlock()
		return result
	}

	// Fetch country code
	countryCode, err := GetCountryFromIP(ip)
	if err != nil {
		countryCache.mu.Unlock()
		logger.Warn("Failed to get country from IP %s: %v", ip, err)
		return ""
	}

	// Convert to flag emoji
	flag := CountryCodeToFlag(countryCode)
	if flag == "" {
		countryCache.mu.Unlock()
		logger.Warn("Failed to convert country code %s to flag", countryCode)
		return ""
	}

	// Cache the result
	countryCache.countryCode = countryCode
	countryCache.flag = fmt.Sprintf("%s %s", flag, countryCode)
	countryCache.initialized = true
	countryCache.mu.Unlock()

	return countryCache.flag
}

