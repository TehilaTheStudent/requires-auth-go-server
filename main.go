package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	// Load CA certificate
	caCert, err := ioutil.ReadFile("certs/ca-cert.pem")
	if err != nil {
		log.Fatal("Failed to read CA certificate:", err)
	}

	// Create CA certificate pool
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse CA certificate")
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair("certs/server-cert.pem", "certs/server-key.pem")
	if err != nil {
		log.Fatal("Failed to load server certificate and key:", err)
	}

	// Configure TLS with client certificate verification
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP server with TLS configuration
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Define routes with logging middleware
	http.HandleFunc("/", loggingMiddleware(handleRoot))
	http.HandleFunc("/secure", loggingMiddleware(handleSecure))
	http.HandleFunc("/health", loggingMiddleware(handleHealth))

	log.Println("Starting HTTPS server on :8443 with client certificate authentication...")
	log.Println("Available endpoints:")
	log.Println("  GET /        - Root endpoint")
	log.Println("  GET /secure  - Secure endpoint with client info")
	log.Println("  GET /health  - Health check endpoint")
	
	// Start the server
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	clientCertDetails := getDetailedClientCertInfo(r)
	
	response := map[string]interface{}{
		"message":              "Root endpoint - Client certificate authentication successful",
		"endpoint":             "/",
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
		"client_cert_details": clientCertDetails,
		"request_info": map[string]interface{}{
			"method":      r.Method,
			"url":         r.URL.String(),
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.Header.Get("User-Agent"),
			"headers":     r.Header,
		},
		"available_endpoints": []string{"/", "/secure", "/health"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleSecure(w http.ResponseWriter, r *http.Request) {
	clientCertDetails := getDetailedClientCertInfo(r)
	
	response := map[string]interface{}{
		"message":              "Access granted to secure endpoint",
		"endpoint":             "/secure",
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
		"client_cert_details": clientCertDetails,
		"request_info": map[string]interface{}{
			"method":      r.Method,
			"url":         r.URL.String(),
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.Header.Get("User-Agent"),
			"headers":     r.Header,
		},
		"tls_info": getTLSInfo(r),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	clientCertDetails := getDetailedClientCertInfo(r)
	
	response := map[string]interface{}{
		"status":               "healthy",
		"message":              "Server is running with client cert auth",
		"endpoint":             "/health",
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
		"client_cert_details": clientCertDetails,
		"server_info": map[string]interface{}{
			"version":    "1.0.0",
			"tls_config": "RequireAndVerifyClientCert",
			"port":       "8443",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Logging middleware that logs every request with massive detail
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		log.Printf("=== INCOMING REQUEST ===")
		log.Printf("Timestamp: %s", start.UTC().Format(time.RFC3339))
		log.Printf("Method: %s", r.Method)
		log.Printf("URL: %s", r.URL.String())
		log.Printf("Remote Address: %s", r.RemoteAddr)
		log.Printf("User-Agent: %s", r.Header.Get("User-Agent"))
		log.Printf("Content-Length: %d", r.ContentLength)
		
		// Log all headers
		log.Printf("--- REQUEST HEADERS ---")
		for name, values := range r.Header {
			for _, value := range values {
				log.Printf("%s: %s", name, value)
			}
		}
		
		// Log TLS information
		if r.TLS != nil {
			log.Printf("--- TLS INFORMATION ---")
			log.Printf("TLS Version: %x", r.TLS.Version)
			log.Printf("Cipher Suite: %x", r.TLS.CipherSuite)
			log.Printf("Server Name: %s", r.TLS.ServerName)
			log.Printf("Negotiated Protocol: %s", r.TLS.NegotiatedProtocol)
			log.Printf("Handshake Complete: %t", r.TLS.HandshakeComplete)
			log.Printf("Did Resume: %t", r.TLS.DidResume)
			
			// Log client certificates in detail
			if len(r.TLS.PeerCertificates) > 0 {
				log.Printf("--- CLIENT CERTIFICATES ---")
				log.Printf("Number of certificates: %d", len(r.TLS.PeerCertificates))
				
				for i, cert := range r.TLS.PeerCertificates {
					log.Printf("Certificate #%d:", i+1)
					log.Printf("  Subject: %s", cert.Subject.String())
					log.Printf("  Issuer: %s", cert.Issuer.String())
					log.Printf("  Serial Number: %s", cert.SerialNumber.String())
					log.Printf("  Not Before: %s", cert.NotBefore.Format(time.RFC3339))
					log.Printf("  Not After: %s", cert.NotAfter.Format(time.RFC3339))
					log.Printf("  DNS Names: %v", cert.DNSNames)
					log.Printf("  Email Addresses: %v", cert.EmailAddresses)
					log.Printf("  Key Usage: %v", cert.KeyUsage)
					log.Printf("  Extended Key Usage: %v", cert.ExtKeyUsage)
					log.Printf("  Is CA: %t", cert.IsCA)
					log.Printf("  Signature Algorithm: %s", cert.SignatureAlgorithm.String())
					log.Printf("  Public Key Algorithm: %s", cert.PublicKeyAlgorithm.String())
				}
			} else {
				log.Printf("--- NO CLIENT CERTIFICATES PROVIDED ---")
			}
			
			// Log verified chains
			if len(r.TLS.VerifiedChains) > 0 {
				log.Printf("--- VERIFIED CERTIFICATE CHAINS ---")
				for i, chain := range r.TLS.VerifiedChains {
					log.Printf("Chain #%d has %d certificates", i+1, len(chain))
				}
			} else {
				log.Printf("--- NO VERIFIED CERTIFICATE CHAINS ---")
			}
		} else {
			log.Printf("--- NO TLS INFORMATION (NOT HTTPS?) ---")
		}
		
		// Call the actual handler
		next(w, r)
		
		// Log response timing
		duration := time.Since(start)
		log.Printf("--- REQUEST COMPLETED ---")
		log.Printf("Duration: %v", duration)
		log.Printf("=========================")
		log.Println()
	}
}

// Get detailed client certificate information as structured data
func getDetailedClientCertInfo(r *http.Request) map[string]interface{} {
	if r.TLS == nil {
		return map[string]interface{}{
			"status": "no_tls",
			"message": "No TLS information available",
		}
	}
	
	if len(r.TLS.PeerCertificates) == 0 {
		return map[string]interface{}{
			"status": "no_client_cert",
			"message": "No client certificate provided",
			"tls_version": fmt.Sprintf("%x", r.TLS.Version),
			"cipher_suite": fmt.Sprintf("%x", r.TLS.CipherSuite),
		}
	}
	
	cert := r.TLS.PeerCertificates[0]
	return map[string]interface{}{
		"status": "client_cert_provided",
		"certificate_count": len(r.TLS.PeerCertificates),
		"primary_certificate": map[string]interface{}{
			"subject": cert.Subject.String(),
			"issuer": cert.Issuer.String(),
			"serial_number": cert.SerialNumber.String(),
			"not_before": cert.NotBefore.Format(time.RFC3339),
			"not_after": cert.NotAfter.Format(time.RFC3339),
			"dns_names": cert.DNSNames,
			"email_addresses": cert.EmailAddresses,
			"key_usage": cert.KeyUsage,
			"extended_key_usage": cert.ExtKeyUsage,
			"is_ca": cert.IsCA,
			"signature_algorithm": cert.SignatureAlgorithm.String(),
			"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		},
		"verified_chains_count": len(r.TLS.VerifiedChains),
	}
}

// Get TLS connection information
func getTLSInfo(r *http.Request) map[string]interface{} {
	if r.TLS == nil {
		return map[string]interface{}{
			"status": "no_tls",
		}
	}
	
	return map[string]interface{}{
		"version": fmt.Sprintf("%x", r.TLS.Version),
		"cipher_suite": fmt.Sprintf("%x", r.TLS.CipherSuite),
		"server_name": r.TLS.ServerName,
		"negotiated_protocol": r.TLS.NegotiatedProtocol,
		"handshake_complete": r.TLS.HandshakeComplete,
		"did_resume": r.TLS.DidResume,
		"peer_certificates_count": len(r.TLS.PeerCertificates),
		"verified_chains_count": len(r.TLS.VerifiedChains),
	}
}
