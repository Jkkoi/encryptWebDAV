package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// Define the chunk size as 4MB
	chunkSize = 10 * 1024 * 1024 // 10MB
)

// Entry point of the application
func main() {
	// Initialize the WebDAV handler
	handler := &webDAVHandler{}

	// Define the server address (can be configured via environment variable)
	addr := ":8080" // Default port
	if port, exists := os.LookupEnv("PORT"); exists {
		addr = ":" + port
	}

	// Start the HTTP server
	log.Printf("Starting WebDAV encryption server on %s", addr)
	err := http.ListenAndServe(addr, handler)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// Define the AuthInfo struct
type AuthInfo struct {
	AESKeyHex        string `json:"aesKeyHex"`
	UpstreamUsername string `json:"upstreamUsername"`
	UpstreamPassword string `json:"upstreamPassword"`
}

// webDAVHandler handles incoming WebDAV requests and proxies them to the upstream server with encryption/decryption
type webDAVHandler struct {
	upstreamURL string
	gcm         cipher.AEAD
	authInfo    *AuthInfo
}

// ServeHTTP routes the incoming HTTP requests to the appropriate handler based on the method
func (h *webDAVHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse the Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse the Basic authentication
	authParts := strings.SplitN(auth, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	// Decode the authorization information
	decoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		http.Error(w, "Invalid authorization encoding", http.StatusUnauthorized)
		return
	}

	// Split the username and password
	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		http.Error(w, "Invalid credentials format", http.StatusUnauthorized)
		return
	}

	// Decode the upstream URL
	upstreamURLBytes, err := base64.StdEncoding.DecodeString(creds[0])
	if err != nil {
		http.Error(w, "Invalid upstream URL encoding", http.StatusUnauthorized)
		return
	}
	h.upstreamURL = string(upstreamURLBytes)

	// Decode and parse the password as JSON
	var authInfo AuthInfo
	passwordBytes, err := base64.StdEncoding.DecodeString(creds[1])
	if err != nil {
		http.Error(w, "Invalid password encoding", http.StatusUnauthorized)
		return
	}
	if err := json.Unmarshal(passwordBytes, &authInfo); err != nil {
		http.Error(w, "Invalid password format", http.StatusUnauthorized)
		return
	}

	// Initialize AES encryption
	aesKey, err := hex.DecodeString(authInfo.AESKeyHex)
	if err != nil || len(aesKey) != 32 {
		http.Error(w, "Invalid AES key", http.StatusUnauthorized)
		return
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		http.Error(w, "Failed to create cipher", http.StatusUnauthorized)
		return
	}

	h.gcm, err = cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "Failed to create GCM", http.StatusUnauthorized)
		return
	}

	h.authInfo = &authInfo

	// Record the request information
	log.Printf("[%s] %s %s, Content-Length: %d",
		time.Now().Format("2006-01-02 15:04:05"),
		r.Method,
		r.URL.Path,
		r.ContentLength)

	switch r.Method {
	case "PUT":
		h.handlePut(w, r)
	case "GET":
		h.handleGet(w, r)
	case "DELETE":
		h.handleDelete(w, r)
	case "MKCOL":
		h.handleMkcol(w, r)
	case "PROPFIND":
		h.handlePropfind(w, r)
	case "OPTIONS":
		h.handleOptions(w, r)
	case "MOVE":
		h.handleMove(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePut handles the PUT method to upload and encrypt files
func (h *webDAVHandler) handlePut(w http.ResponseWriter, r *http.Request) {
	// Construct the upstream URL for the requested path
	upstreamPath := h.constructUpstreamPath(r.URL.Path)

	// Create a pipe to stream encrypted data to the upstream server
	pr, pw := io.Pipe()

	// Start a goroutine to read from the client, encrypt, and write to the pipe writer
	go func() {
		defer pw.Close()
		err := h.encryptStream(r.Body, pw)
		if err != nil {
			pw.CloseWithError(err)
		}
	}()

	// Create a new PUT request to the upstream WebDAV server with the encrypted data
	upstreamReq, err := http.NewRequest("PUT", upstreamPath, pr)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	// Copy relevant headers from the original request
	copyHeaders(r.Header, upstreamReq.Header)
	h.addUpstreamAuth(upstreamReq)

	// Calculate the encrypted size
	originalSize := r.ContentLength
	if originalSize > 0 {
		// Each chunk adds:
		// - 4 bytes length prefix
		// - GCM nonce size
		// - GCM authentication tag size (16 bytes)
		extraBytesPerChunk := 4 + h.gcm.NonceSize() + 16
		numChunks := (originalSize + chunkSize - 1) / chunkSize
		encryptedSize := originalSize + (numChunks * int64(extraBytesPerChunk))

		// Set the new Content-Length
		upstreamReq.Header.Set("Content-Length", strconv.FormatInt(encryptedSize, 10))
	} else {
		// If the original size is unknown, remove Content-Length
		upstreamReq.Header.Del("Content-Length")
	}

	// Send the PUT request to the upstream server
	client := &http.Client{}
	resp, err := client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "Failed to communicate with upstream server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Relay the upstream response status and headers to the client
	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleGet handles the GET method to retrieve and decrypt files
func (h *webDAVHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	// Construct the upstream URL for the requested path
	upstreamPath := h.constructUpstreamPath(r.URL.Path)

	// Create a new GET request to the upstream WebDAV server
	upstreamReq, err := http.NewRequest("GET", upstreamPath, nil)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	// Copy relevant headers from the original request
	copyHeaders(r.Header, upstreamReq.Header)
	h.addUpstreamAuth(upstreamReq)

	// Send the GET request to the upstream server
	client := &http.Client{}
	resp, err := client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "Failed to communicate with upstream server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// If upstream returns an error status, relay it to the client
	if resp.StatusCode != http.StatusOK {
		copyHeaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// Create a pipe to stream decrypted data to the client
	pr, pw := io.Pipe()

	// Start a goroutine to read from the upstream response, decrypt, and write to the pipe writer
	go func() {
		defer pw.Close()
		err := h.decryptStream(resp.Body, pw)
		if err != nil {
			pw.CloseWithError(err)
		}
	}()

	// Copy relevant headers from the upstream response to the client response
	copyHeadersExcept(resp.Header, w.Header(), []string{
		"Content-Length",
		"Content-Encoding",
		"Content-Range",
	})

	// Since the decrypted size is unknown, omit the Content-Length header
	w.WriteHeader(http.StatusOK)

	// Stream the decrypted data to the client
	io.Copy(w, pr)
}

// handleDelete handles the DELETE method to remove files from the upstream server
func (h *webDAVHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	upstreamPath := h.constructUpstreamPath(r.URL.Path)

	upstreamReq, err := http.NewRequest("DELETE", upstreamPath, nil)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	copyHeaders(r.Header, upstreamReq.Header)
	h.addUpstreamAuth(upstreamReq)

	client := &http.Client{}
	resp, err := client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "Failed to communicate with upstream server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleMkcol handles the MKCOL method to create directories on the upstream server
func (h *webDAVHandler) handleMkcol(w http.ResponseWriter, r *http.Request) {
	upstreamPath := h.constructUpstreamPath(r.URL.Path)

	upstreamReq, err := http.NewRequest("MKCOL", upstreamPath, nil)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	copyHeaders(r.Header, upstreamReq.Header)
	h.addUpstreamAuth(upstreamReq)

	client := &http.Client{}
	resp, err := client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "Failed to communicate with upstream server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handlePropfind handles the PROPFIND method to retrieve properties from the upstream server
func (h *webDAVHandler) handlePropfind(w http.ResponseWriter, r *http.Request) {
	upstreamPath := h.constructUpstreamPath(r.URL.Path)

	// Read the body of the PROPFIND request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	upstreamReq, err := http.NewRequest("PROPFIND", upstreamPath, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	copyHeaders(r.Header, upstreamReq.Header)
	h.addUpstreamAuth(upstreamReq)

	client := &http.Client{}
	resp, err := client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "Failed to communicate with upstream server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleOptions handles the OPTIONS method to relay capabilities from the upstream server
func (h *webDAVHandler) handleOptions(w http.ResponseWriter, r *http.Request) {
	upstreamPath := h.constructUpstreamPath(r.URL.Path)

	upstreamReq, err := http.NewRequest("OPTIONS", upstreamPath, nil)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	copyHeaders(r.Header, upstreamReq.Header)
	h.addUpstreamAuth(upstreamReq)

	client := &http.Client{}
	resp, err := client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "Failed to communicate with upstream server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleMove handles the MOVE method to move files between directories on the upstream server
func (h *webDAVHandler) handleMove(w http.ResponseWriter, r *http.Request) {
	// 获取目标路径
	destination := r.Header.Get("Destination")
	if destination == "" {
		http.Error(w, "Destination header required", http.StatusBadRequest)
		return
	}

	// 解析目标 URL
	destinationURL, err := url.Parse(destination)
	if err != nil {
		http.Error(w, "Invalid destination URL", http.StatusBadRequest)
		return
	}

	// 确保路径正确编码
	destinationPath := destinationURL.Path
	// 先解码路径（处理可能已经编码的部分）
	decodedPath, err := url.QueryUnescape(destinationPath)
	if err != nil {
		http.Error(w, "Invalid destination path encoding", http.StatusBadRequest)
		return
	}
	// 重新编码整个路径
	encodedPath := url.PathEscape(decodedPath)
	// 恢复路径分隔符
	encodedPath = strings.ReplaceAll(encodedPath, "%2F", "/")

	// 构造上游源路径和目标路径
	upstreamSrcPath := h.constructUpstreamPath(r.URL.Path)
	upstreamDstPath := h.constructUpstreamPath(encodedPath)

	// 创建 MOVE 请求
	upstreamReq, err := http.NewRequest("MOVE", upstreamSrcPath, nil)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	// 复制请求头
	copyHeaders(r.Header, upstreamReq.Header)
	// 设置正确编码的目标路径
	upstreamReq.Header.Set("Destination", upstreamDstPath)
	h.addUpstreamAuth(upstreamReq)

	// 发送请求到上游服务器
	client := &http.Client{}
	resp, err := client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "Failed to communicate with upstream server", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头和状态码
	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// constructUpstreamPath constructs the full URL to the upstream server based on the request path
func (h *webDAVHandler) constructUpstreamPath(path string) string {
	// Ensure there is no double slash
	return strings.TrimRight(h.upstreamURL, "/") + "/" + strings.TrimLeft(path, "/")
}

// copyHeaders copies HTTP headers from source to destination
func copyHeaders(src http.Header, dst http.Header) {
	for key, values := range src {
		// Skip the Host header
		if strings.ToLower(key) == "host" {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// copyHeadersExcept copies HTTP headers from source to destination, excluding specified headers
func copyHeadersExcept(src http.Header, dst http.Header, exclude []string) {
	excludeMap := make(map[string]bool)
	for _, key := range exclude {
		excludeMap[strings.ToLower(key)] = true
	}
	for key, values := range src {
		if excludeMap[strings.ToLower(key)] {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// encryptStream reads plaintext from src, encrypts it in chunks, and writes encrypted data to dst
func (h *webDAVHandler) encryptStream(src io.Reader, dst io.Writer) error {
	buf := make([]byte, chunkSize)
	for {
		n, err := io.ReadFull(src, buf)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				if n > 0 {
					// Encrypt the final chunk
					encryptedChunk, err := h.encryptChunk(buf[:n])
					if err != nil {
						return err
					}
					// Write the chunk length and encrypted data
					if err := writeLengthPrefixedChunk(dst, encryptedChunk); err != nil {
						return err
					}
				}
				break
			}
			return err
		}

		// Encrypt the chunk
		encryptedChunk, err := h.encryptChunk(buf[:n])
		if err != nil {
			return err
		}

		// Write the chunk length and encrypted data
		if err := writeLengthPrefixedChunk(dst, encryptedChunk); err != nil {
			return err
		}
	}
	return nil
}

// decryptStream reads encrypted data from src, decrypts it in chunks, and writes plaintext to dst
func (h *webDAVHandler) decryptStream(src io.Reader, dst io.Writer) error {
	for {
		// Read the length prefix (4 bytes, big endian)
		lengthBytes := make([]byte, 4)
		_, err := io.ReadFull(src, lengthBytes)
		if err != nil {
			if err == io.EOF {
				break // Finished reading
			}
			return err
		}
		chunkLength := binary.BigEndian.Uint32(lengthBytes)

		// Read the encrypted chunk based on the length
		encryptedChunk := make([]byte, chunkLength)
		_, err = io.ReadFull(src, encryptedChunk)
		if err != nil {
			return err
		}

		// Decrypt the chunk
		plaintext, err := h.decryptChunk(encryptedChunk)
		if err != nil {
			return err
		}

		// Write the plaintext to the destination
		_, err = dst.Write(plaintext)
		if err != nil {
			return err
		}
	}
	return nil
}

// encryptChunk encrypts a single chunk of plaintext and returns nonce + ciphertext
func (h *webDAVHandler) encryptChunk(plaintext []byte) ([]byte, error) {
	// Generate a unique nonce
	nonce := make([]byte, h.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt the plaintext
	ciphertext := h.gcm.Seal(nil, nonce, plaintext, nil)

	// Prepend the nonce to the ciphertext
	return append(nonce, ciphertext...), nil
}

// decryptChunk decrypts a single chunk of encrypted data and returns the plaintext
func (h *webDAVHandler) decryptChunk(encrypted []byte) ([]byte, error) {
	if len(encrypted) < h.gcm.NonceSize() {
		return nil, io.ErrUnexpectedEOF
	}

	// Extract the nonce and ciphertext
	nonce := encrypted[:h.gcm.NonceSize()]
	ciphertext := encrypted[h.gcm.NonceSize():]

	// Decrypt the ciphertext
	plaintext, err := h.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// writeLengthPrefixedChunk writes the length of the chunk followed by the chunk data
func writeLengthPrefixedChunk(dst io.Writer, chunk []byte) error {
	// Write the length prefix (4 bytes, big endian)
	length := uint32(len(chunk))
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, length)
	if _, err := dst.Write(lengthBytes); err != nil {
		return err
	}

	// Write the chunk data
	_, err := dst.Write(chunk)
	return err
}

// addUpstreamAuth adds authentication headers to the upstream request
func (h *webDAVHandler) addUpstreamAuth(req *http.Request) {
	if h.authInfo != nil {
		req.SetBasicAuth(h.authInfo.UpstreamUsername, h.authInfo.UpstreamPassword)
	}
}
