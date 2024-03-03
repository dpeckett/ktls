// Copyright 2024 Damian Peckett <damian@pecke.tt>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ktls_test

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/dpeckett/ktls"
	"github.com/dpeckett/ktls/tls"
	"github.com/stretchr/testify/require"
)

func TestKTLSEnable(t *testing.T) {
	runServer := func(t *testing.T, tlsConfig *tls.Config) (net.Listener, error) {
		lis, err := tls.Listen("tcp", "localhost:0", tlsConfig)
		require.NoError(t, err)

		go func() {
			for {
				conn, err := lis.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}

					t.Logf("Error accepting connection: %s", err.Error())
					return
				}

				go func() {
					defer conn.Close()

					scanner := bufio.NewScanner(conn)
					for scanner.Scan() {
						text := scanner.Text()

						_, err := conn.Write([]byte(text + "\n"))
						if err != nil {
							t.Logf("Error writing data: %s", err.Error())
							break
						}
					}

					if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
						t.Logf("Error reading data: %s", err.Error())
					}
				}()
			}
		}()

		time.Sleep(100 * time.Millisecond)

		return lis, nil
	}

	cert, err := generateSelfSignedCert()
	require.NoError(t, err)

	t.Run("TLS 1.2", func(t *testing.T) {
		t.Run("AES-128-GCM", func(t *testing.T) {
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				},
				Certificates:       []tls.Certificate{cert},
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			}

			lis, err := runServer(t, tlsConfig)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, lis.Close())
			})

			conn, err := net.Dial("tcp", lis.Addr().String())
			require.NoError(t, err)

			{
				tlsConn := tls.Client(conn, tlsConfig)
				require.NoError(t, err)

				require.NoError(t, tlsConn.Handshake())

				require.NoError(t, ktls.Enable(tlsConn))
			}

			// The kernel will now handle encryption/decryption of the data.
			_, err = conn.Write([]byte("AES-128-GCM\n"))
			require.NoError(t, err)

			resp, err := bufio.NewReader(conn).ReadString('\n')
			require.NoError(t, err)
			require.Equal(t, "AES-128-GCM\n", resp)
		})

		t.Run("AES-256-GCM", func(t *testing.T) {
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				},
				Certificates:       []tls.Certificate{cert},
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			}

			lis, err := runServer(t, tlsConfig)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, lis.Close())
			})

			conn, err := net.Dial("tcp", lis.Addr().String())
			require.NoError(t, err)

			{
				tlsConn := tls.Client(conn, tlsConfig)
				require.NoError(t, err)

				require.NoError(t, tlsConn.Handshake())

				require.NoError(t, ktls.Enable(tlsConn))
			}

			// The kernel will now handle encryption/decryption of the data.
			_, err = conn.Write([]byte("AES-256-GCM\n"))
			require.NoError(t, err)

			resp, err := bufio.NewReader(conn).ReadString('\n')
			require.NoError(t, err)
			require.Equal(t, "AES-256-GCM\n", resp)
		})

		t.Run("CHACHA20-POLY1305", func(t *testing.T) {
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				Certificates:       []tls.Certificate{cert},
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			}

			lis, err := runServer(t, tlsConfig)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, lis.Close())
			})

			conn, err := net.Dial("tcp", lis.Addr().String())
			require.NoError(t, err)

			{
				tlsConn := tls.Client(conn, tlsConfig)
				require.NoError(t, err)

				require.NoError(t, tlsConn.Handshake())

				require.NoError(t, ktls.Enable(tlsConn))
			}

			// The kernel will now handle encryption/decryption of the data.
			_, err = conn.Write([]byte("CHACHA20-POLY1305\n"))
			require.NoError(t, err)

			resp, err := bufio.NewReader(conn).ReadString('\n')
			require.NoError(t, err)
			require.Equal(t, "CHACHA20-POLY1305\n", resp)
		})
	})

	t.Run("TLS 1.3", func(t *testing.T) {
		// Golangs TLS 1.3 implementation does not allow for customizing the ciphers.
		// So we'll just check the default cipher (which is AES-128-GCM).
		t.Run("AES-128-GCM", func(t *testing.T) {
			tlsConfig := &tls.Config{
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				Certificates:       []tls.Certificate{cert},
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			}

			lis, err := runServer(t, tlsConfig)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, lis.Close())
			})

			conn, err := net.Dial("tcp", lis.Addr().String())
			require.NoError(t, err)

			{
				tlsConn := tls.Client(conn, tlsConfig)
				require.NoError(t, err)

				require.NoError(t, tlsConn.Handshake())

				require.NoError(t, ktls.Enable(tlsConn))
			}

			// The kernel will now handle encryption/decryption of the data.
			_, err = conn.Write([]byte("AES-128-GCM\n"))
			require.NoError(t, err)

			resp, err := bufio.NewReader(conn).ReadString('\n')
			require.NoError(t, err)
			require.Equal(t, "AES-128-GCM\n", resp)
		})
	})
}

func generateSelfSignedCert() (tls.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return tls.X509KeyPair(certPEM, privKeyPEM)
}
