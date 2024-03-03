// Copyright 2024 Damian Peckett <damian@pecke.tt>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ktls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/dpeckett/ktls/tls"
	"golang.org/x/sys/unix"
)

const (
	TLS_TX = 1 // Set transmit parameters.
	TLS_RX = 2 // Set receive parameters.
)

// Enable enables kernel TLS on the given file descriptor.
func Enable(tlsConn *tls.Conn) error {
	if _, err := os.Stat("/sys/module/tls"); err != nil {
		return fmt.Errorf("kernel tls module not loaded")
	}

	syscallConn, err := tlsConn.NetConn().(syscall.Conn).SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var enableErr error
	err = syscallConn.Control(func(fd uintptr) {
		if err := syscall.SetsockoptString(int(fd), syscall.SOL_TCP, unix.TCP_ULP, "tls"); err != nil {
			enableErr = fmt.Errorf("failed to enable kernel TLS: %w", err)
			return
		}

		state := tlsConn.ConnectionState()
		switch state.CipherSuite {
		case tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_128_GCM_SHA256:
			if err := setAESGCM128Info(fd, state, false); err != nil {
				enableErr = fmt.Errorf("failed to set transmit crypto info: %w", err)
				return
			}

			if err := setAESGCM128Info(fd, state, true); err != nil {
				enableErr = fmt.Errorf("failed to set receive crypto info: %w", err)
			}
		case tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_AES_256_GCM_SHA384:
			if err := setAESGCM256Info(fd, state, false); err != nil {
				enableErr = fmt.Errorf("failed to set transmit crypto info: %w", err)
				return
			}

			if err := setAESGCM256Info(fd, state, true); err != nil {
				enableErr = fmt.Errorf("failed to set receive crypto info: %w", err)
			}
		case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256:
			if err := setChaCha20Poly1305Info(fd, state, false); err != nil {
				enableErr = fmt.Errorf("failed to set transmit crypto info: %w", err)
				return
			}

			if err := setChaCha20Poly1305Info(fd, state, true); err != nil {
				enableErr = fmt.Errorf("failed to set receive crypto info: %w", err)
			}
		default:
			enableErr = fmt.Errorf("unsupported cipher suite: %d", state.CipherSuite)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to control syscall conn: %w", err)
	}

	return enableErr
}

func setAESGCM128Info(fd uintptr, state tls.ConnectionState, read bool) error {
	key, iv, seq := state.KeyInfo(read)

	info := cryptoInfoAESGCM128{
		Info: cryptoInfo{
			Version:    state.Version,
			CipherType: cipherAESGCM128,
		},
		Key:    [cipherAESGCM128KeySize]byte(key),
		Salt:   [cipherAESGCM128SaltSize]byte(iv[:cipherAESGCM128SaltSize]),
		RecSeq: [cipherAESGCM128RecSeqSize]byte(seq),
	}

	// TLSv1.2 generates IV in the kernel.
	if state.Version == tls.VersionTLS12 {
		info.IV = [cipherAESGCM128IVSize]byte(seq)
	} else {
		copy(info.IV[:], iv[cipherAESGCM128SaltSize:])
	}

	var w bytes.Buffer
	if err := binary.Write(&w, binary.NativeEndian, &info); err != nil {
		return fmt.Errorf("failed to encode crypto info: %w", err)
	}

	level := TLS_TX
	if read {
		level = TLS_RX
	}

	if err := setsockoptBytes(fd, unix.SOL_TLS, level, w.Bytes()); err != nil {
		return fmt.Errorf("failed to configure tls socket: %w", err)
	}

	return nil
}

func setAESGCM256Info(fd uintptr, state tls.ConnectionState, read bool) error {
	key, iv, seq := state.KeyInfo(read)

	info := cryptoInfoAESGCM256{
		Info: cryptoInfo{
			Version:    state.Version,
			CipherType: cipherAESGCM256,
		},
		Key:    [cipherAESGCM256KeySize]byte(key),
		Salt:   [cipherAESGCM256SaltSize]byte(iv[:cipherAESGCM256SaltSize]),
		RecSeq: [cipherAESGCM256RecSeqSize]byte(seq),
	}

	// TLSv1.2 generates IV in the kernel.
	if state.Version == tls.VersionTLS12 {
		info.IV = [cipherAESGCM256IVSize]byte(seq)
	} else {
		copy(info.IV[:], iv[cipherAESGCM256SaltSize:])
	}

	var w bytes.Buffer
	if err := binary.Write(&w, binary.NativeEndian, &info); err != nil {
		return fmt.Errorf("failed to encode crypto info: %w", err)
	}

	level := TLS_TX
	if read {
		level = TLS_RX
	}

	if err := setsockoptBytes(fd, unix.SOL_TLS, level, w.Bytes()); err != nil {
		return fmt.Errorf("failed to configure tls socket: %w", err)
	}

	return nil
}

func setChaCha20Poly1305Info(fd uintptr, state tls.ConnectionState, read bool) error {
	key, iv, seq := state.KeyInfo(read)

	info := cryptoInfoCHACHA20POLY1305{
		Info: cryptoInfo{
			Version:    state.Version,
			CipherType: cipherCHACHA20POLY1305,
		},
		IV:     [cipherCHACHA20IVSize]byte(iv),
		Key:    [cipherCHACHA20KeySize]byte(key),
		RecSeq: [cipherCHACHA20RecSeqSize]byte(seq),
	}

	var w bytes.Buffer
	if err := binary.Write(&w, binary.NativeEndian, &info); err != nil {
		return fmt.Errorf("failed to encode crypto info: %w", err)
	}

	level := TLS_TX
	if read {
		level = TLS_RX
	}

	if err := setsockoptBytes(fd, unix.SOL_TLS, level, w.Bytes()); err != nil {
		return fmt.Errorf("failed to configure tls socket: %w", err)
	}

	return nil
}

func setsockoptBytes(fd uintptr, level int, name int, value []byte) error {
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, uintptr(level), uintptr(name), uintptr(unsafe.Pointer(unsafe.SliceData(value))), uintptr(len(value)), 0)
	if e1 != 0 {
		return unix.Errno(e1)
	}

	return nil
}
