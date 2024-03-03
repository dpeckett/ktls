// Copyright 2024 Damian Peckett <damian@pecke.tt>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ktls

const (
	cipherAESGCM128           = 51
	cipherAESGCM128IVSize     = 8
	cipherAESGCM128KeySize    = 16
	cipherAESGCM128SaltSize   = 4
	cipherAESGCM128RecSeqSize = 8

	cipherAESGCM256           = 52
	cipherAESGCM256IVSize     = 8
	cipherAESGCM256KeySize    = 32
	cipherAESGCM256SaltSize   = 4
	cipherAESGCM256RecSeqSize = 8

	cipherCHACHA20POLY1305   = 54
	cipherCHACHA20IVSize     = 12
	cipherCHACHA20KeySize    = 32
	cipherCHACHA20RecSeqSize = 8
)

type cryptoInfo struct {
	Version    uint16
	CipherType uint16
}

type cryptoInfoAESGCM128 struct {
	Info   cryptoInfo
	IV     [cipherAESGCM128IVSize]byte
	Key    [cipherAESGCM128KeySize]byte
	Salt   [cipherAESGCM128SaltSize]byte
	RecSeq [cipherAESGCM128RecSeqSize]byte
}

type cryptoInfoAESGCM256 struct {
	Info   cryptoInfo
	IV     [cipherAESGCM256IVSize]byte
	Key    [cipherAESGCM256KeySize]byte
	Salt   [cipherAESGCM256SaltSize]byte
	RecSeq [cipherAESGCM256RecSeqSize]byte
}

type cryptoInfoCHACHA20POLY1305 struct {
	Info   cryptoInfo
	IV     [cipherCHACHA20IVSize]byte
	Key    [cipherCHACHA20KeySize]byte
	RecSeq [cipherCHACHA20RecSeqSize]byte
}
