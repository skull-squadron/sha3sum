package main

// #include "sha3.h"
import "C"
import (
	"errors"
	"fmt"
	"hash"
	"unsafe"
)

type sha3sum struct {
	bitlen int
	ctx    C.sha3_ctx
}

func newSha3sum(bitlen int) hash.Hash {
	k := &sha3sum{bitlen: bitlen}
	k.Reset()
	return k
}

func New224() hash.Hash {
	return newSha3sum(224)
}

func New256() hash.Hash {
	return newSha3sum(256)
}

func New384() hash.Hash {
	return newSha3sum(384)
}

func New512() hash.Hash {
	return newSha3sum(512)
}

func (k *sha3sum) Write(b []byte) (int, error) {
	p := unsafe.Pointer(&b[0])
	n := C.size_t(len(b))
	if C.FIPS202_SHA3_Update(&k.ctx, p, n) != C.SHA3_OK {
		return 0, errors.New("sha3sum write error")
	}
	return int(n), nil
}

func (k *sha3sum) Sum(b []byte) []byte {
	k0 := *k
	n := C.size_t(k0.bitlen / 8)
	buf := make([]byte, n, n)
	p := unsafe.Pointer(&buf[0])
	if C.FIPS202_SHA3_Final(&k0.ctx, p, n) != C.SHA3_OK {
		panic(fmt.Sprintf("sha3sum sum error %d", n))
	}
	return append(b, buf...)
}

func (k *sha3sum) Reset() {
	if C.FIPS202_SHA3_Init(&k.ctx, C.size_t(k.bitlen)) != C.SHA3_OK {
		panic("sha3sum init error")
	}
}

func (k sha3sum) BlockSize() int {
	return int(C.FIPS202_SHA3_BlockSize(&k.ctx))
}

func (k sha3sum) Size() int {
	return int(C.FIPS202_SHA3_HashSize(&k.ctx))
}
