package pbinter

import (
	//"encoding/binary"
	//"fmt"
	"unsafe"
)

const N int = int(unsafe.Sizeof(0))

func JudEndian() string {
	x := 0x1234
	p := unsafe.Pointer(&x)
	p2 := (*[N]byte)(p)
	if p2[0] == 0 {
		return "bigEndian"
	} else {
		return "littleEndian"
	}
}
