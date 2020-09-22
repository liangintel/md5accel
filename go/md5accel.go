package md5accel

/*
#cgo CFLAGS: -I/opt/stack/qat/quickassist/lookaside/access_layer/src/sample_code/functional/sym/qat_hash
#cgo LDFLAGS:  -lssl -lcrypto -lqat_hash -L/opt/stack/qat/quickassist/lookaside/access_layer/src/sample_code/functional/sym/qat_hash
#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h> //may need to install `apt install libssl-dev`
#include "qat_hash.h"

*/
import "C"

import (
	"hash"
	"fmt"
	"sync"
	"unsafe"
	"reflect"
	"time"
	
	golog "log"
	"sync/atomic"
//	"runtime/debug"

	humanize "github.com/dustin/go-humanize"
)

const PIECE_NUM = 32
const PIECE_SIZE = (4*1024*1024)

var init_once sync.Once
var inited int = 0
var max_engine int = 0
var chan_engines chan int

var inflight_engine_num int32 = 0

// The size of an MD5 checksum in bytes.
const Md5Size = 16

func Init_qat_hash() {
	for {
		if (inited != 0) {
			break
		}

		init_once.Do(Init)
		time.Sleep(time.Duration(200)*time.Millisecond)
	}
}

func Get_max_object_size() int64 {
	return int64(C.get_max_object_size())*humanize.MiByte
}

func Get_inflight_engine_num() int32 {
	return inflight_engine_num
}

func Inc_inflight_engine_num() {
	atomic.AddInt32(&inflight_engine_num, 1)
}

func Init() {
	golog.Println("======= chan_engines Init IN =======")
	max_engine = int(C.get_engine_num())
	chan_engines=make(chan int, max_engine)
	
	r := C.init_qat()
	max_object_size := int(C.get_max_object_size())
	fmt.Println("init_qat:", r, "max_engine:", max_engine, "max_object_size:", max_object_size)
    
	for j:=0;j<max_engine;j++ {
		eng_i := C.get_engine()
		if eng_i < 0 {
		    fmt.Println("failure. index:", j, " eng_i:", eng_i)
		    return;
		}
		chan_engines<-int(eng_i)
	}
	
	init_sum_threads()
	
	go func() {
		for {
			time.Sleep(time.Duration(20)*time.Second)
			golog.Println("free qat engines=", len(chan_engines), "in use=", inflight_engine_num)
		}
	} ()
	
	inited = 1
	fmt.Println("inited.")
}

type Md5accel struct {
	eng_i int
	buf_i int
	blocksize int
	sum_inflight chan int
	buf_arr *[PIECE_NUM]uintptr
	digest []byte
}

func New() hash.Hash {
	Init_qat_hash()
	
	var m hash.Hash = new(Md5accel)
	m.Reset()
	Inc_inflight_engine_num()
	return m
}

func (m *Md5accel) Size() int { return Md5Size }

func (m *Md5accel) Write(data []byte) (nn int, err error) {
	// data is already written to the qat buffer
	m.blocksize += len(data)
	return m.blocksize, nil
}

func (m *Md5accel) Sum(data []byte) []byte {
	inflight := <- m.sum_inflight

	if(m.digest[0] != 0 || m.digest[1] != 0 || m.digest[2] != 0) {
		//fmt.Println("digest2:", hex.EncodeToString(m.digest))
		m.sum_inflight <- (inflight + 1)
		return m.digest
	}
	
	if m.eng_i < 0 {
		golog.Println("failure. m.eng_i=", m.eng_i, "m.digest=", m.digest, "len(data)=", len(data))
	}

	if len(data) > 0 {
		r := C.md5_write(C.int(m.eng_i), (*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)), 1);
		if r != 0 {
			golog.Println("======= md5_write2 failure =========")
		}
	}
	
	r2 := C.md5_sum(C.int(m.eng_i), (*C.uchar)(unsafe.Pointer(&m.digest[0])))
	if r2 != 0 {
		golog.Println("======= md5_sum failure =========")
	}
	
	chan_engines <- m.eng_i
	m.eng_i = -1
	atomic.AddInt32(&inflight_engine_num, -1)
	
	//fmt.Println(m.blocksize, "digest:", hex.EncodeToString(m.digest))
	m.sum_inflight <- (inflight + 1)

	return m.digest
}

func (m *Md5accel) Reset() {
	m.blocksize = 0
	m.eng_i = -1
	m.buf_i = 0
	m.digest = make([]byte, 16)
	m.buf_arr = nil
	m.sum_inflight = make(chan int, 1)
	m.sum_inflight <- 0
}

func (m *Md5accel) BlockSize() int {
	return m.blocksize
}

var max_r int = 120
var max_thread int = 120
var chan_r chan hash.Hash

func init_sum_threads() {
	chan_r = make(chan hash.Hash, max_r)
	for i:=0; i<max_thread; i++ {
		go func() {
			for {
				h := <- chan_r
				if h != nil {
					//t1 := time.Now().UnixNano()
					h.Sum(nil);
					//t2 := time.Now().UnixNano()
					//td := t2 - t1
					
					//golog.Println("t1:", t1, "t2:", t2, "QAT:", td)
				}
			}
		} ()
	}
}

func MD5Sum(h hash.Hash) {
	if h != nil {
		tp := reflect.TypeOf(h).String()
		if tp == "*md5accel.Md5accel" {
			chan_r <- h
		}
	}
}

func GetAccelerator(h hash.Hash) (int) {
	// version check
	Accel_version_check()
	
	if h != nil {
		tp := reflect.TypeOf(h).String()
		if tp == "*md5accel.Md5accel" {
			if m, ok := h.(*Md5accel); ok {
				if m.eng_i < 0 {
					//atomic.AddInt32(&inflight_engine_num, 1)
					m.eng_i = <-chan_engines
					C.reset_engine(C.int(m.eng_i))
				}
				return m.eng_i
			}
		}
	}
	return -1
}

func Accel_version_check() {
	max_object_size := int(C.get_max_object_size()) * humanize.MiByte
	piece_size := int(C.get_cont_piece_size())
	piece_num := max_object_size / piece_size
	if(piece_num != PIECE_NUM) {
		golog.Println("Failure: piece_num mismatch!")
	}
}

func Accel_get_next_buff(h hash.Hash) ([]byte) {
	m, _ := h.(*Md5accel)
	
	if m.buf_arr == nil {
		buff_arr_ := C.get_engine_buffs(C.int(m.eng_i))
		m.buf_arr = (*[PIECE_NUM]uintptr)(buff_arr_)
	}
	
	buff := (*[PIECE_SIZE]byte)(unsafe.Pointer(m.buf_arr[m.buf_i]))
	m.buf_i++
	return buff[:]
}

func Accel_write_data(eng_i int, buf []byte, len int64) {
	ret := C.md5_write(C.int(eng_i), (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len), 0);
	if ret != 0 {
		golog.Println("======= md5_write failure =========")
	}
}

/*
func (r *Reader) PutQATEng() (error) {
	if r.md5Hash != nil {
		tp := reflect.TypeOf(r.md5Hash).String()
		if tp == "*md5accel.Md5accel" {
			if m, ok := r.md5Hash.(*Md5accel); ok {
				if m.eng_i >= 0 {
					chan_engines <- m.eng_i
					m.eng_i = -1
					atomic.AddInt32(&inflight_engine_num, -1)
					return nil
				}
			}
		}
	}
	
	return nil
}

func Accel_get_buff_arr(eng_i int) (*[PIECE_NUM]uintptr) {
	var buff_arr *[PIECE_NUM]uintptr
	
	if(eng_i >= 0) {
		buff_arr_ := C.get_engine_buffs(C.int(eng_i))
		buff_arr = (*[PIECE_NUM]uintptr)(buff_arr_)
	}
	
	return buff_arr
}
*/