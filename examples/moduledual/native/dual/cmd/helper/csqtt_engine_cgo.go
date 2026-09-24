//go:build cgo && !windows

package main

/*
#cgo linux LDFLAGS: -ldl
#cgo android LDFLAGS: -ldl
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef int32_t (*csqtt_protect_cb)(int64_t);

static void *eng;
static void (*fn_set_protect)(csqtt_protect_cb);
static int32_t (*fn_start)(const char *);
static int32_t (*fn_wait_ready)(int32_t);
static int32_t (*fn_packet_port)(void);
static int32_t (*fn_tun_ip)(char *, int32_t);
static int32_t (*fn_tun_dns)(char *, int32_t);
static void (*fn_stop)(void);
static void (*fn_set_paused)(int32_t);
static int32_t (*fn_active_paths)(void);
static void (*fn_nudge)(void);
static void (*fn_rebind)(void);
static void (*fn_set_packet_out)(void *);
static void (*fn_set_packet_out_batch)(void *);
static int32_t (*fn_inject_packet)(const uint8_t *, int32_t);
static int32_t (*fn_inject_batch)(const uint8_t **, const int32_t *, int32_t);
static void (*fn_disconnect)(void);

extern int32_t goProtectFd(int64_t fd);
extern void goPacketOut(uint8_t *data, int32_t n);
extern void goPacketOutBatch(uint8_t **ptrs, int32_t *lens, int32_t count);

static int csqtt_load(const char *path) {
	eng = dlopen(path, RTLD_NOW);
	if (!eng) {
		return -1;
	}
	fn_set_protect = (void (*)(csqtt_protect_cb))dlsym(eng, "csqtt_engine_set_protect");
	fn_start = (int32_t (*)(const char *))dlsym(eng, "csqtt_engine_start");
	fn_wait_ready = (int32_t (*)(int32_t))dlsym(eng, "csqtt_engine_wait_ready");
	fn_packet_port = (int32_t (*)(void))dlsym(eng, "csqtt_engine_packet_port");
	fn_tun_ip = (int32_t (*)(char *, int32_t))dlsym(eng, "csqtt_engine_tun_ip");
	fn_tun_dns = (int32_t (*)(char *, int32_t))dlsym(eng, "csqtt_engine_tun_dns");
	fn_stop = (void (*)(void))dlsym(eng, "csqtt_engine_stop");
	fn_set_paused = (void (*)(int32_t))dlsym(eng, "csqtt_engine_set_paused");
	fn_active_paths = (int32_t (*)(void))dlsym(eng, "csqtt_engine_active_paths");
	fn_nudge = (void (*)(void))dlsym(eng, "csqtt_engine_nudge");
	fn_rebind = (void (*)(void))dlsym(eng, "csqtt_engine_rebind");
	fn_set_packet_out = (void (*)(void *))dlsym(eng, "csqtt_engine_set_packet_out");
	fn_set_packet_out_batch = (void (*)(void *))dlsym(eng, "csqtt_engine_set_packet_out_batch");
	fn_inject_packet = (int32_t (*)(const uint8_t *, int32_t))dlsym(eng, "csqtt_engine_inject_packet");
	fn_inject_batch = (int32_t (*)(const uint8_t **, const int32_t *, int32_t))dlsym(eng, "csqtt_engine_inject_batch");
	fn_disconnect = (void (*)(void))dlsym(eng, "csqtt_engine_disconnect");
	if (!fn_start || !fn_wait_ready || !fn_packet_port || !fn_tun_ip || !fn_stop) {
		return -2;
	}
	return 0;
}

static const char *csqtt_dlerror(void) { return dlerror(); }

static void csqtt_bind_protect(void) {
	if (fn_set_protect) {
		fn_set_protect(goProtectFd);
	}
}

static void csqtt_bind_packet_out(void) {
	if (fn_set_packet_out_batch) {
		fn_set_packet_out_batch((void *)goPacketOutBatch);
	} else if (fn_set_packet_out) {
		fn_set_packet_out((void *)goPacketOut);
	}
}

static int32_t csqtt_start(const char *j) { return fn_start ? fn_start(j) : -1; }
static int32_t csqtt_wait_ready(int32_t ms) { return fn_wait_ready ? fn_wait_ready(ms) : -1; }
static int32_t csqtt_packet_port(void) { return fn_packet_port ? fn_packet_port() : 0; }
static int32_t csqtt_tun_ip(char *b, int32_t n) { return fn_tun_ip ? fn_tun_ip(b, n) : -1; }
static int32_t csqtt_tun_dns(char *b, int32_t n) { return fn_tun_dns ? fn_tun_dns(b, n) : -1; }
static void csqtt_stop(void) { if (fn_stop) fn_stop(); }
static void csqtt_set_paused(int32_t v) { if (fn_set_paused) fn_set_paused(v); }
static int32_t csqtt_active_paths(void) { return fn_active_paths ? fn_active_paths() : -1; }
static void csqtt_nudge(void) { if (fn_nudge) fn_nudge(); }
static int32_t csqtt_rebind(void) { if (!fn_rebind) return -1; fn_rebind(); return 0; }
static int32_t csqtt_inject(const uint8_t *d, int32_t n) {
	return fn_inject_packet ? fn_inject_packet((uint8_t *)d, n) : -1;
}
static int csqtt_has_inject_batch(void) { return fn_inject_batch != 0; }
static int32_t csqtt_inject_batch(const uint8_t **p, const int32_t *l, int32_t n) {
	return fn_inject_batch ? fn_inject_batch(p, l, n) : -4;
}
static void csqtt_disconnect(void) { if (fn_disconnect) fn_disconnect(); }
*/
import "C"

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"strings"
	"unsafe"
)

var protectImpl func(int64) bool
var packetOutSink atomic.Pointer[func([][]byte)]

//export goProtectFd
func goProtectFd(fd C.int64_t) C.int32_t {
	if protectImpl == nil {
		return 1
	}
	if protectImpl(int64(fd)) {
		return 1
	}
	return 0
}

//export goPacketOut
func goPacketOut(data *C.uint8_t, n C.int32_t) {
	if data == nil || n <= 0 {
		return
	}
	sink := packetOutSink.Load()
	if sink == nil || *sink == nil {
		return
	}
	// Borrowed slice: InjectInbound → MakeWithData copies before return.
	// Do not retain past this call.
	buf := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(n))
	(*sink)([][]byte{buf})
}

//export goPacketOutBatch
func goPacketOutBatch(ptrs **C.uint8_t, lens *C.int32_t, count C.int32_t) {
	if ptrs == nil || lens == nil || count <= 0 {
		return
	}
	sink := packetOutSink.Load()
	if sink == nil || *sink == nil {
		return
	}
	n := int(count)
	ptrSlice := unsafe.Slice(ptrs, n)
	lenSlice := unsafe.Slice(lens, n)
	batch := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if ptrSlice[i] == nil || lenSlice[i] <= 0 {
			continue
		}
		batch = append(batch, unsafe.Slice((*byte)(unsafe.Pointer(ptrSlice[i])), int(lenSlice[i])))
	}
	if len(batch) > 0 {
		(*sink)(batch)
	}
}

func engineLibName() string {
	if runtime.GOOS == "darwin" {
		return "libcsqtt_engine.dylib"
	}
	return "libcsqtt_engine.so"
}

func engineLoad(searchDirs ...string) error {
	path, err := findEngineLib(engineLibName(), searchDirs...)
	if err != nil {
		return err
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	if rc := C.csqtt_load(cpath); rc != 0 {
		errStr := C.GoString(C.csqtt_dlerror())
		return fmt.Errorf("dlopen %s: %s (code %d)", path, errStr, int(rc))
	}
	return nil
}

func engineSetProtect(fn func(int64) bool) {
	protectImpl = fn
	C.csqtt_bind_protect()
}

func engineSetPacketOut(fn func([][]byte)) {
	if fn == nil {
		packetOutSink.Store(nil)
		return
	}
	packetOutSink.Store(&fn)
	C.csqtt_bind_packet_out()
}

func engineInjectPacket(pkt []byte) error {
	return engineInjectPackets([][]byte{pkt})
}

func engineInjectPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if C.csqtt_has_inject_batch() == 0 {
		for _, pkt := range pkts {
			if len(pkt) == 0 {
				continue
			}
			rc := C.csqtt_inject((*C.uint8_t)(unsafe.Pointer(&pkt[0])), C.int32_t(len(pkt)))
			if rc != 0 {
				return fmt.Errorf("inject_packet: %d", int32(rc))
			}
		}
		return nil
	}
	n := 0
	for _, pkt := range pkts {
		if len(pkt) > 0 {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	ptrs := make([]*C.uint8_t, n)
	lens := make([]C.int32_t, n)
	// cgo rejects a Go pointer to an unpinned Go pointer. The batch table
	// holds pointers into packet bytes, so both the table and each buffer
	// stay pinned until Rust has copied them.
	var pin runtime.Pinner
	defer pin.Unpin()
	i := 0
	for _, pkt := range pkts {
		if len(pkt) == 0 {
			continue
		}
		pin.Pin(&pkt[0])
		ptrs[i] = (*C.uint8_t)(unsafe.Pointer(&pkt[0]))
		lens[i] = C.int32_t(len(pkt))
		i++
	}
	pin.Pin(&ptrs[0])
	rc := C.csqtt_inject_batch((**C.uint8_t)(unsafe.Pointer(&ptrs[0])), &lens[0], C.int32_t(n))
	if rc != 0 {
		return fmt.Errorf("inject_batch: %d", int32(rc))
	}
	return nil
}

func engineDisconnect() {
	C.csqtt_disconnect()
}

func engineStart(configJSON string) error {
	cj := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cj))
	if rc := C.csqtt_start(cj); rc != 0 {
		return fmt.Errorf("csqtt_engine_start: %d", int32(rc))
	}
	return nil
}

func engineWaitReady(timeoutMs int) error {
	if C.csqtt_wait_ready(C.int32_t(timeoutMs)) != 0 {
		return fmt.Errorf("engine not ready")
	}
	return nil
}

func enginePacketPort() int { return int(C.csqtt_packet_port()) }

func engineTunIP() string {
	buf := make([]byte, 128)
	if C.csqtt_tun_ip((*C.char)(unsafe.Pointer(&buf[0])), C.int32_t(len(buf))) != 0 {
		return ""
	}
	return cstrFrom(buf)
}

func engineTunDNS() string {
	buf := make([]byte, 128)
	if C.csqtt_tun_dns((*C.char)(unsafe.Pointer(&buf[0])), C.int32_t(len(buf))) != 0 {
		return ""
	}
	return cstrFrom(buf)
}

func cstrFrom(buf []byte) string {
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}

func engineStop() { C.csqtt_stop() }

func engineSetPaused(paused bool) {
	v := C.int32_t(0)
	if paused {
		v = 1
	}
	C.csqtt_set_paused(v)
}

// engineActivePaths — READY TURN sessions; -1 when the engine build lacks the symbol.
func engineActivePaths() int { return int(C.csqtt_active_paths()) }

// engineNudge — re-validate every TURN path now (wake / stall).
func engineNudge() { C.csqtt_nudge() }

// engineRebind — soft handover: re-allocate every TURN path on the current network with the
// cached credentials, engine stays up. false → the loaded engine predates the symbol; caller
// falls back to a full recycle.
func engineRebind() bool { return C.csqtt_rebind() == 0 }

func findEngineLib(name string, extra ...string) (string, error) {
	var dirs []string
	if d := androidModuleDir(); d != "" {
		dirs = append(dirs, d)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	dirs = append(dirs, extra...)
	for _, d := range dirs {
		if d == "" {
			continue
		}
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	if env := os.Getenv("CSQTT_ENGINE_LIB"); env != "" {
		return env, nil
	}
	return "", fmt.Errorf("%s not found next to helper (searched %v)", name, dirs)
}

func androidModuleDir() string {
	if runtime.GOOS != "android" {
		return ""
	}
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		idx := strings.Index(line, "libcsqtthelper.so")
		if idx < 0 {
			continue
		}
		path := strings.TrimSpace(line[strings.LastIndex(line, " ")+1:])
		if strings.HasSuffix(path, "libcsqtthelper.so") {
			return filepath.Dir(path)
		}
	}
	return ""
}
