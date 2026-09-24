//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	engineDLL         *windows.LazyDLL
	procSetProtect    *windows.LazyProc
	procStart         *windows.LazyProc
	procWaitReady     *windows.LazyProc
	procPacketPort    *windows.LazyProc
	procTunIP         *windows.LazyProc
	procTunDNS        *windows.LazyProc
	procStop          *windows.LazyProc
	procSetPaused     *windows.LazyProc
	procActivePaths   *windows.LazyProc
	procNudge         *windows.LazyProc
	procRebind        *windows.LazyProc
	procSetPacketOut      *windows.LazyProc
	procSetPacketOutBatch *windows.LazyProc
	procInjectPacket      *windows.LazyProc
	procInjectBatch       *windows.LazyProc
	procDisconnect        *windows.LazyProc
	protectImpl           func(int64) bool
	protectCallback       uintptr
	packetOutSink         atomic.Pointer[func([][]byte)]
	packetOutCallback     uintptr
)

func engineLibName() string { return "csqtt_engine.dll" }

func engineLoad(searchDirs ...string) error {
	path, err := findEngineLib(engineLibName(), searchDirs...)
	if err != nil {
		return err
	}
	engineDLL = windows.NewLazyDLL(path)
	if err := engineDLL.Load(); err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}
	procSetProtect = engineDLL.NewProc("csqtt_engine_set_protect")
	procStart = engineDLL.NewProc("csqtt_engine_start")
	procWaitReady = engineDLL.NewProc("csqtt_engine_wait_ready")
	procPacketPort = engineDLL.NewProc("csqtt_engine_packet_port")
	procTunIP = engineDLL.NewProc("csqtt_engine_tun_ip")
	procTunDNS = engineDLL.NewProc("csqtt_engine_tun_dns")
	procStop = engineDLL.NewProc("csqtt_engine_stop")
	procSetPaused = engineDLL.NewProc("csqtt_engine_set_paused")
	procActivePaths = engineDLL.NewProc("csqtt_engine_active_paths")
	procNudge = engineDLL.NewProc("csqtt_engine_nudge")
	procRebind = engineDLL.NewProc("csqtt_engine_rebind")
	procSetPacketOut = engineDLL.NewProc("csqtt_engine_set_packet_out")
	procSetPacketOutBatch = engineDLL.NewProc("csqtt_engine_set_packet_out_batch")
	procInjectPacket = engineDLL.NewProc("csqtt_engine_inject_packet")
	procInjectBatch = engineDLL.NewProc("csqtt_engine_inject_batch")
	procDisconnect = engineDLL.NewProc("csqtt_engine_disconnect")
	return nil
}

func engineSetProtect(fn func(int64) bool) {
	protectImpl = fn
	protectCallback = syscall.NewCallback(func(fd uintptr) uintptr {
		if protectImpl == nil {
			return 1
		}
		if protectImpl(int64(fd)) {
			return 1
		}
		return 0
	})
	_, _, _ = procSetProtect.Call(protectCallback)
}

func engineSetPacketOut(fn func([][]byte)) {
	if fn == nil {
		packetOutSink.Store(nil)
		return
	}
	packetOutSink.Store(&fn)
	packetOutCallback = syscall.NewCallback(func(ptrs, lens, count uintptr) uintptr {
		sink := packetOutSink.Load()
		if sink == nil || *sink == nil || ptrs == 0 || lens == 0 || count == 0 {
			return 0
		}
		n := int(count)
		ptrSlice := unsafe.Slice((**byte)(unsafe.Pointer(ptrs)), n)
		lenSlice := unsafe.Slice((*int32)(unsafe.Pointer(lens)), n)
		batch := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			if ptrSlice[i] == nil || lenSlice[i] <= 0 {
				continue
			}
			batch = append(batch, unsafe.Slice(ptrSlice[i], int(lenSlice[i])))
		}
		if len(batch) > 0 {
			(*sink)(batch)
		}
		return 0
	})
	if procSetPacketOutBatch.Find() == nil {
		_, _, _ = procSetPacketOutBatch.Call(packetOutCallback)
		return
	}
	// Legacy single-packet fallback for older engine DLLs.
	packetOutCallback = syscall.NewCallback(func(data uintptr, n uintptr) uintptr {
		sink := packetOutSink.Load()
		if sink == nil || *sink == nil || data == 0 || n == 0 {
			return 0
		}
		buf := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(n))
		(*sink)([][]byte{buf})
		return 0
	})
	_, _, _ = procSetPacketOut.Call(packetOutCallback)
}

func engineInjectPacket(pkt []byte) error {
	return engineInjectPackets([][]byte{pkt})
}

func engineInjectPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if procInjectBatch != nil && procInjectBatch.Find() == nil {
		ptrs := make([]uintptr, len(pkts))
		lens := make([]int32, len(pkts))
		for i, pkt := range pkts {
			if len(pkt) == 0 {
				continue
			}
			ptrs[i] = uintptr(unsafe.Pointer(&pkt[0]))
			lens[i] = int32(len(pkt))
		}
		r, _, _ := procInjectBatch.Call(
			uintptr(unsafe.Pointer(&ptrs[0])),
			uintptr(unsafe.Pointer(&lens[0])),
			uintptr(len(pkts)),
		)
		if int32(r) != 0 {
			return fmt.Errorf("inject_batch: %d", int32(r))
		}
		return nil
	}
	for _, pkt := range pkts {
		if len(pkt) == 0 {
			continue
		}
		if procInjectPacket == nil {
			return fmt.Errorf("inject_packet unavailable")
		}
		r, _, _ := procInjectPacket.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)))
		if int32(r) != 0 {
			return fmt.Errorf("inject_packet: %d", int32(r))
		}
	}
	return nil
}

func engineDisconnect() {
	if procDisconnect != nil && procDisconnect.Find() == nil {
		_, _, _ = procDisconnect.Call()
	}
}

func engineStart(configJSON string) error {
	p, err := windows.BytePtrFromString(configJSON)
	if err != nil {
		return err
	}
	r, _, _ := procStart.Call(uintptr(unsafe.Pointer(p)))
	if r != 0 {
		return fmt.Errorf("csqtt_engine_start: %d", int32(r))
	}
	return nil
}

func engineWaitReady(timeoutMs int) error {
	r, _, _ := procWaitReady.Call(uintptr(timeoutMs))
	if r != 0 {
		return fmt.Errorf("engine not ready")
	}
	return nil
}

func enginePacketPort() int {
	r, _, _ := procPacketPort.Call()
	return int(int32(r))
}

func engineTunIP() string  { return engineCString(procTunIP) }
func engineTunDNS() string { return engineCString(procTunDNS) }

func engineCString(p *windows.LazyProc) string {
	buf := make([]byte, 128)
	r, _, _ := p.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r != 0 {
		return ""
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}

func engineStop() {
	if procStop != nil {
		_, _, _ = procStop.Call()
	}
}

func engineSetPaused(paused bool) {
	if procSetPaused == nil {
		return
	}
	v := uintptr(0)
	if paused {
		v = 1
	}
	_, _, _ = procSetPaused.Call(v)
}

func engineActivePaths() int {
	if procActivePaths == nil || procActivePaths.Find() != nil {
		return -1
	}
	r, _, _ := procActivePaths.Call()
	return int(int32(r))
}

func engineNudge() {
	if procNudge == nil || procNudge.Find() != nil {
		return
	}
	_, _, _ = procNudge.Call()
}

func engineRebind() bool {
	if procRebind == nil || procRebind.Find() != nil {
		return false
	}
	_, _, _ = procRebind.Call()
	return true
}

func findEngineLib(name string, extra ...string) (string, error) {
	var dirs []string
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
