// SPDX-License-Identifier: MIT
//
// Dual AntiNet helper: one binary, two schemes (csqtt:// + qwdtt://).
// Canons shared/* are injected into this package by build.py.
// CSQTT datapath lives in this package (csqtt_*.go); qWDTT is internal/qwdtt.
package main

import (
	"fmt"
	"log"
	"strings"
	"syscall"

	"dual-antinet/internal/qwdtt"
	"dual-antinet/internal/route"
)

func moduleCall(verb, arg string) string {
	verb = strings.ToLower(strings.TrimSpace(verb))
	arg = strings.TrimSpace(arg)
	scheme, err := route.FromLink(arg)
	if err != nil {
		// Import / opaque text: try both parsers (MODULE_API §2.2 normalize/summarize).
		switch verb {
		case "normalize":
			if out := qwdtt.Call("normalize", arg); out != "" {
				return out
			}
			return csqttCall("normalize", arg)
		case "summarize":
			if out := qwdtt.Call("summarize", arg); out != "" {
				return out
			}
			return csqttCall("summarize", arg)
		case "canping":
			if out := qwdtt.Call("canping", arg); out == "ok" {
				return "ok"
			}
			if out := csqttCall("canping", arg); out == "ok" {
				return "ok"
			}
			return "no"
		}
		return ""
	}
	switch scheme {
	case route.SchemeCSQTT:
		return csqttCall(verb, arg)
	case route.SchemeQWDTT:
		return qwdtt.Call(verb, arg)
	default:
		return ""
	}
}

func wireQwdtt() {
	qwdtt.WireHost(qwdtt.HostHooks{
		EmitProgress:       emitProgress,
		EmitLog:            emitLog,
		EmitStatus:         emitStatus,
		EmitEventAck:       emitEventAck,
		DieWithParent:      dieWithParent,
		ProtectFromOomKill: protectFromOomKill,
	})
	qwdtt.WireDialControl(func(protectPath string, st *qwdtt.ProtectStat) func(network, address string, c syscall.RawConn) error {
		_ = st
		return dialControl(protectPath, nil)
	})
	qwdtt.WireSocks(openListener, writeReady)
	qwdtt.WireActions(awaitActionResult)
	qwdtt.WireHostEvents(setHostEventHandler, startHostEventReader)
	qwdtt.WireStatusConsts("ready", statusOK, statusFatal)
	qwdtt.WireAutoHashes(qwdttAutoHashes)
}

// qwdttAutoHashes — Авто API (calls.start) для добора хешей под группы qWDTT.
// wantHashes — сколько звонков создать (1 хеш ≈ 1 группа из 9 воркеров), не CSQTT-формула.
func qwdttAutoHashes(profileDir, protectPath, moduleState string, wantHashes int, hashMode string) ([]string, func(), error) {
	_ = hashMode // уже нормализован в Run (auto_api); auto_js сюда не доходит
	resolver := newProtectedResolver("", protectPath)
	configureVkHTTP(protectPath, resolver)
	s := csqttStringsFor("") // язык уже в логах qWDTT; строки OAuth — дефолт
	tok, terr := ensureVkToken(moduleState, profileDir, s, resolver)
	if terr != nil {
		return nil, nil, terr
	}
	emitProgress("%s", s.vkAutoAPIProgress)
	started, aerr := startVkAutoCallsCount(tok, wantHashes)
	if aerr != nil || len(started.Hashes) == 0 {
		if aerr == nil {
			aerr = fmt.Errorf("empty hash list")
		}
		return nil, nil, aerr
	}
	cleanup := func() { finishVkAutoCalls(tok, started.Calls) }
	return started.Hashes, cleanup, nil
}

func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	wireQwdtt()

	link := linkFromConfig(configContent)
	scheme, err := route.FromLink(link)
	if err != nil {
		log.Printf("dual: %v", err)
		emitStatus(statusFatal, "bad link scheme")
		return 1
	}
	emitLog("dual: starting scheme=%s", scheme)

	switch scheme {
	case route.SchemeCSQTT:
		return csqttRun(configContent, resolversPath, profileDir, protectPath, listenFd)
	case route.SchemeQWDTT:
		return qwdtt.Run(configContent, resolversPath, profileDir, protectPath, listenFd)
	default:
		emitStatus(statusFatal, "unknown scheme")
		return 1
	}
}

func linkFromConfig(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "LINK=") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}
