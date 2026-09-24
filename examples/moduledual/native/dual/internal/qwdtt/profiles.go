// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import (
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"path/filepath"
)

// Profile holds consistent browser fingerprint headers for TLS+HTTP requests.
type Profile struct {
	UserAgent       string `json:"user_agent"`
	SecChUa         string `json:"sec_ch_ua"`
	SecChUaMobile   string `json:"sec_ch_ua_mobile"`
	SecChUaPlatform string `json:"sec_ch_ua_platform"`
}

// SavedProfile is a saved real browser profile loaded from disk.
type SavedProfile struct {
	Profile
	DeviceJSON string `json:"device_json"`
	BrowserFp  string `json:"browser_fp"`
}

const (
	profileFile         = "vk_profile.json"
	captchaBrowserFpFile = "captcha_browser_fp"
)

// stateFilePath — АНТИНЕТ-ПАТЧ поверх апстрима: путь к файлу состояния модуля.
//
// Апстрим (HEAD `fae121e`, `go_client/profiles.go:26`) держит оба имени ГОЛЫМИ
// относительными путями и открывает их от CWD процесса. У автора это верно: qWDTT там —
// десктопная утилита, запускаемая из собственного каталога.
//
// В нашем Android-порту тот же код исполняется внутри слот-процесса `:modN`, у которого
// CWD = "/" — read-only. `os.WriteFile` падает с EROFS, ротация профиля молча не
// происходит (апстрим её ошибку ЛОГИРУЕТ И ИДЁТ ДАЛЬШЕ — `creds.go:629-632`, у него она
// недостижима), VK видит ту же личность и выдаёт капчу снова. В живом логе это выглядит как
// серия подряд идущих `ACTION_REQUIRED(captcha-100-N)`: юзер решает каждую успешно
// (`WBV: auto solve succeeded`), а перед каждой стоит `profile rotate failed: open
// vk_profile.json: read-only file system`.
//
// `moduleProfileDir` приходит от хоста (`realMain`, run.go) и указывает на
// `files/module-state/<id>/` — writable. Пустая строка = standalone-CLI без profileDir:
// тогда поведение апстрима сохраняется 1:1. Тот же идиом применён каноном `shared/hostproto`
// (`awaitActionResult` кладёт туда `action_result.<id>`); новой сущности не заводим.
func stateFilePath(name string) string {
	if moduleProfileDir == "" {
		return name
	}
	return filepath.Join(moduleProfileDir, name)
}

func LoadProfileFromDisk() (*SavedProfile, error) {
	data, err := os.ReadFile(stateFilePath(profileFile))
	if err != nil {
		return nil, err
	}
	var sp SavedProfile
	if err := json.Unmarshal(data, &sp); err != nil {
		return nil, err
	}
	return &sp, nil
}

// rotateCaptchaBrowserFP — полная ротация профиля капчи (fp + UA + device_json).
func rotateCaptchaBrowserFP() (*SavedProfile, error) {
	return rotateCaptchaProfile()
}

func rotateCaptchaProfile() (*SavedProfile, error) {
	fp, err := captchaV2BrowserFP()
	if err != nil {
		return nil, err
	}
	p := getRandomProfile()
	deviceJSON := captchaV2VariedDeviceJSON(captchaV2DeviceInfo)
	sp := &SavedProfile{
		Profile:    p,
		DeviceJSON: deviceJSON,
		BrowserFp:  fp,
	}
	data, err := json.Marshal(sp)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(stateFilePath(profileFile), data, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(stateFilePath(captchaBrowserFpFile), []byte(fp), 0644); err != nil {
		return nil, err
	}
	log.Printf("[CAPTCHA] captcha profile rotated (fp=%s...)", fp[:8])
	return sp, nil
}

// profileList contains paired User-Agent and Client Hints strings.
var profileList = []Profile{
	// Windows Chrome
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},

	// Windows Edge
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Microsoft Edge";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Microsoft Edge";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},

	// macOS Chrome
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},

	// Linux Chrome
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
}

// getRandomProfile returns a paired User-Agent and Client Hints profile.
func getRandomProfile() Profile {
	return profileList[rand.Intn(len(profileList))]
}
