package model

type Process struct {
	PID         uint32
	ExePath     string
	Platform    string
	Version     int
	FullVersion string
	Status      string
	DataDir     string
	AccountName string
}

// 平台常量定义
const (
	PlatformWindows = "windows"
	PlatformMacOS   = "darwin"
	PlatformLinux   = "linux"
)

const (
	StatusInit    = ""
	StatusOffline = "offline"
	StatusOnline  = "online"
)
