package w32timezone

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/hnakamur/w32registry"
	"github.com/hnakamur/w32syscall"
)

var TimeZoneNameNotFoundError = errors.New("TimeZone name not found")

// cf. [Setting the Time Zone using Windows PowerShell - The Deployment Guys - Site Home - TechNet Blogs](http://blogs.technet.com/b/deploymentguys/archive/2009/06/07/setting-the-time-zone-using-windows-powershell.aspx)

type regTzi struct {
	Bias         int32
	StandardBias int32
	DaylightBias int32
	StandardDate syscall.Systemtime
	DaylightDate syscall.Systemtime
}

func getRegTzi(timeZoneName string) (tzi regTzi, err error) {
	subkey := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\` + timeZoneName
	subkeyp, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return
	}

	valname := "TZI"
	valnamep, err := syscall.UTF16PtrFromString(valname)
	if err != nil {
		return
	}

	bufLen := uint32(unsafe.Sizeof(tzi))
	var flags uint32 = w32syscall.RRF_RT_REG_BINARY
	err = w32syscall.RegGetValue(syscall.HKEY_LOCAL_MACHINE, subkeyp, valnamep, flags, nil, (*byte)(unsafe.Pointer(&tzi)), &bufLen)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		err = TimeZoneNameNotFoundError
	}
	return
}

func BuildDynamicTimeZoneInformation(timeZoneName string) (tzi w32syscall.DynamicTimeZoneInformation, err error) {
	subKey := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\` + timeZoneName
	standardName, err := w32registry.GetValueString(syscall.HKEY_LOCAL_MACHINE, subKey, "MUI_Std")
	if err == syscall.ERROR_FILE_NOT_FOUND || standardName == "" {
		standardName, err = w32registry.GetValueString(syscall.HKEY_LOCAL_MACHINE, subKey, "Std")
		if err == syscall.ERROR_FILE_NOT_FOUND {
			err = TimeZoneNameNotFoundError
		}
	}
	if err != nil {
		return
	}
	standardNameChars, err := syscall.UTF16FromString(standardName)
	if err != nil {
		return
	}
	copy(tzi.StandardName[:], standardNameChars)

	daylightName, err := w32registry.GetValueString(syscall.HKEY_LOCAL_MACHINE, subKey, "MUI_Dlt")
	if err == syscall.ERROR_FILE_NOT_FOUND || standardName == "" {
		daylightName, err = w32registry.GetValueString(syscall.HKEY_LOCAL_MACHINE, subKey, "Dlt")
		if err == syscall.ERROR_FILE_NOT_FOUND {
			err = TimeZoneNameNotFoundError
		}
	}
	daylightNameChars, err := syscall.UTF16FromString(daylightName)
	if err != nil {
		return
	}
	copy(tzi.DaylightName[:], daylightNameChars)

	timeZoneNameChars, err := syscall.UTF16FromString(timeZoneName)
	if err != nil {
		return
	}
	copy(tzi.TimeZoneKeyName[:], timeZoneNameChars)

	regTzi, err := getRegTzi(timeZoneName)
	if err != nil {
		return
	}
	tzi.Bias = regTzi.Bias
	tzi.StandardDate = regTzi.StandardDate
	tzi.StandardBias = regTzi.StandardBias
	tzi.DaylightDate = regTzi.DaylightDate
	tzi.DaylightBias = regTzi.DaylightBias
	return
}

func SetSystemTimeZone(tzi w32syscall.DynamicTimeZoneInformation) error {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}

	var hToken syscall.Token
	err = syscall.OpenProcessToken(process, syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &hToken)
	if err != nil {
		return err
	}

	seTimeZoneNameP, err := syscall.UTF16PtrFromString(w32syscall.SE_TIME_ZONE_NAME)
	if err != nil {
		return err
	}
	var tkp w32syscall.TokenPrivileges
	err = w32syscall.LookupPrivilegeValue(nil, seTimeZoneNameP, &tkp.Privileges[0].Luid)
	if err != nil {
		return err
	}
	tkp.PrivilegeCount = 1
	tkp.Privileges[0].Attributes = w32syscall.SE_PRIVILEGE_ENABLED

	err = w32syscall.AdjustTokenPrivileges(hToken, false, &tkp, 0, nil, nil)
	if err != nil {
		return err
	}

	err = w32syscall.SetDynamicTimeZoneInformation(&tzi)
	if err != nil {
		return err
	}

	tkp.Privileges[0].Attributes = 0
	err = w32syscall.AdjustTokenPrivileges(hToken, false, &tkp, 0, nil, nil)
	if err != nil {
		return err
	}

	return nil
}
