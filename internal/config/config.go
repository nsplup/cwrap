// Package config 负责 cwrap 自身配置（TOML）的读写。
//
// 层级：全局 ~/.config/cwrap/global.toml -> 应用 ~/.config/cwrap/apps/<name>.toml
// -> 命令行 FLAG（标量字段逐级覆盖，列表字段累加并去重）。
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cwrap/internal/perm"

	"github.com/BurntSushi/toml"
)

// Dir 返回 cwrap 配置目录（$XDG_CONFIG_HOME/cwrap，默认 ~/.config/cwrap）。
func Dir() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "cwrap")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/tmp"
	}
	return filepath.Join(home, ".config", "cwrap")
}

func globalPath() string { return filepath.Join(Dir(), "global.toml") }

func appPath(name string) string {
	return filepath.Join(Dir(), "apps", name+".toml")
}

// LoadGlobal 读取全局默认配置；文件不存在时返回空配置。
func LoadGlobal() (*perm.Permissions, error) {
	return loadFile(globalPath())
}

// Program 是 cwrap 程序级配置（区别于全局权限配置 global.toml），
// 文件为 ~/.config/cwrap/config.toml，用于指定外部工具的可执行路径。
type Program struct {
	BwrapPath        string `toml:"bwrap_path,omitempty"`          // 默认 "bwrap"（按 PATH 查找）
	XdgDBusProxyPath string `toml:"xdg_dbus_proxy_path,omitempty"` // 默认 "xdg-dbus-proxy"（按 PATH 查找）
	// 自定义 flatpak-xdg-utils 的 xdg-open 路径（--allow portal 时覆盖容器
	// 内 /usr/bin/xdg-open）。留空则按多发行版候选路径自动探测
	// （lib/libexec/lib64 等）；指定的文件不存在时警告并回退自动探测。
	XDGOpenPath string `toml:"xdg_open_path,omitempty"`
}

// DefaultBwrapCmd / DefaultDBusProxyCmd 是未自定义时使用的命令名。
const (
	DefaultBwrapCmd     = "bwrap"
	DefaultDBusProxyCmd = "xdg-dbus-proxy"
)

// BwrapCmd 返回实际使用的 bwrap 命令（未自定义时按 PATH 查找）。
func (p Program) BwrapCmd() string {
	if p.BwrapPath != "" {
		return p.BwrapPath
	}
	return DefaultBwrapCmd
}

// DBusProxyCmd 返回实际使用的 xdg-dbus-proxy 命令。
func (p Program) DBusProxyCmd() string {
	if p.XdgDBusProxyPath != "" {
		return p.XdgDBusProxyPath
	}
	return DefaultDBusProxyCmd
}

func programPath() string { return filepath.Join(Dir(), "config.toml") }

// LoadProgram 读取程序级配置；文件不存在时返回空配置（全部使用默认命令）。
func LoadProgram() (Program, error) {
	var prog Program
	data, err := os.ReadFile(programPath())
	if err != nil {
		if os.IsNotExist(err) {
			return prog, nil
		}
		return prog, fmt.Errorf("读取程序配置 %s: %w", programPath(), err)
	}
	if err := toml.Unmarshal(data, &prog); err != nil {
		return prog, fmt.Errorf("解析程序配置 %s: %w", programPath(), err)
	}
	return prog, nil
}

// LoadApp 读取指定应用的配置；文件不存在时返回空配置。
func LoadApp(name string) (*perm.Permissions, error) {
	return loadFile(appPath(name))
}

// AppExists 判断应用配置是否存在。
func AppExists(name string) bool {
	_, err := os.Stat(appPath(name))
	return err == nil
}

func loadFile(path string) (*perm.Permissions, error) {
	p := &perm.Permissions{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return nil, fmt.Errorf("读取配置 %s: %w", path, err)
	}
	// 严格模式：未知字段报错。toml 默认静默忽略未知键，
	// 拼错的键名会静默失效，排查困难（用 MetaData.Undecoded 检查，
	// BurntSushi/toml v1.4 无 DisallowUnknownFields）。
	dec := toml.NewDecoder(bytes.NewReader(data))
	md, derr := dec.Decode(p)
	if derr != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", path, derr)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("配置 %s 含未知字段: %s", path, strings.Join(keys, ", "))
	}
	return p, nil
}

// SaveApp 把权限写为应用配置文件（--persist 与 permission export 共用）。
func SaveApp(p *perm.Permissions) error {
	if p.App == "" {
		return fmt.Errorf("保存配置需要应用名")
	}
	dir := filepath.Dir(appPath(p.App))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".cwrap-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	enc := toml.NewEncoder(f)
	if err := enc.Encode(p); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, appPath(p.App))
}

// AppPath 返回应用配置文件路径（提示信息用）。
func AppPath(name string) string { return appPath(name) }
