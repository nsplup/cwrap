// Package config 负责 cwrap 自身配置（TOML）的读写。
//
// 层级：全局 ~/.config/cwrap/cwrap.toml -> 应用 ~/.config/cwrap/apps/<name>.toml
// -> 命令行 FLAG（逐级覆盖，后者非空字段覆盖前者）。
package config

import (
	"fmt"
	"os"
	"path/filepath"

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

func globalPath() string { return filepath.Join(Dir(), "cwrap.toml") }

func appPath(name string) string {
	return filepath.Join(Dir(), "apps", name+".toml")
}

// LoadGlobal 读取全局默认配置；文件不存在时返回空配置。
func LoadGlobal() (*perm.Permissions, error) {
	return loadFile(globalPath())
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
	if err := toml.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", path, err)
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
