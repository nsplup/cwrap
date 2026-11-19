// fskeys 实现 --fs 授权路径的 Flatpak 风格关键字展开。
//
// 支持的关键字（语义对齐 flatpak --filesystem）：
//
//	home / ~ / ~/sub       用户 HOME
//	host                   宿主全部一级目录（跳过基线已覆盖及伪文件系统：
//	                       /proc /sys /dev /usr /etc /run，以及由
//	                       --tmp 管辖的 /tmp）
//	host-os                /usr（基线已只读挂载，展开后 no-op）
//	host-etc               /etc（同上）
//	xdg-config[/sub]       $XDG_CONFIG_HOME（默认 $HOME/.config）
//	xdg-data[/sub]         $XDG_DATA_HOME（默认 $HOME/.local/share）
//	xdg-cache[/sub]        $XDG_CACHE_HOME（默认 $HOME/.cache）
//	xdg-run[/sub]          $XDG_RUNTIME_DIR（默认 /run/user/<uid>）
//	xdg-desktop xdg-documents xdg-download xdg-music xdg-pictures
//	xdg-public-share xdg-templates xdg-videos
//	                       XDG 用户目录，按 user-dirs.dirs 解析，
//	                       未配置时回退 $HOME/<英文名>
//
// 尾缀 "?"（flatpak 语义）：目标不存在时不报错，改用 --bind-try/--ro-bind-try。
package perm

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// FSKeywords 是全部合法关键字（校验与报错用）。
var FSKeywords = []string{
	"home", "host", "host-os", "host-etc",
	"xdg-config", "xdg-data", "xdg-cache", "xdg-run",
	"xdg-desktop", "xdg-documents", "xdg-download", "xdg-music",
	"xdg-pictures", "xdg-public-share", "xdg-templates", "xdg-videos",
}

// pseudoRoots 是 host 关键字展开时跳过的目录：
// 伪文件系统、基线已处理的 /usr /etc 与 /bin /sbin /lib /lib64
// （rootSymlinks 按 merged-usr 形态生成）、tmpfs 的 /run、--tmp 管辖的 /tmp。
var pseudoRoots = []string{
	"/proc", "/sys", "/dev", "/usr", "/etc", "/run", "/tmp",
	"/bin", "/sbin", "/lib", "/lib64",
}

// ResolveFSPath 把 --fs 的 PATH 部分展开为宿主绝对路径列表。
// 返回值：展开路径列表（可能多个，如 host）、是否带 ? 后缀。
func ResolveFSPath(raw string) ([]string, bool, error) {
	path := raw
	tryOK := false
	if strings.HasSuffix(path, "?") {
		tryOK = true
		path = strings.TrimSuffix(path, "?")
	}
	if path == "/" {
		return nil, tryOK, fmt.Errorf("--fs 不允许挂载宿主根目录 /（请使用 host 关键字或逐项授权）")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		return []string{expandHome(path)}, tryOK, nil
	}
	root := path
	sub := ""
	if i := strings.Index(path, "/"); i >= 0 {
		root, sub = path[:i], path[i+1:]
	}
	switch root {
	case "home":
		return []string{expandHome("~" + "/" + sub)}, tryOK, nil
	case "host":
		dirs, err := hostTopDirs()
		if err != nil {
			return nil, tryOK, err
		}
		return dirs, tryOK, nil
	case "host-os":
		return []string{"/usr"}, tryOK, nil
	case "host-etc":
		return []string{"/etc"}, tryOK, nil
	case "xdg-config", "xdg-data", "xdg-cache", "xdg-run":
		base := xdgBase(root)
		if sub != "" {
			base = filepath.Join(base, sub)
		}
		return []string{base}, tryOK, nil
	case "xdg-desktop", "xdg-documents", "xdg-download", "xdg-music",
		"xdg-pictures", "xdg-public-share", "xdg-templates", "xdg-videos":
		base := xdgUserDir(root)
		if sub != "" {
			base = filepath.Join(base, sub)
		}
		return []string{base}, tryOK, nil
	}
	if inList(FSKeywords, root) {
		return nil, tryOK, nil // 不可达：上面已穷举
	}
	if !strings.HasPrefix(path, "/") {
		return nil, tryOK, fmt.Errorf("--fs 路径必须是绝对路径或 flatpak 关键字（%s）：%q",
			strings.Join(FSKeywords, " "), raw)
	}
	return []string{filepath.Clean(path)}, tryOK, nil
}

// FSPathValid 校验 --fs 的 PATH 部分（关键字或绝对路径）。
func FSPathValid(raw string) error {
	_, _, err := ResolveFSPath(raw)
	return err
}

func expandHome(p string) string {
	if p == "~" {
		return userHome()
	}
	return filepath.Clean(filepath.Join(userHome(), strings.TrimPrefix(p, "~")))
}

func userHome() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return "/root"
	}
	return h
}

// hostTopDirs 返回宿主根目录下的一级目录（跳过 pseudoRoots）。
func hostTopDirs() ([]string, error) {
	ents, err := os.ReadDir("/")
	if err != nil {
		return nil, fmt.Errorf("展开 host 关键字失败: %w", err)
	}
	var out []string
	for _, e := range ents {
		p := "/" + e.Name()
		if inList(pseudoRoots, p) {
			continue
		}
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			// 符号链接（如 /bin -> usr/bin）由 bwrap 的 -try 容错
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func xdgBase(key string) string {
	home := userHome()
	switch key {
	case "xdg-config":
		if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
			return v
		}
		return filepath.Join(home, ".config")
	case "xdg-data":
		if v := os.Getenv("XDG_DATA_HOME"); v != "" {
			return v
		}
		return filepath.Join(home, ".local", "share")
	case "xdg-cache":
		if v := os.Getenv("XDG_CACHE_HOME"); v != "" {
			return v
		}
		return filepath.Join(home, ".cache")
	case "xdg-run":
		if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
			return v
		}
		uid := os.Getuid()
		return "/run/user/" + strconv.Itoa(uid)
	}
	return home
}

// xdgUserDirFallback 是未配置 user-dirs.dirs 时的英文回退目录
// （对齐 flatpak：xdg-download -> $HOME/Downloads 等）。
var xdgUserDirFallback = map[string]string{
	"xdg-desktop":      "Desktop",
	"xdg-documents":    "Documents",
	"xdg-download":     "Downloads",
	"xdg-music":        "Music",
	"xdg-pictures":     "Pictures",
	"xdg-public-share": "Public",
	"xdg-templates":    "Templates",
	"xdg-videos":       "Videos",
}

// xdgUserDir 按 ~/.config/user-dirs.dirs 解析 XDG 用户目录，
// 未配置或缺项时回退 $HOME/<英文>。
func xdgUserDir(key string) string {
	fallback := filepath.Join(userHome(), xdgUserDirFallback[key])
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		dir = filepath.Join(userHome(), ".config")
	}
	f, err := os.Open(filepath.Join(dir, "user-dirs.dirs"))
	if err != nil {
		return fallback
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 形如 XDG_DOCUMENTS_DIR="$HOME/Documents"
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k != "XDG_"+strings.ToUpper(strings.TrimPrefix(key, "xdg-"))+"_DIR" {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		v = strings.ReplaceAll(v, "$HOME", userHome())
		if strings.HasPrefix(v, "/") {
			return v
		}
		return fallback
	}

	if err := sc.Err(); err != nil {
		return fallback
	}

	return fallback
}
