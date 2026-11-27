// 持久化运行目录与实例注册表（取代原 daemon 的陈旧目录清扫）。
//
// 目录布局（每个配置一个持久目录，目录名与 generateFlatpakInfo 使用的
// flatpakAppName 一致）：
//
//	$XDG_RUNTIME_DIR/cwrap/<flatpakAppName>/                 持久化配置目录
//	$XDG_RUNTIME_DIR/cwrap/<flatpakAppName>/instances.json   instanceID -> PID 映射表
//	$XDG_RUNTIME_DIR/cwrap/<flatpakAppName>/.lock            注册表文件锁（flock）
//	$XDG_RUNTIME_DIR/cwrap/<flatpakAppName>/<instanceID>/    单次运行的 socket 目录
//
// 每次通过同一配置启动沙箱时，先在锁内清扫残留：映射表中 PID 已死
// （starttime 校验防 PID 复用）的实例目录、以及不在映射表中的孤儿目录
// （mkdir 后、注册前崩溃的产物——mkdir 与注册同处一个锁段，表外目录
// 必然无存活属主）。正常退出时注销自身条目并删除实例目录；异常退出
// （含 SIGKILL）留下的残留由下一次启动清扫兜底。
package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"cwrap/internal/perm"
)

const (
	mapFileName  = "instances.json"
	lockFileName = ".lock"
)

// InstanceMeta 是映射表中一个实例的属主信息。
// PID 为启动该沙箱的 cwrap 主进程；Start 为其 /proc starttime，
// 用于区分 PID 被内核回收复用的情形。
type InstanceMeta struct {
	PID   int    `json:"pid"`
	Start uint64 `json:"start"`
	App   string `json:"app,omitempty"`
}

// Instance 是一次运行的持久化目录句柄。
type Instance struct {
	AppDir string // 持久化配置目录（跨运行保留）
	Dir    string // 本次运行的 socket 目录（AppDir/<ID>）
	ID     string // instanceID
}

// runtimeBase 返回 cwrap 运行目录基座（$XDG_RUNTIME_DIR/cwrap）。
func runtimeBase() string {
	rt := os.Getenv("XDG_RUNTIME_DIR")
	if rt == "" {
		rt = fmt.Sprintf("/run/user/%d", syscall.Getuid())
	}
	return filepath.Join(rt, "cwrap")
}

// lockDir 对配置目录上 flock 排他锁，返回解锁函数。
// 同一配置的并发启动/退出/清扫由此串行化。
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}

func loadMap(appDir string) map[string]InstanceMeta {
	m := map[string]InstanceMeta{}
	data, err := os.ReadFile(filepath.Join(appDir, mapFileName))
	if err != nil {
		return m
	}
	_ = json.Unmarshal(data, &m) // 损坏的映射表按空表处理，孤儿目录清扫兜底
	return m
}

func saveMap(appDir string, m map[string]InstanceMeta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(appDir, mapFileName), append(data, '\n'), 0o600)
}

// metaAlive 判断实例属主是否存活（starttime 校验防 PID 复用）。
func metaAlive(meta InstanceMeta) bool {
	if meta.PID <= 0 {
		return false
	}
	if meta.Start == 0 {
		return syscall.Kill(meta.PID, 0) == nil
	}
	cur, err := procStartTicks(meta.PID)
	return err == nil && cur == meta.Start
}

// pruneLocked 清扫死实例与孤儿目录（调用方必须已持有目录锁）。
// 返回清理的目录数。
func pruneLocked(appDir string) int {
	m := loadMap(appDir)
	n := 0
	for id, meta := range m {
		if !metaAlive(meta) {
			os.RemoveAll(filepath.Join(appDir, id))
			delete(m, id)
			n++
		}
	}
	entries, _ := os.ReadDir(appDir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, ok := m[e.Name()]; !ok {
			os.RemoveAll(filepath.Join(appDir, e.Name()))
			n++
		}
	}
	_ = saveMap(appDir, m)
	return n
}

// Prepare 为一次运行准备实例目录：定位（或创建）该配置的持久化目录，
// 锁内清扫残留，然后生成 instanceID、创建 socket 目录并把
// instanceID -> 本进程 PID 写入映射表。
func Prepare(spec *perm.Permissions) (*Instance, error) {
	return prepareAt(runtimeBase(), spec)
}

func prepareAt(base string, spec *perm.Permissions) (*Instance, error) {
	appDir := filepath.Join(base, flatpakAppName(spec))
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := lockDir(appDir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	pruneLocked(appDir) // 启动前清扫残留的临时目录

	id := newInstanceID()
	dir := filepath.Join(appDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := loadMap(appDir)
	st, _ := procStartTicks(os.Getpid()) // 失败为 0，metaAlive 回退 kill(0)
	m[id] = InstanceMeta{PID: os.Getpid(), Start: st, App: spec.App}
	if err := saveMap(appDir, m); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return &Instance{AppDir: appDir, Dir: dir, ID: id}, nil
}

// Release 注销实例并删除其 socket 目录。持久化配置目录与映射表保留。
// 幂等，可重复调用。
func (i *Instance) Release() {
	if i == nil {
		return
	}
	if unlock, err := lockDir(i.AppDir); err == nil {
		m := loadMap(i.AppDir)
		delete(m, i.ID)
		_ = saveMap(i.AppDir, m)
		unlock()
	}
	os.RemoveAll(i.Dir)
}

// RunningInfo 描述一个运行中的沙箱（ps 输出）。
type RunningInfo struct {
	ID  string
	App string
	PID int
}

// List 枚举所有配置下存活的实例。
func List() []RunningInfo {
	return listAt(runtimeBase())
}

func listAt(base string) []RunningInfo {
	var out []RunningInfo
	apps, err := os.ReadDir(base)
	if err != nil {
		return out
	}
	for _, a := range apps {
		if !a.IsDir() {
			continue
		}
		for id, meta := range loadMap(filepath.Join(base, a.Name())) {
			if !metaAlive(meta) {
				continue
			}
			app := meta.App
			if app == "" {
				app = a.Name()
			}
			out = append(out, RunningInfo{ID: id, App: app, PID: meta.PID})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Kill 终止目标沙箱：向 cwrap 主进程发 SIGTERM（由其转发给沙箱进程组）；
// 宽限 3 秒仍存活则 SIGKILL 主进程——bwrap 带 --die-with-parent，
// 内核 PDEATHSIG 会随主进程退出依序回收 monitor 与沙箱。
// target 可为 instanceID、应用名或持久化目录名（flatpakAppName）。
func Kill(target string) error {
	base := runtimeBase()
	apps, err := os.ReadDir(base)
	if err != nil {
		return fmt.Errorf("未找到运行中的沙箱: %s", target)
	}
	for _, a := range apps {
		if !a.IsDir() {
			continue
		}
		for id, meta := range loadMap(filepath.Join(base, a.Name())) {
			if id != target && meta.App != target && a.Name() != target {
				continue
			}
			if !metaAlive(meta) {
				continue
			}
			if err := syscall.Kill(meta.PID, syscall.SIGTERM); err != nil {
				return fmt.Errorf("向进程 %d 发送 SIGTERM 失败: %w", meta.PID, err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if !metaAlive(meta) {
					return nil
				}
				time.Sleep(100 * time.Millisecond)
			}
			if metaAlive(meta) {
				syscall.Kill(meta.PID, syscall.SIGKILL)
			}
			return nil
		}
	}
	return fmt.Errorf("未找到运行中的沙箱: %s", target)
}

// Clean 清扫所有配置下的陈旧实例目录，返回清理数量。
// 同时兼容清理旧版（daemon 架构）遗留的时间戳目录与 cwrapd socket/日志。
func Clean() int {
	base := runtimeBase()
	apps, err := os.ReadDir(base)
	if err != nil {
		return 0
	}
	n := 0
	for _, a := range apps {
		path := filepath.Join(base, a.Name())
		if !a.IsDir() {
			// 旧版 daemon 残留文件
			if a.Name() == "cwrapd.sock" || a.Name() == "cwrapd.log" {
				os.Remove(path)
			}
			continue
		}
		// 旧版时间戳运行目录（含 .pid 文件）：按旧规则判活清理
		if legacyDir(a.Name()) {
			if cleanLegacy(path) {
				n++
			}
			continue
		}
		unlock, err := lockDir(path)
		if err != nil {
			continue
		}
		n += pruneLocked(path)
		unlock()
	}
	return n
}

// legacyDir 判断是否为旧版纯数字时间戳目录名。
func legacyDir(name string) bool {
	if name == "" {
		return false
	}
	_, err := strconv.ParseUint(name, 10, 64)
	return err == nil
}

// cleanLegacy 清理旧版运行目录：.pid 记录的 daemon 已死则整目录删除。
func cleanLegacy(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, ".pid"))
	if err != nil {
		os.RemoveAll(dir)
		return true
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 || syscall.Kill(pid, 0) != nil {
		os.RemoveAll(dir)
		return true
	}
	return false
}
