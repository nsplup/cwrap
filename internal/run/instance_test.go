package run

import (
	"os"
	"path/filepath"
	"testing"

	"cwrap/internal/perm"
)

// deadMeta 构造一个必然判死的属主（PID 超出内核 pid_max，/proc 不存在）。
func deadMeta(app string) InstanceMeta {
	return InstanceMeta{PID: 999999999, Start: 1, App: app}
}

// 持久化目录名与 flatpakAppName 一致；socket 目录名为 instanceID；
// 映射表记录 instanceID -> 本进程 PID。
func TestPrepareLayoutAndMapping(t *testing.T) {
	base := t.TempDir()
	spec := perm.Default()
	spec.App = "demo"

	inst, err := prepareAt(base, spec)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(inst.AppDir) != flatpakAppName(spec) {
		t.Fatalf("持久化目录名应为 flatpakAppName: %s", inst.AppDir)
	}
	if filepath.Base(inst.Dir) != inst.ID || filepath.Dir(inst.Dir) != inst.AppDir {
		t.Fatalf("socket 目录应为 AppDir/<instanceID>: %s", inst.Dir)
	}
	if len(inst.ID) != 32 {
		t.Fatalf("instanceID 应为 32 位 hex: %s", inst.ID)
	}
	m := loadMap(inst.AppDir)
	meta, ok := m[inst.ID]
	if !ok {
		t.Fatal("映射表缺少本实例条目")
	}
	if meta.PID != os.Getpid() {
		t.Fatalf("映射表 PID 应为主进程 PID: %d", meta.PID)
	}
	if !metaAlive(meta) {
		t.Fatal("本进程应判活")
	}

	inst.Release()
	if _, err := os.Stat(inst.Dir); !os.IsNotExist(err) {
		t.Fatal("Release 后实例目录应被删除")
	}
	if _, ok := loadMap(inst.AppDir)[inst.ID]; ok {
		t.Fatal("Release 后映射表条目应被注销")
	}
	if _, err := os.Stat(inst.AppDir); err != nil {
		t.Fatal("持久化配置目录应保留")
	}
}

// 启动前清扫：死 PID 的实例目录、表外孤儿目录都应被清理；
// 存活实例（本进程）不受影响。
func TestPrepareSweepsStale(t *testing.T) {
	base := t.TempDir()
	spec := perm.Default()
	spec.App = "demo"

	// 先建立一个存活实例（模拟同配置的并发运行）
	live, err := prepareAt(base, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Release()

	// 伪造残留：死 PID 条目 + 目录；孤儿目录（不在映射表）
	m := loadMap(live.AppDir)
	m["dead0000000000000000000000000000"] = deadMeta("demo")
	if err := saveMap(live.AppDir, m); err != nil {
		t.Fatal(err)
	}
	staleDir := filepath.Join(live.AppDir, "dead0000000000000000000000000000")
	orphanDir := filepath.Join(live.AppDir, "orphan00000000000000000000000000")
	for _, d := range []string{staleDir, orphanDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "session"), nil, 0o600)
	}

	inst, err := prepareAt(base, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Release()

	for _, d := range []string{staleDir, orphanDir} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("残留目录应被清扫: %s", d)
		}
	}
	if _, ok := loadMap(live.AppDir)["dead0000000000000000000000000000"]; ok {
		t.Fatal("死实例的映射表条目应被移除")
	}
	if _, err := os.Stat(live.Dir); err != nil {
		t.Fatal("存活实例目录不应被误删")
	}
}

// PID 复用防护：PID 存活但 starttime 不符 => 判死。
func TestMetaAliveStartTicksMismatch(t *testing.T) {
	st, err := procStartTicks(os.Getpid())
	if err != nil {
		t.Skip("无法读取 /proc starttime")
	}
	if metaAlive(InstanceMeta{PID: os.Getpid(), Start: st + 1}) {
		t.Fatal("starttime 不符应判死（PID 复用）")
	}
	if !metaAlive(InstanceMeta{PID: os.Getpid(), Start: st}) {
		t.Fatal("starttime 相符应判活")
	}
}

// 无应用名时回退 org.cwrap.Sandbox 目录。
func TestPrepareNoAppFallback(t *testing.T) {
	base := t.TempDir()
	inst, err := prepareAt(base, perm.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Release()
	if filepath.Base(inst.AppDir) != "org.cwrap.Sandbox" {
		t.Fatalf("无应用名应回退 org.cwrap.Sandbox: %s", inst.AppDir)
	}
}

// List 只返回存活实例。
func TestListFiltersDead(t *testing.T) {
	base := t.TempDir()
	spec := perm.Default()
	spec.App = "demo"
	inst, err := prepareAt(base, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Release()

	m := loadMap(inst.AppDir)
	m["dead0000000000000000000000000000"] = deadMeta("demo")
	saveMap(inst.AppDir, m)

	runs := listAt(base)
	if len(runs) != 1 || runs[0].ID != inst.ID || runs[0].App != "demo" {
		t.Fatalf("List 应只含存活实例: %+v", runs)
	}
}
