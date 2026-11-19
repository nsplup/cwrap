package perm

import (
        "strings"
        "testing"
)

func TestResolveFSPathKeywords(t *testing.T) {
        home := userHome()
        cases := []struct {
                raw  string
                want []string
        }{
                {"home", []string{home}},
                {"~", []string{home}},
                {"~/Documents", []string{home + "/Documents"}},
                {"host-os", []string{"/usr"}},
                {"host-etc", []string{"/etc"}},
        }
        for _, c := range cases {
                got, try, err := ResolveFSPath(c.raw)
                if err != nil {
                        t.Fatalf("%s: %v", c.raw, err)
                }
                if try {
                        t.Fatalf("%s: 不应带 ?", c.raw)
                }
                if strings.Join(got, ",") != strings.Join(c.want, ",") {
                        t.Fatalf("%s: got %v want %v", c.raw, got, c.want)
                }
        }
}

func TestResolveFSPathTrySuffix(t *testing.T) {
        _, try, err := ResolveFSPath("home?")
        if err != nil || !try {
                t.Fatalf("try=%v err=%v", try, err)
        }
}

func TestResolveFSPathHost(t *testing.T) {
        got, _, err := ResolveFSPath("host")
        if err != nil || len(got) < 2 {
                t.Fatalf("host: got %v err %v", got, err)
        }
        banned := map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/usr": true, "/etc": true, "/run": true, "/tmp": true, "/": true}
        for _, p := range got {
                if banned[p] {
                        t.Fatalf("host 不应包含 %s", p)
                }
                if !strings.HasPrefix(p, "/") {
                        t.Fatalf("host 项必须是绝对路径: %s", p)
                }
        }
}

func TestResolveFSPathXdg(t *testing.T) {
        got, _, err := ResolveFSPath("xdg-run/sub")
        if err != nil {
                t.Fatal(err)
        }
        if !strings.HasPrefix(got[0], "/run/user/") && !strings.HasPrefix(got[0], "/tmp/") {
                t.Fatalf("xdg-run 展开异常: %v", got)
        }
}

func TestFSPathValidRejects(t *testing.T) {
        for _, bad := range []string{"/", "", "app", "xdg-unknown"} {
                if err := FSPathValid(bad); err == nil {
                        t.Fatalf("%q 应拒绝", bad)
                }
        }
        if err := FSPathValid("/x?"); err != nil {
                t.Fatalf("/x? 应合法: %v", err)
        }
}

func TestParseTmp(t *testing.T) {
        for _, ok := range []string{"", "sandbox", "tmpfs", "host", "sandbox:/var/tmp", "/opt/data"} {
                if _, err := ParseTmp(ok); err != nil {
                        t.Fatalf("%q 应合法: %v", ok, err)
                }
        }
        for _, bad := range []string{"sandbox:relative", "wrong", "bind:/x"} {
                if _, err := ParseTmp(bad); err == nil {
                        t.Fatalf("%q 应拒绝", bad)
                }
        }
        ts, err := ParseTmp("/opt/data")
        if err != nil || ts.Kind != "bind" || ts.Path != "/opt/data" {
                t.Fatalf("bind 解析异常: %+v %v", ts, err)
        }
}

func TestFilterTmpFSConflicts(t *testing.T) {
        // sandbox 默认：/tmp 本身冲突，/tmp 子路径保留
        p := Default()
        p.FS = []string{"rw:/tmp", "ro:/tmp/sub", "rw:/opt"}
        fs, warns := FilterTmpFSConflicts(p)
        if len(fs) != 2 || fs[0] != "ro:/tmp/sub" || fs[1] != "rw:/opt" {
                t.Fatalf("过滤结果异常: %v", fs)
        }
        if len(warns) != 1 {
                t.Fatalf("应有一条警告: %v", warns)
        }

        // host：/tmp 子路径也冲突
        p2 := Default()
        p2.Tmp = "host"
        p2.FS = []string{"ro:/tmp/.X11-unix", "rw:/opt"}
        fs2, warns2 := FilterTmpFSConflicts(p2)
        if len(fs2) != 1 || fs2[0] != "rw:/opt" {
                t.Fatalf("host 过滤结果异常: %v", fs2)
        }
        if len(warns2) != 1 {
                t.Fatalf("host 应有一条警告: %v", warns2)
        }

        // tmpfs：子路径保留
        p3 := Default()
        p3.Tmp = "tmpfs"
        p3.FS = []string{"rw:/tmp/data"}
        fs3, _ := FilterTmpFSConflicts(p3)
        if len(fs3) != 1 {
                t.Fatalf("tmpfs 不应过滤子路径: %v", fs3)
        }

        // bind 自定义为宿主 /tmp：等同 host
        p4 := Default()
        p4.Tmp = "/tmp"
        p4.FS = []string{"ro:/tmp/x"}
        fs4, warns4 := FilterTmpFSConflicts(p4)
        if len(fs4) != 0 || len(warns4) != 1 {
                t.Fatalf("bind:/tmp 应过滤子路径: %v %v", fs4, warns4)
        }
}

func TestParseFSKeyword(t *testing.T) {
        mode, path, err := ParseFS("ro:xdg-download?")
        if err != nil || mode != "ro" || path != "xdg-download?" {
                t.Fatalf("ParseFS 关键字失败: %s %s %v", mode, path, err)
        }
        if _, _, err := ParseFS("rw:host"); err != nil {
                t.Fatalf("rw:host 应合法: %v", err)
        }
        if _, _, err := ParseFS("rw:/"); err == nil {
                t.Fatal("rw:/ 应拒绝")
        }
}
