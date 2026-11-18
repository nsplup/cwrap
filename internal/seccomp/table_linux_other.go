//go:build linux && !amd64

package seccomp

// num 在非 amd64 构建上返回未命中。
// 黑名单等级（low/medium）在多数架构上仍可工作，
// 但其中个别名称缺失时会被跳过；high（白名单）暂只支持 amd64 构建。
func num(name string) (uint32, bool) { return 0, false }

func auditArch() (uint32, bool) { return 0, false }
