// Package ipc 定义 CLI <-> cwrapd 的 Unix socket 协议。
//
// 帧格式：
//  1. run 请求：客户端先通过 SCM_RIGHTS 传递 3 个 stdio FD（每个 1 字节载荷），
//     随后发送一行 JSON Request。会话中途可发送 {"cmd":"signal","sig":N} 行。
//  2. 服务端先回一行 JSON Event（{"event":"started",...}），运行结束时
//     回一行 JSON Response 后关闭连接。
//  3. ps/kill 请求直接回一行 JSON Response。
package ipc

import (
        "bufio"
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "os"

        "golang.org/x/sys/unix"

        "cwrap/internal/perm"
)

// Request 是 CLI 发给 daemon 的请求。
type Request struct {
        Cmd    string             `json:"cmd"` // run | ps | kill
        Spec   *perm.Permissions  `json:"spec,omitempty"`
        Argv   []string           `json:"argv,omitempty"` // run: [cmdPath, args...]
        Target string             `json:"target,omitempty"` // kill: id 或 app 名
}

// SignalMsg 是会话中途的信号转发消息。
type SignalMsg struct {
        Cmd string `json:"cmd"` // 固定 "signal"
        Sig int    `json:"sig"`
}

// Event 是 daemon 在运行开始时回发的事件（tcsetpgrp 用）。
type Event struct {
        Event string `json:"event"` // started
        ID    string `json:"id"`
        App   string `json:"app"`
        PGID  int    `json:"pgid"`
}

// Response 是 daemon 的最终应答。
type Response struct {
        Ok       bool      `json:"ok"`
        Error    string    `json:"error,omitempty"`
        ExitCode int       `json:"exit_code,omitempty"`
        Runs     []RunInfo `json:"runs,omitempty"` // ps
}

// RunInfo 描述一个运行中的沙箱。
type RunInfo struct {
        ID  string `json:"id"`
        App string `json:"app"`
}

// SocketPath 返回 daemon socket 路径（$XDG_RUNTIME_DIR/cwrap/cwrapd.sock）。
func SocketPath() (string, error) {
        rt := os.Getenv("XDG_RUNTIME_DIR")
        if rt == "" {
                return "", fmt.Errorf("XDG_RUNTIME_DIR 未设置")
        }
        return rt + "/cwrap/cwrapd.sock", nil
}

// SendFDs 通过 SCM_RIGHTS 发送 stdio FD（逐个发送，避免控制消息拼接歧义）。
func SendFDs(conn *net.UnixConn, fds []int) error {
        for _, fd := range fds {
                r := unix.UnixRights(fd)
                if _, _, err := conn.WriteMsgUnix([]byte{0}, r, nil); err != nil {
                        return fmt.Errorf("发送 FD: %w", err)
                }
        }
        return nil
}

// RecvFDs 接收 n 个 FD；返回收到的 *os.File 列表与流中残余字节。
func RecvFDs(conn *net.UnixConn, n int) ([]*os.File, []byte, error) {
        var files []*os.File
        var leftover []byte
        for len(files) < n {
                buf := make([]byte, 4096)
                oob := make([]byte, 4096)
                nr, noob, _, _, err := conn.ReadMsgUnix(buf, oob)
                if err != nil {
                        return nil, nil, fmt.Errorf("接收 FD: %w", err)
                }
                if noob > 0 {
                        scms, err := unix.ParseSocketControlMessage(oob[:noob])
                        if err != nil {
                                return nil, nil, err
                        }
                        for _, scm := range scms {
                                fds, err := unix.ParseUnixRights(&scm)
                                if err != nil {
                                        return nil, nil, err
                                }
                                for _, fd := range fds {
                                        files = append(files, os.NewFile(uintptr(fd), "stdio"))
                                }
                        }
                }
                if nr > 1 {
                        // 每条 FD 消息的载荷为 1 字节标记，跳过后再拼回残余流
                        leftover = append(leftover, buf[1:nr]...)
                }
                if nr == 0 && noob == 0 {
                        return nil, nil, fmt.Errorf("连接在对齐 FD 前关闭")
                }
        }
        return files, leftover, nil
}

// WriteJSON 向 writer 写一行 JSON。
func WriteJSON(w io.Writer, v any) error {
        b, err := json.Marshal(v)
        if err != nil {
                return err
        }
        _, err = w.Write(append(b, '\n'))
        return err
}

// ReadJSON 从 bufio 读取一行 JSON。
func ReadJSON(r *bufio.Reader, v any) error {
        line, err := r.ReadBytes('\n')
        if err != nil {
                return err
        }
        line = bytes.TrimSpace(line)
        if len(line) == 0 {
                return io.ErrUnexpectedEOF
        }
        return json.Unmarshal(line, v)
}
