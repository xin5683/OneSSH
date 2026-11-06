package main

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

// 用独立的变量名前缀,避免与真实 ONESSH_* 配置或其他用例互相干扰。
const dotenvTestPrefix = "ONESSH_DOTENV_TEST_"

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()
	content := "# 注释行\n" +
		"ONESSH_DOTENV_TEST_FROM_FILE=from-file\n" +
		"export ONESSH_DOTENV_TEST_EXISTING=from-file\n" +
		"ONESSH_DOTENV_TEST_QUOTED=\"a quoted value\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(dotenvTestPrefix+"EXISTING", "from-env")
	t.Chdir(dir)
	loadDotEnv()
	t.Cleanup(func() {
		for _, name := range []string{"FROM_FILE", "QUOTED"} {
			os.Unsetenv(dotenvTestPrefix + name)
		}
	})

	if got := os.Getenv(dotenvTestPrefix + "FROM_FILE"); got != "from-file" {
		t.Errorf(".env 中的变量未生效: %sFROM_FILE = %q, 期望 \"from-file\"", dotenvTestPrefix, got)
	}
	if got := os.Getenv(dotenvTestPrefix + "EXISTING"); got != "from-env" {
		t.Errorf("已有环境变量被 .env 覆盖: %sEXISTING = %q, 期望 \"from-env\"", dotenvTestPrefix, got)
	}
	if got := os.Getenv(dotenvTestPrefix + "QUOTED"); got != "a quoted value" {
		t.Errorf("带引号的值解析错误: %sQUOTED = %q, 期望 \"a quoted value\"", dotenvTestPrefix, got)
	}
}

func TestLoadDotEnvMissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	loadDotEnv()

	if got := os.Getenv(dotenvTestPrefix + "MISSING"); got != "" {
		t.Errorf("无 .env 时不应读到任何值: %sMISSING = %q", dotenvTestPrefix, got)
	}
}

func TestLoadDotEnvBrokenFile(t *testing.T) {
	dir := t.TempDir()
	// 未闭合的引号,godotenv 会返回解析错误
	content := "ONESSH_DOTENV_TEST_BROKEN=\"unterminated\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	loadDotEnv() // 期望只告警,不 panic、不 Fatal

	if got := os.Getenv(dotenvTestPrefix + "BROKEN"); got != "" {
		t.Errorf("解析失败的 .env 不应设置任何变量: %sBROKEN = %q", dotenvTestPrefix, got)
	}
}

func TestLoadDotEnvFallsBackToExecutableDirectory(t *testing.T) {
	cwd := t.TempDir()
	executableDir := t.TempDir()
	name := dotenvTestPrefix + "EXE_DIR"
	content := []byte(name + "=from-exe-dir\n")
	if err := os.WriteFile(filepath.Join(executableDir, ".env"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Unsetenv(name) })

	if !loadDotEnvFromPaths([]string{filepath.Join(cwd, ".env"), filepath.Join(executableDir, ".env")}) {
		t.Fatal("未找到可执行文件目录中的 .env")
	}
	if got := os.Getenv(name); got != "from-exe-dir" {
		t.Fatalf("%s = %q, 期望 \"from-exe-dir\"", name, got)
	}
}

func TestLoadDotEnvSupportsUTF8AndUTF16BOM(t *testing.T) {
	name := dotenvTestPrefix + "BOM"
	t.Cleanup(func() { os.Unsetenv(name) })

	tests := map[string]struct {
		content []byte
		want    string
	}{
		"utf8": {
			content: append([]byte{0xEF, 0xBB, 0xBF}, []byte(name+"=utf8\n")...),
			want:    "utf8",
		},
	}
	utf16LE := []byte{0xFF, 0xFE}
	for _, unit := range utf16.Encode([]rune(name + "=utf16\n")) {
		utf16LE = append(utf16LE, byte(unit), byte(unit>>8))
	}
	tests["utf16le"] = struct {
		content []byte
		want    string
	}{content: utf16LE, want: "utf16"}

	for label, tt := range tests {
		t.Run(label, func(t *testing.T) {
			os.Unsetenv(name)
			dir := t.TempDir()
			path := filepath.Join(dir, ".env")
			if err := os.WriteFile(path, tt.content, 0o600); err != nil {
				t.Fatal(err)
			}
			loadDotEnvFromPaths([]string{path})
			if got := os.Getenv(name); got != tt.want {
				t.Fatalf("%s = %q, 期望 %q", name, got, tt.want)
			}
		})
	}
}
