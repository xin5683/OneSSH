package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/joho/godotenv"
)

// loadDotEnv 依次查找当前目录和可执行文件目录的 .env。
// 真实环境变量始终优先，避免容器或服务管理器注入的配置被文件意外覆盖。
func loadDotEnv() {
	paths := dotEnvCandidatePaths()
	if !loadDotEnvFromPaths(paths) {
		log.Printf("未找到 .env（已检查: %s）", strings.Join(paths, ", "))
	}
}

func dotEnvCandidatePaths() []string {
	if explicit := strings.TrimSpace(os.Getenv("ONESSH_ENV_FILE")); explicit != "" {
		return []string{explicit}
	}

	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, ".env"))
	} else {
		log.Printf("读取当前工作目录失败: %v", err)
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), ".env"))
	} else {
		log.Printf("解析可执行文件路径失败: %v", err)
	}

	seen := make(map[string]bool, len(candidates))
	unique := candidates[:0]
	for _, path := range candidates {
		key := filepath.Clean(path)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, path)
	}
	return unique
}

func loadDotEnvFromPaths(paths []string) bool {
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Printf("检查 .env 失败 %s: %v", path, err)
			continue
		}
		if info.IsDir() {
			log.Printf("忽略作为目录存在的 .env: %s", path)
			continue
		}
		applied, skipped, err := applyDotEnvFile(path)
		if err != nil {
			log.Printf("忽略无法解析的 .env %s: %v", path, err)
			return true
		}
		if len(skipped) == 0 {
			log.Printf("已加载 .env: %s（应用 %d 项）", path, applied)
		} else {
			log.Printf("已加载 .env: %s（应用 %d 项；已有环境变量优先: %s）",
				path, applied, strings.Join(skipped, ", "))
		}
		return true
	}
	return false
}

func applyDotEnvFile(path string) (applied int, skipped []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}
	data, err = normalizeDotEnvText(data)
	if err != nil {
		return 0, nil, err
	}
	values, err := godotenv.Unmarshal(string(data))
	if err != nil {
		return 0, nil, err
	}
	for key, value := range values {
		if _, exists := os.LookupEnv(key); exists {
			skipped = append(skipped, key)
			continue
		}
		if err = os.Setenv(key, value); err != nil {
			return 0, nil, fmt.Errorf("设置 %s: %w", key, err)
		}
		applied++
	}
	sort.Strings(skipped)
	return applied, skipped, nil
}

// Windows 编辑器常给文本文件加 BOM；godotenv 不识别 BOM，会把它当作变量名的一部分。
func normalizeDotEnvText(data []byte) ([]byte, error) {
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		data = data[3:]
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		var err error
		data, err = decodeUTF16(data[2:], false)
		if err != nil {
			return nil, err
		}
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		var err error
		data, err = decodeUTF16(data[2:], true)
		if err != nil {
			return nil, err
		}
	}
	if !utf8.Valid(data) {
		return nil, errors.New("文件不是有效的 UTF-8 或带 BOM 的 UTF-16 文本")
	}
	return data, nil
}

func decodeUTF16(data []byte, bigEndian bool) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, errors.New("UTF-16 文件长度为奇数")
	}
	codeUnits := make([]uint16, len(data)/2)
	for i := range codeUnits {
		if bigEndian {
			codeUnits[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
		} else {
			codeUnits[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
		}
	}
	return []byte(string(utf16.Decode(codeUnits))), nil
}
