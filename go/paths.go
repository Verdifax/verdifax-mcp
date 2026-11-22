package verdifaxmcp

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Every file a tool reads must stay inside the working folder. A path is
// relative, never holds a .. segment, and after symbolic links are followed
// it must still be a regular file inside the folder.

var (
	driveLetter = regexp.MustCompile(`^[A-Za-z]:`)
	separators  = regexp.MustCompile(`[\\/]`)
)

func resolveInWorkdir(workdir, relative, field string) (string, error) {
	if workdir == "" {
		return "", toolErr("VERDIFAX_MCP_WORKDIR is not set, so this server reads no files")
	}
	if strings.ContainsRune(relative, 0) {
		return "", toolErr(field + " holds a zero byte")
	}
	if filepath.IsAbs(relative) || strings.HasPrefix(relative, "/") || strings.HasPrefix(relative, `\`) || driveLetter.MatchString(relative) {
		return "", toolErr(field + " must be a path relative to the working folder")
	}
	for _, segment := range separators.Split(relative, -1) {
		if segment == ".." {
			return "", toolErr(field + " must not hold a .. segment")
		}
	}
	real, realErr := filepath.EvalSymlinks(filepath.Join(workdir, relative))
	if realErr != nil {
		return "", toolErr(field + " names no file in the working folder")
	}
	prefix := workdir
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if real != workdir && !strings.HasPrefix(real, prefix) {
		return "", toolErr(field + " leads outside the working folder")
	}
	if info, statErr := os.Stat(real); statErr != nil || !info.Mode().IsRegular() {
		return "", toolErr(field + " is not a regular file")
	}
	return real, nil
}
