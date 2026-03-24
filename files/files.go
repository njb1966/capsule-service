package files

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Manager struct {
	capsuleRoot          string
	maxFileSizeBytes     int64
	maxTotalStorageBytes int64
	maxFilesPerUser      int
}

func New(capsuleRoot string, maxFileSize, maxTotalStorage int64, maxFiles int) *Manager {
	return &Manager{
		capsuleRoot:          capsuleRoot,
		maxFileSizeBytes:     maxFileSize,
		maxTotalStorageBytes: maxTotalStorage,
		maxFilesPerUser:      maxFiles,
	}
}

// userRoot returns the capsule directory for a user and verifies it exists.
func (m *Manager) userRoot(username string) string {
	return filepath.Join(m.capsuleRoot, username+".gemcities.com")
}

// safePath resolves a user-supplied path and verifies it stays within the user's capsule.
// This is the critical path traversal protection function.
func (m *Manager) safePath(username, relPath string) (string, error) {
	root := m.userRoot(username)
	// Clean and join, then resolve symlinks to catch traversal via symlinks
	joined := filepath.Join(root, filepath.Clean("/"+relPath))
	resolved, err := filepath.EvalSymlinks(filepath.Dir(joined))
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("invalid path")
	}
	// For new files the dir may not exist yet; use the joined path directly
	if os.IsNotExist(err) {
		resolved = filepath.Dir(joined)
	}
	full := filepath.Join(resolved, filepath.Base(joined))
	if !strings.HasPrefix(full+string(filepath.Separator), root+string(filepath.Separator)) {
		return "", fmt.Errorf("path outside capsule")
	}
	return full, nil
}

type FileInfo struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
}

func (m *Manager) List(username, relPath string) ([]FileInfo, error) {
	dir, err := m.safePath(username, relPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	result := make([]FileInfo, 0, len(entries))
	for _, e := range entries {
		info, _ := e.Info()
		var size int64
		if info != nil {
			size = info.Size()
		}
		result = append(result, FileInfo{Name: e.Name(), IsDir: e.IsDir(), Size: size})
	}
	return result, nil
}

func (m *Manager) Read(username, relPath string) ([]byte, error) {
	p, err := m.safePath(username, relPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (m *Manager) Write(username, relPath string, data []byte, currentStorageBytes int64) (int64, error) {
	if int64(len(data)) > m.maxFileSizeBytes {
		return 0, fmt.Errorf("file exceeds size limit")
	}

	p, err := m.safePath(username, relPath)
	if err != nil {
		return 0, err
	}

	// Calculate storage impact (subtract old file size if replacing)
	var oldSize int64
	if info, err := os.Stat(p); err == nil {
		oldSize = info.Size()
	}
	newTotal := currentStorageBytes - oldSize + int64(len(data))
	if newTotal > m.maxTotalStorageBytes {
		return 0, fmt.Errorf("storage limit exceeded")
	}

	// Count files only for new files
	if _, err := os.Stat(p); os.IsNotExist(err) {
		count, err := m.countFiles(username)
		if err != nil {
			return 0, err
		}
		if count >= m.maxFilesPerUser {
			return 0, fmt.Errorf("file count limit exceeded")
		}
	}

	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		return 0, err
	}
	// Return new storage total
	return newTotal, nil
}

func (m *Manager) Delete(username, relPath string, currentStorageBytes int64) (int64, error) {
	p, err := m.safePath(username, relPath)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	var freed int64
	if info.IsDir() {
		freed = dirSize(p)
		err = os.RemoveAll(p)
	} else {
		freed = info.Size()
		err = os.Remove(p)
	}
	if err != nil {
		return 0, err
	}
	return currentStorageBytes - freed, nil
}

func (m *Manager) Rename(username, oldPath, newPath string) error {
	src, err := m.safePath(username, oldPath)
	if err != nil {
		return err
	}
	dst, err := m.safePath(username, newPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

func (m *Manager) Mkdir(username, relPath string) error {
	p, err := m.safePath(username, relPath)
	if err != nil {
		return err
	}
	return os.MkdirAll(p, 0755)
}

func (m *Manager) Export(username string, w io.Writer) error {
	root := m.userRoot(username)
	zw := zip.NewWriter(w)
	defer zw.Close()
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		f, err := zw.Create(rel)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	})
}

func (m *Manager) InitCapsule(username string) error {
	root := m.userRoot(username)
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	indexPath := filepath.Join(root, "index.gmi")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		content := fmt.Sprintf("# %s's Capsule\n\nWelcome to my Gemini capsule!\n", username)
		return os.WriteFile(indexPath, []byte(content), 0644)
	}
	return nil
}

func (m *Manager) DeleteAll(username string) error {
	return os.RemoveAll(m.userRoot(username))
}

func (m *Manager) countFiles(username string) (int, error) {
	root := m.userRoot(username)
	count := 0
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}

func dirSize(path string) int64 {
	var total int64
	filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}
