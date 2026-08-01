package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
)

var errA9TopicKeySource = errors.New(
	"a9 topic key source invalid",
)

const maxA9TopicKeySourceBytes int64 = 64 * 1024

// loadA9TopicKeySet transfers ownership of the file buffer directly into the
// trust parser. No immutable string containing a TOPIC secret is created.
func loadA9TopicKeySet(
	path string,
	environment string,
) (*a9trust.TopicKeySet, error) {
	raw, err := readA9TopicKeySource(path)
	if err != nil {
		return nil, errA9TopicKeySource
	}
	// ParseTopicKeySetBytes consumes and clears raw on every return path. The
	// additional defer keeps ownership unambiguous if that contract changes.
	defer clear(raw)
	set, err := a9trust.ParseTopicKeySetBytes(raw, environment)
	if err != nil {
		return nil, errA9TopicKeySource
	}
	return set, nil
}

func readA9TopicKeySource(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errA9TopicKeySource
	}
	before, err := os.Lstat(path)
	if err != nil || !validA9TopicKeyFileInfo(before) {
		return nil, errA9TopicKeySource
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errA9TopicKeySource
	}
	opened, err := file.Stat()
	if err != nil ||
		!validA9TopicKeyFileInfo(opened) ||
		!os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errA9TopicKeySource
	}
	afterOpen, err := os.Lstat(path)
	if err != nil ||
		!validA9TopicKeyFileInfo(afterOpen) ||
		!os.SameFile(opened, afterOpen) ||
		afterOpen.Size() != opened.Size() {
		_ = file.Close()
		return nil, errA9TopicKeySource
	}

	raw, err := io.ReadAll(io.LimitReader(
		file,
		maxA9TopicKeySourceBytes+1,
	))
	if err != nil {
		clear(raw)
		_ = file.Close()
		return nil, errA9TopicKeySource
	}
	finalOpened, statErr := file.Stat()
	afterRead, pathErr := os.Lstat(path)
	closeErr := file.Close()
	if statErr != nil ||
		pathErr != nil ||
		closeErr != nil ||
		!validA9TopicKeyFileInfo(finalOpened) ||
		!validA9TopicKeyFileInfo(afterRead) ||
		!os.SameFile(opened, finalOpened) ||
		!os.SameFile(finalOpened, afterRead) ||
		finalOpened.Size() != opened.Size() ||
		afterRead.Size() != opened.Size() ||
		int64(len(raw)) != opened.Size() {
		clear(raw)
		return nil, errA9TopicKeySource
	}
	return raw, nil
}

func validA9TopicKeyFileInfo(info os.FileInfo) bool {
	if info == nil ||
		!info.Mode().IsRegular() ||
		info.Size() < 1 ||
		info.Size() > maxA9TopicKeySourceBytes ||
		info.Mode()&(os.ModeSymlink|
			os.ModeSetuid|
			os.ModeSetgid|
			os.ModeSticky) != 0 {
		return false
	}
	permissions := info.Mode().Perm()
	return permissions&0o400 != 0 &&
		permissions&0o111 == 0 &&
		permissions&0o077 == 0
}
