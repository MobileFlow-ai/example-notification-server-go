package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"golang.org/x/sys/unix"
)

const (
	a9MaterialMaxBytes      = 1024 * 1024
	a9MaterialFailureOutput = "a9_material=fail\n"
	a9ProvisionPassOutput   = "a9_material_provision=pass\n"
	a9PreflightPassOutput   = "a9_material_preflight=pass\n"

	a9TopicCommitmentKeysMaterial = "topic-commitment-keys"
	a9TLSCertificateMaterial      = "tls-certificate"
	a9TLSPrivateKeyMaterial       = "tls-private-key"

	a9TopicCommitmentKeysVariable = "BRIDGE_A9_TOPIC_COMMITMENT_KEYS_FILE_PATH"
	a9TLSCertificateVariable      = "BRIDGE_A9_TLS_CERTIFICATE_FILE_PATH"
	a9TLSPrivateKeyVariable       = "BRIDGE_A9_TLS_PRIVATE_KEY_FILE_PATH"

	a9RailwayMaterialDirectory  = "/var/lib/notifications-server/a9"
	a9RailwayTopicKeysPath      = a9RailwayMaterialDirectory + "/topic-commitment-keys.json"
	a9RailwayTLSCertificatePath = a9RailwayMaterialDirectory + "/tls-certificate.pem"
	a9RailwayTLSPrivateKeyPath  = a9RailwayMaterialDirectory + "/tls-private-key.pem"
)

var errA9MaterialRejected = errors.New("a9 material rejected")

type a9MaterialTarget struct {
	path         string
	variableName string
	maxBytes     int64
}

type a9RuntimeFileKind uint8

const (
	a9RuntimeTopicKeys a9RuntimeFileKind = iota
	a9RuntimeTLSCertificate
	a9RuntimeTLSPrivateKey
)

const (
	a9MaterialHookProvisionParentOpened = "provision_parent_opened"
	a9MaterialHookProvisionFileOpened   = "provision_file_opened"
	a9MaterialHookProvisionFileSynced   = "provision_file_synced"
	a9MaterialHookPreflightFileOpened   = "preflight_file_opened"
)

// a9MaterialTestHook is nil in production. Tests use it to deterministically
// exercise path replacement windows without weakening the filesystem API.
var a9MaterialTestHook func(string)

type a9MaterialRoot struct {
	directory  *os.File
	path       string
	name       string
	parentInfo os.FileInfo
}

type provisionedA9File struct {
	materialRoot *a9MaterialRoot
	file         *os.File
	info         os.FileInfo
	maxBytes     int64
}

type checkedA9RuntimeFile struct {
	materialRoot *a9MaterialRoot
	file         *os.File
	info         os.FileInfo
	kind         a9RuntimeFileKind
	maxBytes     int64
}

type checkedA9RuntimeFiles struct {
	files []*checkedA9RuntimeFile
}

func runA9MaterialMode(
	config options.Options,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) bool {
	if stdin == nil || stdout == nil || stderr == nil ||
		!a9MaterialModeValid(config) {
		writeA9MaterialFailure(stderr)
		return false
	}

	if config.PreflightA9RuntimeFiles {
		if !a9RuntimeConfigurationValid(config) {
			writeA9MaterialFailure(stderr)
			return false
		}
		files, valid := openA9RuntimeFiles(config)
		if !valid {
			writeA9MaterialFailure(stderr)
			return false
		}
		if !files.current() || !files.closeChecked() {
			files.close()
			writeA9MaterialFailure(stderr)
			return false
		}
		if _, err := io.WriteString(
			stdout,
			a9PreflightPassOutput+
				a9TopicCommitmentKeysVariable+"\n"+
				a9TLSCertificateVariable+"\n"+
				a9TLSPrivateKeyVariable+"\n",
		); err != nil {
			writeA9MaterialFailure(stderr)
			return false
		}
		return true
	}

	target, valid := configuredA9MaterialTarget(config)
	if !valid {
		writeA9MaterialFailure(stderr)
		return false
	}
	provisioned, err := provisionRestrictedA9File(
		stdin,
		target.path,
		target.maxBytes,
	)
	if err != nil {
		writeA9MaterialFailure(stderr)
		return false
	}
	if !provisioned.current() || !provisioned.closeChecked() {
		provisioned.close()
		writeA9MaterialFailure(stderr)
		return false
	}
	if _, err := fmt.Fprintf(
		stdout,
		"%s%s\n",
		a9ProvisionPassOutput,
		target.variableName,
	); err != nil {
		writeA9MaterialFailure(stderr)
		return false
	}
	return true
}

func a9MaterialModeValid(config options.Options) bool {
	if config.CreateMigration != "" ||
		config.MigrateOnly ||
		config.PreflightLegacyRetirement {
		return false
	}
	if config.PreflightA9RuntimeFiles {
		return config.ProvisionA9Material == ""
	}
	return config.ProvisionA9Material != ""
}

func configuredA9MaterialTarget(
	config options.Options,
) (a9MaterialTarget, bool) {
	switch config.ProvisionA9Material {
	case a9TopicCommitmentKeysMaterial:
		return checkedA9MaterialTarget(
			config.A9.TopicCommitmentKeysFilePath,
			a9TopicCommitmentKeysVariable,
			maxA9TopicKeySourceBytes,
		)
	case a9TLSCertificateMaterial:
		return checkedA9MaterialTarget(
			config.A9.TLSCertificateFilePath,
			a9TLSCertificateVariable,
			a9MaterialMaxBytes,
		)
	case a9TLSPrivateKeyMaterial:
		return checkedA9MaterialTarget(
			config.A9.TLSPrivateKeyFilePath,
			a9TLSPrivateKeyVariable,
			a9MaterialMaxBytes,
		)
	default:
		return a9MaterialTarget{}, false
	}
}

func checkedA9MaterialTarget(
	path string,
	variableName string,
	maxBytes int64,
) (a9MaterialTarget, bool) {
	if !a9MaterialPathValid(path) || variableName == "" || maxBytes < 1 {
		return a9MaterialTarget{}, false
	}
	if railwayDeploymentDetected() {
		expectedPath, valid := railwayA9MaterialPath(variableName)
		if !valid || path != expectedPath {
			return a9MaterialTarget{}, false
		}
	}
	return a9MaterialTarget{
		path:         path,
		variableName: variableName,
		maxBytes:     maxBytes,
	}, true
}

func railwayDeploymentDetected() bool {
	return os.Getenv("RAILWAY_PROJECT_ID") != "" ||
		os.Getenv("RAILWAY_ENVIRONMENT_ID") != "" ||
		os.Getenv("RAILWAY_SERVICE_ID") != ""
}

func railwayA9MaterialPath(variableName string) (string, bool) {
	switch variableName {
	case a9TopicCommitmentKeysVariable:
		return a9RailwayTopicKeysPath, true
	case a9TLSCertificateVariable:
		return a9RailwayTLSCertificatePath, true
	case a9TLSPrivateKeyVariable:
		return a9RailwayTLSPrivateKeyPath, true
	default:
		return "", false
	}
}

func railwayA9RuntimePathsValid(config options.A9Options) bool {
	return !railwayDeploymentDetected() ||
		config.TopicCommitmentKeysFilePath == a9RailwayTopicKeysPath &&
			config.TLSCertificateFilePath == a9RailwayTLSCertificatePath &&
			config.TLSPrivateKeyFilePath == a9RailwayTLSPrivateKeyPath
}

func provisionRestrictedA9File(
	stdin io.Reader,
	path string,
	maxBytes int64,
) (*provisionedA9File, error) {
	if stdin == nil || !a9MaterialPathValid(path) || maxBytes < 1 {
		return nil, errA9MaterialRejected
	}
	materialRoot, err := openA9MaterialRoot(path)
	if err != nil {
		return nil, errA9MaterialRejected
	}
	rootOwned := true
	defer func() {
		if rootOwned {
			_ = materialRoot.directory.Close()
		}
	}()
	callA9MaterialTestHook(a9MaterialHookProvisionParentOpened)
	if _, err = statA9MaterialFile(materialRoot); err == nil {
		return nil, errA9MaterialRejected
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, errA9MaterialRejected
	}

	material, err := io.ReadAll(io.LimitReader(stdin, maxBytes+1))
	defer func() {
		for index := range material {
			material[index] = 0
		}
	}()
	if err != nil || len(material) == 0 || int64(len(material)) > maxBytes {
		return nil, errA9MaterialRejected
	}

	file, err := openA9MaterialFile(
		materialRoot,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL,
		0o600,
	)
	if err != nil {
		return nil, errA9MaterialRejected
	}
	fileOwned := true
	defer func() {
		if fileOwned {
			_ = file.Close()
		}
	}()
	callA9MaterialTestHook(a9MaterialHookProvisionFileOpened)

	if err = file.Chmod(0o600); err == nil {
		var written int
		written, err = file.Write(material)
		if err == nil && written != len(material) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = file.Sync()
	}
	callA9MaterialTestHook(a9MaterialHookProvisionFileSynced)
	openedInfo, statErr := file.Stat()
	pathRawInfo, pathRawStatErr := statA9MaterialFile(materialRoot)
	pathFile, pathOpenErr := openA9MaterialFile(
		materialRoot,
		unix.O_RDONLY|unix.O_NONBLOCK,
		0,
	)
	pathFileOwned := pathOpenErr == nil
	defer func() {
		if pathFileOwned {
			_ = pathFile.Close()
		}
	}()
	var pathInfo os.FileInfo
	var pathStatErr error
	if pathOpenErr == nil {
		pathInfo, pathStatErr = pathFile.Stat()
	}
	if err != nil || statErr != nil || pathRawStatErr != nil ||
		pathOpenErr != nil || pathStatErr != nil ||
		!rawA9FileInfoRegular(pathRawInfo) ||
		!rawA9FileMatches(pathRawInfo, pathFile) ||
		!provisionedA9FileInfoValid(openedInfo, maxBytes) ||
		openedInfo.Size() != int64(len(material)) ||
		!provisionedA9FileInfoValid(pathInfo, maxBytes) ||
		pathInfo.Size() != openedInfo.Size() ||
		!os.SameFile(openedInfo, pathInfo) ||
		syncA9MaterialDirectory(materialRoot) != nil {
		// Once O_EXCL creates the destination, never unlink by pathname.
		// A restricted partial file is safer than deleting a raced-in entry.
		return nil, errA9MaterialRejected
	}
	writeCloseErr := file.Close()
	fileOwned = false
	if writeCloseErr != nil {
		return nil, errA9MaterialRejected
	}
	receipt := &provisionedA9File{
		materialRoot: materialRoot,
		file:         pathFile,
		info:         openedInfo,
		maxBytes:     maxBytes,
	}
	if !receipt.current() {
		return nil, errA9MaterialRejected
	}
	pathFileOwned = false
	rootOwned = false
	return receipt, nil
}

func syncA9MaterialDirectory(materialRoot *a9MaterialRoot) error {
	if materialRoot == nil || materialRoot.directory == nil ||
		materialRoot.parentInfo == nil {
		return errA9MaterialRejected
	}
	info, statErr := materialRoot.directory.Stat()
	syncErr := materialRoot.directory.Sync()
	if statErr != nil || syncErr != nil ||
		!os.SameFile(materialRoot.parentInfo, info) {
		return errA9MaterialRejected
	}
	return nil
}

func openA9RuntimeFiles(
	config options.Options,
) (*checkedA9RuntimeFiles, bool) {
	paths := []string{
		config.A9.TopicCommitmentKeysFilePath,
		config.A9.TLSCertificateFilePath,
		config.A9.TLSPrivateKeyFilePath,
	}
	maxBytes := []int64{
		maxA9TopicKeySourceBytes,
		a9MaterialMaxBytes,
		a9MaterialMaxBytes,
	}
	kinds := []a9RuntimeFileKind{
		a9RuntimeTopicKeys,
		a9RuntimeTLSCertificate,
		a9RuntimeTLSPrivateKey,
	}
	files := &checkedA9RuntimeFiles{
		files: make([]*checkedA9RuntimeFile, 0, len(paths)),
	}
	for index, path := range paths {
		file, err := openCheckedA9RuntimeFile(
			path,
			kinds[index],
			maxBytes[index],
		)
		if err != nil {
			files.close()
			return nil, false
		}
		for _, existing := range files.files {
			if os.SameFile(existing.info, file.info) {
				file.close()
				files.close()
				return nil, false
			}
		}
		files.files = append(files.files, file)
	}
	if !files.current() {
		files.close()
		return nil, false
	}
	return files, true
}

func restrictedA9FileValid(path string) bool {
	file, err := openCheckedA9RuntimeFile(
		path,
		a9RuntimeTLSPrivateKey,
		a9MaterialMaxBytes,
	)
	if err != nil {
		return false
	}
	defer file.close()
	return file.current() && file.info.Mode().Perm() == 0o600
}

func openCheckedA9RuntimeFile(
	path string,
	kind a9RuntimeFileKind,
	maxBytes int64,
) (*checkedA9RuntimeFile, error) {
	if maxBytes < 1 {
		return nil, errA9MaterialRejected
	}
	materialRoot, err := openA9MaterialRoot(path)
	if err != nil {
		return nil, errA9MaterialRejected
	}
	rootOwned := true
	defer func() {
		if rootOwned {
			_ = materialRoot.directory.Close()
		}
	}()
	beforePath, err := statA9MaterialFile(materialRoot)
	if err != nil || !rawA9FileInfoRegular(beforePath) {
		return nil, errA9MaterialRejected
	}
	file, err := openA9MaterialFile(
		materialRoot,
		unix.O_RDONLY|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, errA9MaterialRejected
	}
	fileOwned := true
	defer func() {
		if fileOwned {
			_ = file.Close()
		}
	}()
	before, err := file.Stat()
	if err != nil || !rawA9FileMatches(beforePath, file) ||
		!a9RuntimeFileInfoValid(before, kind, maxBytes) {
		return nil, errA9MaterialRejected
	}
	callA9MaterialTestHook(a9MaterialHookPreflightFileOpened)
	openedInfo, statErr := file.Stat()
	afterPath, afterPathStatErr := statA9MaterialFile(materialRoot)
	afterFile, pathOpenErr := openA9MaterialFile(
		materialRoot,
		unix.O_RDONLY|unix.O_NONBLOCK,
		0,
	)
	var afterOpen os.FileInfo
	var pathStatErr error
	var pathCloseErr error
	var afterPathMatches bool
	if pathOpenErr == nil {
		afterOpen, pathStatErr = afterFile.Stat()
		afterPathMatches = rawA9FileMatches(afterPath, afterFile)
		pathCloseErr = afterFile.Close()
	}
	if statErr != nil || afterPathStatErr != nil || pathOpenErr != nil ||
		pathStatErr != nil ||
		pathCloseErr != nil ||
		!rawA9FileInfoRegular(afterPath) ||
		!afterPathMatches ||
		!rawA9FileIdentityEqual(beforePath, afterPath) ||
		!a9RuntimeFileInfoValid(openedInfo, kind, maxBytes) ||
		!a9RuntimeFileInfoValid(afterOpen, kind, maxBytes) ||
		!os.SameFile(before, openedInfo) ||
		!os.SameFile(openedInfo, afterOpen) ||
		before.Size() != openedInfo.Size() ||
		afterOpen.Size() != openedInfo.Size() {
		return nil, errA9MaterialRejected
	}
	checked := &checkedA9RuntimeFile{
		materialRoot: materialRoot,
		file:         file,
		info:         openedInfo,
		kind:         kind,
		maxBytes:     maxBytes,
	}
	if !checked.current() {
		return nil, errA9MaterialRejected
	}
	fileOwned = false
	rootOwned = false
	return checked, nil
}

func (file *checkedA9RuntimeFile) current() bool {
	if file == nil || file.materialRoot == nil || file.file == nil ||
		file.info == nil {
		return false
	}
	openedInfo, err := file.file.Stat()
	if err != nil || !a9RuntimeFileInfoValid(
		openedInfo,
		file.kind,
		file.maxBytes,
	) || !os.SameFile(file.info, openedInfo) ||
		file.info.Size() != openedInfo.Size() {
		return false
	}
	return a9MaterialPathMatches(
		file.materialRoot,
		file.info,
		func(info os.FileInfo) bool {
			return a9RuntimeFileInfoValid(info, file.kind, file.maxBytes)
		},
	)
}

func (file *checkedA9RuntimeFile) close() {
	if file == nil {
		return
	}
	if file.file != nil {
		_ = file.file.Close()
	}
	if file.materialRoot != nil && file.materialRoot.directory != nil {
		_ = file.materialRoot.directory.Close()
	}
}

func (file *checkedA9RuntimeFile) closeChecked() bool {
	if file == nil {
		return false
	}
	valid := true
	if file.file != nil {
		if err := file.file.Close(); err != nil {
			valid = false
		}
		file.file = nil
	}
	if file.materialRoot != nil && file.materialRoot.directory != nil {
		if err := file.materialRoot.directory.Close(); err != nil {
			valid = false
		}
		file.materialRoot.directory = nil
	}
	return valid
}

func (files *checkedA9RuntimeFiles) current() bool {
	if files == nil || len(files.files) != 3 {
		return false
	}
	for index, file := range files.files {
		if !file.current() {
			return false
		}
		for previous := 0; previous < index; previous++ {
			if os.SameFile(file.info, files.files[previous].info) {
				return false
			}
		}
	}
	return true
}

func (files *checkedA9RuntimeFiles) close() {
	if files == nil {
		return
	}
	for _, file := range files.files {
		file.close()
	}
}

func (files *checkedA9RuntimeFiles) closeChecked() bool {
	if files == nil || len(files.files) != 3 {
		return false
	}
	valid := true
	for _, file := range files.files {
		if !file.closeChecked() {
			valid = false
		}
	}
	return valid
}

func (file *provisionedA9File) current() bool {
	if file == nil || file.materialRoot == nil || file.file == nil ||
		file.info == nil ||
		!provisionedA9FileInfoValid(file.info, file.maxBytes) {
		return false
	}
	openedInfo, err := file.file.Stat()
	if err != nil || !provisionedA9FileInfoValid(openedInfo, file.maxBytes) ||
		!os.SameFile(file.info, openedInfo) ||
		file.info.Size() != openedInfo.Size() {
		return false
	}
	return a9MaterialPathMatches(
		file.materialRoot,
		file.info,
		func(info os.FileInfo) bool {
			return provisionedA9FileInfoValid(info, file.maxBytes)
		},
	)
}

func (file *provisionedA9File) close() {
	if file == nil {
		return
	}
	if file.file != nil {
		_ = file.file.Close()
	}
	if file.materialRoot != nil && file.materialRoot.directory != nil {
		_ = file.materialRoot.directory.Close()
	}
}

func (file *provisionedA9File) closeChecked() bool {
	if file == nil {
		return false
	}
	valid := true
	if file.file != nil {
		if err := file.file.Close(); err != nil {
			valid = false
		}
		file.file = nil
	}
	if file.materialRoot != nil && file.materialRoot.directory != nil {
		if err := file.materialRoot.directory.Close(); err != nil {
			valid = false
		}
		file.materialRoot.directory = nil
	}
	return valid
}

func a9MaterialPathMatches(
	expectedRoot *a9MaterialRoot,
	expectedFile os.FileInfo,
	validFile func(os.FileInfo) bool,
) bool {
	if expectedRoot == nil || expectedFile == nil || validFile == nil {
		return false
	}
	currentRoot, err := openA9MaterialRoot(expectedRoot.path)
	if err != nil {
		return false
	}
	rootOwned := true
	defer func() {
		if rootOwned {
			_ = currentRoot.directory.Close()
		}
	}()
	if !os.SameFile(expectedRoot.parentInfo, currentRoot.parentInfo) {
		return false
	}
	currentPath, err := statA9MaterialFile(currentRoot)
	if err != nil || !rawA9FileInfoRegular(currentPath) {
		return false
	}
	currentFile, err := openA9MaterialFile(
		currentRoot,
		unix.O_RDONLY|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return false
	}
	currentInfo, statErr := currentFile.Stat()
	pathMatches := rawA9FileMatches(currentPath, currentFile)
	closeErr := currentFile.Close()
	rootCloseErr := currentRoot.directory.Close()
	rootOwned = false
	return statErr == nil && closeErr == nil && rootCloseErr == nil &&
		pathMatches && validFile(currentInfo) &&
		os.SameFile(expectedFile, currentInfo) &&
		expectedFile.Size() == currentInfo.Size()
}

func openA9MaterialRoot(path string) (*a9MaterialRoot, error) {
	if !a9MaterialPathValid(path) {
		return nil, errA9MaterialRejected
	}
	parentPath := filepath.Dir(path)
	directory, err := os.Open(string(filepath.Separator))
	if err != nil {
		return nil, errA9MaterialRejected
	}
	rootOwned := true
	defer func() {
		if rootOwned {
			_ = directory.Close()
		}
	}()
	info, err := directory.Stat()
	if err != nil || !a9MaterialDirectoryValid(info) {
		return nil, errA9MaterialRejected
	}
	trimmed := strings.TrimPrefix(parentPath, string(filepath.Separator))
	if trimmed != "" {
		for _, component := range strings.Split(
			trimmed,
			string(filepath.Separator),
		) {
			if component == "" || component == "." || component == ".." {
				return nil, errA9MaterialRejected
			}
			nextDescriptor, openErr := unix.Openat(
				int(directory.Fd()),
				component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0,
			)
			if openErr != nil {
				return nil, errA9MaterialRejected
			}
			next := os.NewFile(uintptr(nextDescriptor), component)
			if next == nil {
				_ = unix.Close(nextDescriptor)
				return nil, errA9MaterialRejected
			}
			after, nextStatErr := next.Stat()
			if nextStatErr != nil || !a9MaterialDirectoryValid(after) {
				_ = next.Close()
				return nil, errA9MaterialRejected
			}
			_ = directory.Close()
			directory = next
			info = after
		}
	}
	rootOwned = false
	return &a9MaterialRoot{
		directory:  directory,
		path:       path,
		name:       filepath.Base(path),
		parentInfo: info,
	}, nil
}

func openA9MaterialFile(
	materialRoot *a9MaterialRoot,
	flags int,
	permissions uint32,
) (*os.File, error) {
	if materialRoot == nil || materialRoot.directory == nil ||
		materialRoot.name == "" {
		return nil, errA9MaterialRejected
	}
	descriptor, err := unix.Openat(
		int(materialRoot.directory.Fd()),
		materialRoot.name,
		flags|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		permissions,
	)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, errA9MaterialRejected
	}
	file := os.NewFile(uintptr(descriptor), materialRoot.name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errA9MaterialRejected
	}
	return file, nil
}

func statA9MaterialFile(
	materialRoot *a9MaterialRoot,
) (*unix.Stat_t, error) {
	if materialRoot == nil || materialRoot.directory == nil ||
		materialRoot.name == "" {
		return nil, errA9MaterialRejected
	}
	var info unix.Stat_t
	err := unix.Fstatat(
		int(materialRoot.directory.Fd()),
		materialRoot.name,
		&info,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, errA9MaterialRejected
	}
	return &info, nil
}

func rawA9FileInfoRegular(info *unix.Stat_t) bool {
	return info != nil && info.Mode&unix.S_IFMT == unix.S_IFREG
}

func rawA9FileIdentityEqual(left *unix.Stat_t, right *unix.Stat_t) bool {
	return left != nil && right != nil &&
		left.Dev == right.Dev && left.Ino == right.Ino
}

func rawA9FileMatches(info *unix.Stat_t, file *os.File) bool {
	if info == nil || file == nil {
		return false
	}
	var opened unix.Stat_t
	return unix.Fstat(int(file.Fd()), &opened) == nil &&
		rawA9FileIdentityEqual(info, &opened)
}

func provisionedA9FileInfoValid(info os.FileInfo, maxBytes int64) bool {
	return info != nil && info.Mode().IsRegular() &&
		info.Mode().Perm() == 0o600 &&
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Size() > 0 && info.Size() <= maxBytes &&
		a9FileOwnedByCurrentProcess(info)
}

func a9RuntimeFileInfoValid(
	info os.FileInfo,
	kind a9RuntimeFileKind,
	maxBytes int64,
) bool {
	if info == nil || info.Size() > maxBytes ||
		!a9FileOwnedByCurrentProcess(info) {
		return false
	}
	switch kind {
	case a9RuntimeTopicKeys:
		return validA9TopicKeyFileInfo(info)
	case a9RuntimeTLSCertificate:
		return a9api.TransportFileMetadataValid(info, false)
	case a9RuntimeTLSPrivateKey:
		return a9api.TransportFileMetadataValid(info, true)
	default:
		return false
	}
}

func a9MaterialDirectoryValid(info os.FileInfo) bool {
	if info == nil || !info.IsDir() ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == uint32(os.Geteuid()) || stat.Uid == 0)
}

func callA9MaterialTestHook(stage string) {
	if a9MaterialTestHook != nil {
		a9MaterialTestHook(stage)
	}
}

func a9FileOwnedByCurrentProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func a9MaterialPathValid(path string) bool {
	return path != "" && filepath.IsAbs(path) &&
		filepath.Clean(path) == path && path != string(filepath.Separator)
}

func a9MaterialModeRequested(args []string) bool {
	return longOptionPresent(args, "--provision-a9-material") ||
		longOptionPresent(args, "--preflight-a9-runtime-files")
}

func longOptionPresent(args []string, option string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == option || len(arg) > len(option) &&
			arg[:len(option)+1] == option+"=" {
			return true
		}
	}
	return false
}

func writeA9MaterialFailure(stderr io.Writer) {
	if stderr != nil {
		_, _ = io.WriteString(stderr, a9MaterialFailureOutput)
	}
}
