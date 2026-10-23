// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package repair

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type linuxSpec struct {
	family, label, bundle, config, sources, local, blocklist, updater, state, root string
	args                                                                           []string
}

type linuxStore struct {
	spec    linuxSpec
	owner   int
	rebuild func() error
}

type nativeEdit struct {
	Path    string            `json:"path"`
	Existed bool              `json:"existed"`
	Before  []byte            `json:"before,omitempty"`
	After   []byte            `json:"after"`
	Mode    uint32            `json:"mode"`
	Sources map[string]string `json:"sources,omitempty"`
}

type nativeRecord struct {
	Version      int          `json:"version"`
	Family       string       `json:"family"`
	Created      string       `json:"created"`
	Bundle       string       `json:"bundle"`
	BundleBefore []byte       `json:"bundle_before"`
	Roots        []Root       `json:"roots"`
	Edits        []nativeEdit `json:"edits"`
}

type nativePlan struct {
	Plan
	edits  []nativeEdit
	bundle []byte
}

func linuxSystem() (*linuxStore, error) {
	// os-release is data, never sourced as a shell program.
	path, err := filepath.EvalSymlinks("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("locate Linux release information: %w", err)
	}
	if err = trustedParents(path, "/", 0); err != nil {
		return nil, err
	}
	data, info, err := readSecure(path, false)
	if err != nil {
		return nil, err
	}
	if !ownedBy(info, 0) {
		return nil, errors.New("untrusted Linux release information")
	}
	id := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"'")
		}
	}
	spec, err := linuxLayout(id)
	if err != nil {
		return nil, err
	}
	store := &linuxStore{spec: spec}
	if spec.family == "p11-kit" {
		if _, err := os.Stat(spec.blocklist); os.IsNotExist(err) {
			store.spec.blocklist = "/etc/pki/ca-trust/source/blacklist"
		}
	}
	return store, nil
}

func linuxLayout(id string) (linuxSpec, error) {
	spec := linuxSpec{root: "/", state: "/etc/embarass-fix", args: nil}
	switch id {
	case "debian", "ubuntu", "alpine":
		spec.family, spec.label = "debian", id+" native CA configuration"
		spec.bundle, spec.config = "/etc/ssl/certs/ca-certificates.crt", "/etc/ca-certificates.conf"
		spec.sources, spec.local = "/usr/share/ca-certificates", "/usr/local/share/ca-certificates"
		spec.updater = "/usr/sbin/update-ca-certificates"
	case "fedora", "rhel", "centos", "rocky", "almalinux", "amzn", "ol":
		spec.family, spec.label = "p11-kit", id+" native CA distrust"
		spec.bundle = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
		spec.blocklist = "/etc/pki/ca-trust/source/blocklist"
		spec.updater, spec.args = "/usr/bin/update-ca-trust", []string{"extract"}
	default:
		return spec, fmt.Errorf("unsupported Linux distribution %q; update its CA packages and use batch to verify", id)
	}
	return spec, nil
}

func (s *linuxStore) Inspect() (Plan, error) {
	plan, err := s.prepare()
	return plan.Plan, err
}

// Native helpers execute root-owned distro hooks. The preview discloses this;
// the caller never supplies a command, environment, source root, or hook path.
func (s *linuxStore) validate() error {
	paths := []string{s.spec.bundle, s.spec.updater, s.spec.state}
	if s.spec.config != "" {
		paths = append(paths, s.spec.config)
	}
	if s.spec.blocklist != "" {
		paths = append(paths, filepath.Join(s.spec.blocklist, "probe.pem"))
	}
	for _, path := range paths {
		if err := trustedParents(path, s.spec.root, s.owner); err != nil {
			return err
		}
	}
	_, info, err := readSecure(s.spec.updater, false)
	if err != nil {
		return fmt.Errorf("native CA updater is required; install/update the full ca-certificates package first: %w", err)
	}
	if !ownedBy(info, s.owner) || info.Mode().Perm()&0111 == 0 {
		return errors.New("untrusted native CA updater")
	}
	return nil
}

func trustedParents(path, root string, owner int) error {
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("resolve native store directory: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve native store root: %w", err)
	}
	if dir != root && !strings.HasPrefix(dir, strings.TrimSuffix(root, "/")+"/") {
		return errors.New("native store path escapes its root")
	}
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("inspect native store directory: %w", err)
		}
		if !info.IsDir() || !ownedBy(info, owner) || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("unsafe native store directory: %s", dir)
		}
		if dir == root {
			return nil
		}
		dir = filepath.Dir(dir)
	}
}

func (s *linuxStore) read(path string) ([]byte, os.FileInfo, error) {
	if err := trustedParents(path, s.spec.root, s.owner); err != nil {
		return nil, nil, err
	}
	data, info, err := readSecure(path, false)
	if err != nil {
		return nil, nil, err
	}
	if !ownedBy(info, s.owner) {
		return nil, nil, fmt.Errorf("unexpected native store file owner: %s", path)
	}
	if info.Mode().Perm()&0004 == 0 {
		return nil, nil, fmt.Errorf("private native CA files need manual handling: %s", path)
	}
	return data, info, nil
}

func (s *linuxStore) prepare() (nativePlan, error) {
	var result nativePlan
	if err := s.validate(); err != nil {
		return result, err
	}
	bundle, _, err := s.read(s.spec.bundle)
	if err != nil {
		return result, err
	}
	plan, err := inspect(bundle)
	if err != nil {
		return result, err
	}
	plan.BundlePath, plan.Platform = s.spec.bundle, s.spec.label
	plan.Refresh = strings.Join(append([]string{s.spec.updater}, s.spec.args...), " ")
	result.Plan, result.bundle = plan, bundle
	var snapshot bytes.Buffer
	snapshot.WriteString(digest(bundle))
	if s.spec.family == "debian" {
		result.Path = s.spec.config
		edits, roots, err := s.debianEdits(&snapshot)
		if err != nil {
			return result, err
		}
		result.edits = edits
		result.Removed = uniqueRoots(append(result.Removed, roots...))
	} else {
		result.Path = s.spec.blocklist
		blocks, err := certificateBlocks(bundle)
		if err != nil {
			return result, err
		}
		for _, root := range uniqueRoots(result.Removed) {
			path := filepath.Join(s.spec.blocklist, "embarass-"+root.SHA256+".pem")
			before, _, err := s.read(path)
			snapshot.WriteString(path)
			if err == nil {
				snapshot.WriteString(digest(before))
				known, parseErr := certificateBlocks(before)
				if parseErr != nil || len(known) != 1 || known[root.SHA256] == nil {
					return result, fmt.Errorf("conflicting native distrust file: %s", path)
				}
				continue // Pre-existing policy is never claimed or removed by undo.
			}
			if !errors.Is(err, os.ErrNotExist) {
				return result, err
			}
			snapshot.WriteString("absent")
			result.edits = append(result.edits, nativeEdit{Path: path, After: blocks[root.SHA256], Mode: 0644})
		}
	}
	result.BeforeSHA256 = digest(snapshot.Bytes())
	return result, nil
}

func (s *linuxStore) debianEdits(snapshot *bytes.Buffer) ([]nativeEdit, []Root, error) {
	config, info, err := s.read(s.spec.config)
	if err != nil {
		return nil, nil, fmt.Errorf("native CA configuration is required; install/update the full ca-certificates package first: %w", err)
	}
	snapshot.WriteString(digest(config))
	var out bytes.Buffer
	var roots []Root
	sources := make(map[string]string)
	for _, line := range strings.SplitAfter(string(config), "\n") {
		entry := strings.TrimSpace(line)
		disabled := strings.HasPrefix(entry, "!")
		if entry == "" || strings.HasPrefix(entry, "#") {
			out.WriteString(line)
			continue
		}
		entry = strings.TrimPrefix(entry, "!")
		if filepath.IsAbs(entry) || filepath.Clean(entry) != entry || strings.HasPrefix(entry, "..") || !strings.HasSuffix(entry, ".crt") {
			return nil, nil, fmt.Errorf("unsupported CA configuration entry %q", entry)
		}
		path := filepath.Join(s.spec.sources, entry)
		cert, _, readErr := s.read(path)
		snapshot.WriteString(path)
		if readErr != nil {
			if !errors.Is(readErr, os.ErrNotExist) {
				return nil, nil, readErr
			}
			snapshot.WriteString("absent")
			out.WriteString(line)
			continue // Native updaters also tolerate removed vendor source files.
		}
		snapshot.WriteString(digest(cert))
		found, err := matchingRoots(cert)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect native CA source %s: %w", path, err)
		}
		if len(found) > 0 && !disabled {
			blocks, err := certificateBlocks(cert)
			if err != nil || len(blocks) != len(found) {
				return nil, nil, fmt.Errorf("CA source mixes affected and unrelated certificates: %s", path)
			}
			roots = append(roots, found...)
			sources[path] = digest(cert)
			// Preserve whitespace/comments everywhere except this exact entry.
			position := strings.Index(line, entry)
			out.WriteString(line[:position] + "!" + line[position:])
		} else {
			out.WriteString(line)
		}
	}
	if err := s.checkLocalRoots(snapshot); err != nil {
		return nil, nil, err
	}
	var edits []nativeEdit
	if !bytes.Equal(config, out.Bytes()) {
		edits = append(edits, nativeEdit{Path: s.spec.config, Existed: true, Before: config, After: out.Bytes(), Mode: uint32(info.Mode().Perm()), Sources: sources})
	}
	return edits, roots, nil
}

func (s *linuxStore) checkLocalRoots(snapshot *bytes.Buffer) error {
	if _, err := os.Lstat(s.spec.local); os.IsNotExist(err) {
		return nil
	}
	err := filepath.WalkDir(s.spec.local, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("inspect local CA directory: %w", walkErr)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("local CA symlink requires manual review: %s", path)
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".crt") {
			return nil
		}
		data, _, err := s.read(path)
		if err != nil {
			return err
		}
		snapshot.WriteString(path + digest(data))
		roots, err := matchingRoots(data)
		if err != nil {
			return err
		}
		if len(roots) > 0 {
			return fmt.Errorf("affected root also installed as a local CA at %s; review that explicit local trust before automatic repair", path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("check local CA overrides: %w", err)
	}
	return nil
}

func certificateBlocks(data []byte) (map[string][]byte, error) {
	blocks := make(map[string][]byte)
	beginCount := bytes.Count(data, []byte("-----BEGIN "))
	endCount := bytes.Count(data, []byte("-----END "))
	decoded := 0
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("unsupported native certificate format")
		}
		if _, err := parseBundleCertificate(block.Bytes); err != nil {
			return nil, err
		}
		blocks[digest(block.Bytes)] = pem.EncodeToMemory(block)
		decoded++
		data = rest
	}
	if decoded != beginCount || decoded != endCount {
		return nil, errors.New("malformed native certificate PEM")
	}
	if len(blocks) == 0 {
		return nil, errors.New("native CA source contains no certificates")
	}
	return blocks, nil
}

func matchingRoots(data []byte) ([]Root, error) {
	blocks, err := certificateBlocks(data)
	if err != nil {
		return nil, err
	}
	var roots []Root
	for _, root := range affectedRoots {
		if blocks[root.SHA256] != nil {
			roots = append(roots, root)
		}
	}
	return roots, nil
}

func uniqueRoots(roots []Root) []Root {
	var result []Root
	seen := make(map[string]bool)
	for _, root := range roots {
		if !seen[root.SHA256] {
			result = append(result, root)
			seen[root.SHA256] = true
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SHA256 < result[j].SHA256 })
	return result
}

func (s *linuxStore) refresh() error {
	if s.rebuild != nil {
		return s.rebuild()
	}
	cmd := exec.Command(s.spec.updater, s.spec.args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	// Drain output without retaining unbounded output from vendor hooks.
	var output cappedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("native CA regeneration failed: %w: %s", err, strings.TrimSpace(output.String()))
	}
	return nil
}

type cappedOutput struct{ bytes.Buffer }

func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remain := 16384 - b.Len(); remain > 0 {
		_, _ = b.Buffer.Write(p[:min(n, remain)])
	}
	return n, nil
}

func (s *linuxStore) Apply(expected string, undo bool) (Receipt, error) {
	if err := s.validate(); err != nil {
		return Receipt{}, err
	}
	unlock, err := lockStore(s.spec.state + ".lock")
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	if undo {
		return s.undo(expected)
	}
	plan, err := s.prepare()
	if err != nil {
		return Receipt{}, err
	}
	if plan.BeforeSHA256 != expected {
		return Receipt{}, errors.New("native CA inputs changed after preview; inspect again")
	}
	if len(plan.Removed) == 0 {
		return Receipt{}, errors.New("target roots are already absent; nothing to apply")
	}
	record := nativeRecord{Version: 2, Family: s.spec.family, Created: time.Now().UTC().Format(time.RFC3339Nano),
		Bundle: s.spec.bundle, BundleBefore: plan.bundle, Roots: plan.Removed, Edits: plan.edits}
	if err = os.Mkdir(s.spec.state, 0755); err != nil {
		return Receipt{}, fmt.Errorf("create native repair record; recover any previous transaction with fix --undo: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(filepath.Join(s.spec.state, "receipt.json"))
			_ = os.Remove(s.spec.state)
		}
	}()
	if err = os.Chmod(s.spec.state, 0755); err != nil {
		return Receipt{}, fmt.Errorf("set native record permissions: %w", err)
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return Receipt{}, fmt.Errorf("encode native receipt: %w", err)
	}
	if err = writeExclusive(filepath.Join(s.spec.state, "receipt.json"), encoded, 0644); err != nil {
		return Receipt{}, err
	}
	if err = syncDirectory(s.spec.state); err != nil {
		return Receipt{}, err
	}
	if err = syncDirectory(filepath.Dir(s.spec.state)); err != nil {
		return Receipt{}, err
	}
	keep = true
	receipt := s.receipt(record)
	for _, edit := range plan.edits {
		if edit.Existed {
			err = replace(edit.Path, digest(edit.Before), edit.After, os.FileMode(edit.Mode))
		} else {
			err = writeExclusive(edit.Path, edit.After, os.FileMode(edit.Mode))
			if err == nil {
				err = syncDirectory(filepath.Dir(edit.Path))
			}
		}
		if err != nil {
			return receipt, fmt.Errorf("native repair incomplete; recovery record retained at %s: %w", receipt.Backup, err)
		}
	}
	if err = s.refresh(); err != nil {
		return receipt, fmt.Errorf("native policy changed but regeneration incomplete; recover with fix --undo: %w", err)
	}
	if err = s.verify(plan.bundle); err != nil {
		return receipt, fmt.Errorf("native policy changed but verification failed; recovery record retained: %w", err)
	}
	return receipt, nil
}

func (s *linuxStore) verify(before []byte) error {
	current, _, err := s.read(s.spec.bundle)
	if err != nil {
		return err
	}
	plan, err := inspect(current)
	if err != nil {
		return err
	}
	if len(plan.Removed) != 0 {
		return errors.New("affected roots remain in the regenerated TLS bundle; inspect local overrides")
	}
	oldSet, err := certificateBlocks(before)
	if err != nil {
		return err
	}
	newSet, err := certificateBlocks(current)
	if err != nil {
		return err
	}
	for _, root := range affectedRoots {
		delete(oldSet, root.SHA256)
	}
	for fingerprint := range oldSet {
		if newSet[fingerprint] == nil {
			return errors.New("native regeneration also removed unrelated certificates; review current distro policy")
		}
	}
	return nil
}

func (s *linuxStore) receipt(record nativeRecord) Receipt {
	return Receipt{Version: 2, Created: record.Created, Backup: filepath.Join(s.spec.state, "receipt.json"), Removed: record.Roots}
}

func (s *linuxStore) recovery() (nativeRecord, error) {
	var record nativeRecord
	if err := s.validate(); err != nil {
		return record, err
	}
	encoded, _, err := s.read(filepath.Join(s.spec.state, "receipt.json"))
	if err != nil {
		return record, err
	}
	if err = json.Unmarshal(encoded, &record); err != nil {
		return record, fmt.Errorf("decode native repair record: %w", err)
	}
	if record.Version != 2 || record.Family != s.spec.family || record.Bundle != s.spec.bundle {
		return record, errors.New("native repair record does not match this distribution")
	}
	if _, err = inspect(record.BundleBefore); err != nil {
		return record, err
	}
	for _, edit := range record.Edits {
		if edit.Mode&^uint32(0777) != 0 || edit.Mode&0022 != 0 {
			return record, errors.New("unsafe native repair record permissions")
		}
		if s.spec.family == "debian" {
			if edit.Path != s.spec.config || !edit.Existed || !onlyDeselections(edit.Before, edit.After) {
				return record, errors.New("native repair record contains unexpected configuration changes")
			}
			for path := range edit.Sources {
				if filepath.Clean(path) != path || !strings.HasPrefix(path, s.spec.sources+string(filepath.Separator)) {
					return record, errors.New("invalid recorded native CA source")
				}
			}
		} else {
			roots, err := matchingRoots(edit.After)
			if err != nil || len(roots) != 1 || edit.Existed || len(edit.Before) != 0 || edit.Path != filepath.Join(s.spec.blocklist, "embarass-"+roots[0].SHA256+".pem") {
				return record, errors.New("native repair record contains an unexpected distrust file")
			}
		}
	}
	return record, nil
}

func onlyDeselections(before, after []byte) bool {
	original, replacement := strings.SplitAfter(string(before), "\n"), strings.SplitAfter(string(after), "\n")
	if len(original) != len(replacement) {
		return false
	}
	for i, line := range original {
		if line == replacement[i] {
			continue
		}
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") || strings.HasPrefix(entry, "!") {
			return false
		}
		position := strings.Index(line, entry)
		if replacement[i] != line[:position]+"!"+line[position:] {
			return false
		}
	}
	return true
}

func (s *linuxStore) UndoPlan() (Plan, error) {
	record, err := s.recovery()
	if err != nil {
		return Plan{}, err
	}
	return s.undoPlan(record)
}

func (s *linuxStore) undoPlan(record nativeRecord) (Plan, error) {
	current, _, err := s.read(s.spec.bundle)
	if err != nil {
		return Plan{}, err
	}
	plan, err := inspect(current)
	if err != nil {
		return Plan{}, err
	}
	var snapshot bytes.Buffer
	snapshot.WriteString(digest(current))
	for _, edit := range record.Edits {
		data, _, err := s.read(edit.Path)
		snapshot.WriteString(edit.Path)
		if errors.Is(err, os.ErrNotExist) && !edit.Existed {
			snapshot.WriteString("absent")
			continue
		}
		if err != nil {
			return Plan{}, err
		}
		if !bytes.Equal(data, edit.After) && (!edit.Existed || !bytes.Equal(data, edit.Before)) {
			return Plan{}, errors.New("native CA policy changed since repair; refusing to overwrite vendor or administrator changes")
		}
		if edit.Existed && bytes.Equal(data, edit.After) {
			keys := make([]string, 0, len(edit.Sources))
			for path := range edit.Sources {
				keys = append(keys, path)
			}
			sort.Strings(keys)
			for _, path := range keys {
				source, _, err := s.read(path)
				if err != nil || digest(source) != edit.Sources[path] {
					return Plan{}, fmt.Errorf("vendor CA source changed since repair at %s; refusing stale undo", path)
				}
				snapshot.WriteString(path + digest(source))
			}
		}
		snapshot.WriteString(digest(data))
	}
	plan.Path = s.spec.config
	if plan.Path == "" {
		plan.Path = s.spec.blocklist
	}
	plan.BundlePath, plan.Platform, plan.Removed = s.spec.bundle, s.spec.label, record.Roots
	plan.Refresh = strings.Join(append([]string{s.spec.updater}, s.spec.args...), " ")
	plan.BeforeSHA256 = digest(snapshot.Bytes())
	return plan, nil
}

func (s *linuxStore) undo(expected string) (Receipt, error) {
	record, err := s.recovery()
	if err != nil {
		return Receipt{}, err
	}
	receipt := s.receipt(record)
	plan, err := s.undoPlan(record)
	if err != nil {
		return receipt, err
	}
	if plan.BeforeSHA256 != expected {
		return receipt, errors.New("native CA inputs changed after undo preview")
	}
	for _, edit := range record.Edits {
		data, _, err := s.read(edit.Path)
		if errors.Is(err, os.ErrNotExist) && !edit.Existed {
			continue
		}
		if err != nil {
			return receipt, err
		}
		if edit.Existed {
			if bytes.Equal(data, edit.Before) {
				continue
			}
			err = replace(edit.Path, digest(edit.After), edit.Before, os.FileMode(edit.Mode))
		} else if bytes.Equal(data, edit.After) {
			err = os.Remove(edit.Path)
		} else {
			err = errors.New("native distrust file changed during undo")
		}
		if err != nil {
			return receipt, fmt.Errorf("native undo incomplete; recovery record retained: %w", err)
		}
		if err = syncDirectory(filepath.Dir(edit.Path)); err != nil {
			return receipt, err
		}
	}
	if err = s.refresh(); err != nil {
		return receipt, fmt.Errorf("local policy restored but native regeneration incomplete: %w", err)
	}
	// Never restore an old generated bundle: current vendor policy owns outputs.
	if _, _, err = s.read(s.spec.bundle); err != nil {
		return receipt, err
	}
	archive := s.spec.state + ".restored-" + time.Now().UTC().Format("20060102T150405.000000000")
	if err = os.Rename(s.spec.state, archive); err != nil {
		return receipt, fmt.Errorf("native policy restored but receipt archive failed: %w", err)
	}
	receipt.Backup = filepath.Join(archive, "receipt.json")
	return receipt, syncDirectory(filepath.Dir(s.spec.state))
}
