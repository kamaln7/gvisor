// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gofer

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

var (
	errPartialRevalidation  = fmt.Errorf("partial revalidation")
	errRevalidationStepDone = fmt.Errorf("stop revalidation")
)

// revalidatePath checks cached dentries for external modification. File
// attributes are refreshed and cache is invalidated in case the dentry has been
// deleted, or a new file/directory created in its place.
//
// Preconditions:
// * fs.renameMu must be locked.
func (fs *filesystem) revalidatePath(ctx context.Context, rpOrig *vfs.ResolvingPath, start *dentry, ds **[]*dentry) error {
	if start.cachedMetadataAuthoritative() {
		return nil
	}

	// Copy resolving path to walk the path for revalidation.
	rp := *rpOrig
	done := func() bool { return rp.Done() }
	return fs.revalidate(ctx, &rp, start, done, ds)
}

// revalidateParentDir does the same as revalidatePath, but stops are the parent.
func (fs *filesystem) revalidateParentDir(ctx context.Context, rpOrig *vfs.ResolvingPath, start *dentry, ds **[]*dentry) error {
	if start.cachedMetadataAuthoritative() {
		return nil
	}

	// Copy resolving path to walk the path for revalidation.
	rp := *rpOrig
	done := func() bool { return rp.Final() }
	return fs.revalidate(ctx, &rp, start, done, ds)
}

// revalidateOne does the same as revalidatePath, but checks a single dentry.
func (fs *filesystem) revalidateOne(ctx context.Context, vfsObj *vfs.VirtualFilesystem, parent *dentry, name string, ds **[]*dentry) error {
	if parent.cachedMetadataAuthoritative() {
		return nil
	}

	parent.dirMu.Lock()
	child, ok := parent.children[name]
	parent.dirMu.Unlock()
	if !ok {
		return nil
	}

	state := makeRevalidateState(parent)
	defer state.reset()

	if child == nil {
		state.addNegativeEntry(name)
	} else {
		state.addWithLockMetadata(name, child)
	}
	return fs.revalidateHelper(ctx, vfsObj, &state, ds)
}

func (fs *filesystem) revalidate(ctx context.Context, rp *vfs.ResolvingPath, start *dentry, done func() bool, ds **[]*dentry) error {
	state := makeRevalidateState(start)
	defer state.reset()
	state.addWithLockMetadata("", start)

retry:
	for cur := start; !done(); {
		var err error
		cur, err = fs.revalidateStep(ctx, rp, cur, &state)
		switch {
		case err == errPartialRevalidation:
			if err := fs.revalidateHelper(ctx, rp.VirtualFilesystem(), &state, ds); err != nil {
				return err
			}
			state.reset()
			state.start = cur
			state.addWithLockMetadata("", cur)

		case err == errRevalidationStepDone:
			break retry

		case err != nil:
			return err
		}
	}
	return fs.revalidateHelper(ctx, rp.VirtualFilesystem(), &state, ds)
}

// revalidateStep walks one element of the path and update revalidation state
// with the entry if needed. It may also stop the revalidation or ask for a
// partial revalidation when ".." is present in the path.
//
// Returns:
// * (dentry, nil): step worked, continue stepping.`
// * (dentry, errPartialRevalidation): revalidation should be done with the
//     state gathered so far. Then continue stepping with the remainder of the
//     path, starting at `dentry`.
// * (nil, errRevalidationStepDone): revalidation doesn't need to step any
//     further. It hit a symlink, a mount point, or an uncached dentry.
//
// Preconditions:
// * fs.renameMu must be locked.
// * !rp.Done().
func (fs *filesystem) revalidateStep(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, state *revalidateState) (*dentry, error) {
	switch name := rp.Component(); name {
	case ".":
		// Do nothing.

	case "..":
		// Consume all ".."'s that are grouped together.
		for {
			if rp.Done() {
				return nil, errRevalidationStepDone
			}
			if rp.Component() != ".." {
				break
			}

			if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
				return nil, errRevalidationStepDone
			} else if isRoot || d.parent == nil {
				rp.Advance()
				continue
			}
			if err := rp.CheckMount(ctx, &d.parent.vfsd); err != nil {
				return nil, errRevalidationStepDone
			}

			d = d.parent
			rp.Advance()
		}
		return d, errPartialRevalidation

	default:
		d.dirMu.Lock()
		child, ok := d.children[name]
		d.dirMu.Unlock()
		if !ok {
			// child is not cached, no need to validate any further.
			return nil, errRevalidationStepDone
		}

		if child == nil {
			state.addNegativeEntry(name)
			return nil, errRevalidationStepDone
		}

		state.addWithLockMetadata(name, child)

		// Decide if iteration may continue forward or should stop.
		if child.isSynthetic() || child.isSymlink() {
			return nil, errRevalidationStepDone
		}

		d = child
	}

	rp.Advance()
	return d, nil
}

// revalidateHelper calls the gofer to stat all dentries in `state`. It will
// update or invalidate dentries in the cache based on the result.
//
// Preconditions: d.cachedMetadataAuthoritative()
// Preconditions:
// * fs.renameMu must be locked.
// * d.metadataMu must be locked for all dentries
// * d.cachedMetadataAuthoritative() for all dentries
func (fs *filesystem) revalidateHelper(ctx context.Context, vfsObj *vfs.VirtualFilesystem, state *revalidateState, ds **[]*dentry) error {
	stats, err := state.start.file.multiGetAttr(ctx, state.names)
	//log.Infof("FOO multiGetAttr return: qids: %d, err: %v", len(qids), err)
	if err != nil {
		return err
	}

	for i, d := range state.dentries {
		if i == 0 && len(state.names[0]) == 0 {
			// First dentry is where the search is starting, just update attributes
			// since it cannot be replaced.
			d.updateFromP9AttrsLocked(stats[i].Valid, &stats[i].Attr)
			state.unlockMetadata(d)
			continue
		}

		notFound := i >= len(stats)
		//log.Infof("FOO: name: %q, i: %v, notFound: %v, qids: %v", state.names[i], i, notFound, len(qids))
		if notFound || d.qidPath != stats[i].QID.Path {
			log.Infof("FOO invalidate, name: %q, notFound: %v, synthetic: %v, symlink: %v", state.names[i], notFound, d.isSynthetic(), d.isSymlink())
			state.unlockMetadata(d)
			if notFound && d.isSynthetic() {
				// We have a synthetic file, and no remote file has arisen to replace
				// it.
				return nil
			}
			// The file at this path has changed or no longer exists. Mark the
			// dentry invalidated, and re-evaluate its caching status (i.e. if it
			// has 0 references, drop it). The dentry will be reloaded next time it's
			// accessed.
			vfsObj.InvalidateDentry(ctx, &d.vfsd)
			if d.isSynthetic() {
				// Normally we don't mark invalidated dentries as deleted since
				// they may still exist (but at a different path), and also for
				// consistency with Linux. However, synthetic files are guaranteed
				// to become unreachable if their dentries are invalidated, so
				// treat their invalidation as deletion.
				d.setDeleted()
				d.syntheticChildren--
				d.decRefNoCaching()
				d.dirents = nil
			}

			name := state.names[i]
			d.parent.dirMu.Lock()
			// Since the lock was released, re-check that the parent's child with this
			// name is still the same. Do not touch it if it has been replaced with a
			// different one.
			if child := d.parent.children[name]; child == d {
				if notFound {
					// No file exists at this path now. Cache the negative lookup if allowed.
					d.parent.cacheNegativeLookupLocked(name)
				} else {
					delete(d.parent.children, name)
				}
			}
			d.parent.dirMu.Unlock()

			*ds = appendDentry(*ds, d)
			return nil
		}

		// The file at this path hasn't changed. Just update cached metadata.
		//log.Infof("FOO name: %q, not changed", state.names[i])
		d.updateFromP9AttrsLocked(stats[i].Valid, &stats[i].Attr)
		state.unlockMetadata(d)
	}

	// If checking for a negative entry, remove the entry in case a new file/dir
	// has been found.
	if parent, name, ok := state.negativeEntry(); ok && len(state.names) == len(stats) {
		parent.dirMu.Lock()
		// Re-check that negative entry is still there after lock is acquired.
		if child, ok := parent.children[name]; ok && child == nil {
			delete(parent.children, name)
		}
		parent.dirMu.Unlock()
	}

	return nil
}

// revalidateState keeps state related to a revalidation request. It keeps track
// of {name, dentry} list being revalidated, as well as metadata locks on the
// dentries. The list must be in ancestry order, in other words `n` must be
// `n-1` child.
type revalidateState struct {
	// start is the dentry where to start the attributes search.
	start *dentry

	// List of names of entries to refresh attributes. Names length must be the
	// same as detries length or one higher, in case it's checking for an negative
	// cache entry (where a dentry doesn't exist).
	names []string

	// dentries is the list of dentries that corresppond to the names above.
	// dentry.metadataMu is acquired as each dentry is added to this list.
	dentries []*dentry

	// locks keeps tracks of all dentries that have been locked. They are released
	// upon reset().
	locks map[*dentry]struct{}

	// locked when set to true doesn't allow more names or dentries to be added
	// until it's reset().
	locked bool
}

func makeRevalidateState(start *dentry) revalidateState {
	return revalidateState{
		start:    start,
		names:    make([]string, 0, 20),
		dentries: make([]*dentry, 0, 20),
		locks:    make(map[*dentry]struct{}),
	}
}

func (r *revalidateState) addWithLockMetadata(name string, d *dentry) {
	if r.locked {
		panic("revalidateState is locked")
	}
	r.names = append(r.names, name)
	r.dentries = append(r.dentries, d)
	r.locks[d] = struct{}{}
	d.metadataMu.Lock()
}

func (r *revalidateState) unlockMetadata(d *dentry) {
	d.metadataMu.Unlock()
	delete(r.locks, d)
}

// addNegativeEntry adds a name to be checked that belongs to a negative record
// in the dentry cache. A negative entry must be the last one to be added, since
// a negative entry has no children.
func (r *revalidateState) addNegativeEntry(name string) {
	if r.locked {
		panic("revalidateState is locked")
	}
	r.names = append(r.names, name)
	r.locked = true
}

// negativeEntry retrieves a negative entry if one exists.
//
// Returns:
// * (parent, name, true): if a negative entry exists, returns the dentry parent
//   name and true.
// * (nil, "", false): a negative entry doesn't exist.
func (r *revalidateState) negativeEntry() (*dentry, string, bool) {
	if len(r.names) == len(r.dentries) {
		return nil, "", false
	}
	// There can be only one negative entry and it must be at the end.
	if len(r.names) != len(r.dentries)+1 {
		panic(fmt.Sprintf("revalidateState invalid negative entry: %+v", r))
	}
	return r.dentries[len(r.dentries)-1], r.names[len(r.names)-1], true
}

// reset releases all metadata locks and resets all fields to allow this
// instance to be reused.
func (r *revalidateState) reset() {
	for d := range r.locks {
		r.unlockMetadata(d)
	}
	r.start = nil
	r.names = r.names[:0]
	r.dentries = r.dentries[:0]
	r.locked = false
}
