use super::*;

type MmapFn = unsafe extern "C" fn(
    *mut libc::c_void,
    usize,
    libc::c_int,
    libc::c_int,
    libc::c_int,
    libc::off_t,
) -> *mut libc::c_void;
type MemoryFn = unsafe extern "C" fn(*mut libc::c_void, usize) -> libc::c_int;
type MemoryFlagsFn = unsafe extern "C" fn(*mut libc::c_void, usize, libc::c_int) -> libc::c_int;

#[derive(Clone)]
struct MappingSlice {
    address: usize,
    length: usize,
    file_start: u64,
    file_end: u64,
    open: Arc<OpenFile>,
}

struct PendingMapping {
    file_offset: u64,
    writable: bool,
    open: Arc<OpenFile>,
}

impl FilesystemHookRuntime {
    fn prepare_mapping(
        &self,
        length: usize,
        protection: libc::c_int,
        flags: libc::c_int,
        descriptor: libc::c_int,
        offset: libc::off_t,
    ) -> Result<Option<PendingMapping>> {
        if flags & libc::MAP_SHARED == 0 || offset < 0 || length == 0 {
            return Ok(None);
        }
        let Some(open) = self.tracked_open(descriptor) else {
            return Ok(None);
        };
        let file_offset = offset as u64;
        let file_end = file_offset
            .checked_add(u64::try_from(length).context("memory mapping length overflowed")?)
            .context("memory mapping file range overflowed")?;
        let writable = protection & libc::PROT_WRITE != 0;
        if writable {
            self.register_potential_range(&open, file_offset, file_end)?;
        }
        Ok(Some(PendingMapping {
            file_offset,
            writable,
            open,
        }))
    }

    fn register_mapping(
        &self,
        address: *mut libc::c_void,
        length: usize,
        pending: Option<PendingMapping>,
    ) -> Result<()> {
        let Some(pending) = pending else {
            return Ok(());
        };
        let start = address as usize;
        let end = start
            .checked_add(length)
            .context("memory mapping address overflowed")?;
        lock(&self.mappings).push(MemoryMapping {
            start,
            end,
            file_offset: pending.file_offset,
            writable: pending.writable,
            open: pending.open,
        });
        Ok(())
    }

    fn register_potential_mapping(&self, mapping: &MemoryMapping) -> Result<()> {
        let end = mapping
            .file_offset
            .checked_add((mapping.end - mapping.start) as u64)
            .context("memory mapping file range overflowed")?;
        self.register_potential_range(&mapping.open, mapping.file_offset, end)
    }

    fn register_potential_range(&self, open: &OpenFile, start: u64, end: u64) -> Result<()> {
        let Some(registration) = &open.local else {
            return Ok(());
        };
        if !registration.writable {
            return Ok(());
        }
        let range = LocalByteRange::new(start, end)?;
        self.local
            .as_ref()
            .context("local filesystem runtime is unavailable")?
            .potentially_dirty(&registration.handle, range)?;
        Ok(())
    }

    fn mapping_slices(&self, start: usize, end: usize, writable_only: bool) -> Vec<MappingSlice> {
        lock(&self.mappings)
            .iter()
            .filter(|mapping| !writable_only || mapping.writable)
            .filter_map(|mapping| {
                let overlap_start = start.max(mapping.start);
                let overlap_end = end.min(mapping.end);
                (overlap_start < overlap_end).then(|| MappingSlice {
                    address: overlap_start,
                    length: overlap_end - overlap_start,
                    file_start: mapping.file_offset + (overlap_start - mapping.start) as u64,
                    file_end: mapping.file_offset + (overlap_end - mapping.start) as u64,
                    open: Arc::clone(&mapping.open),
                })
            })
            .collect()
    }

    fn mappings_becoming_writable(&self, start: usize, end: usize) -> Vec<MemoryMapping> {
        lock(&self.mappings)
            .iter()
            .filter(|mapping| !mapping.writable)
            .filter_map(|mapping| {
                let overlap_start = start.max(mapping.start);
                let overlap_end = end.min(mapping.end);
                (overlap_start < overlap_end).then(|| MemoryMapping {
                    start: overlap_start,
                    end: overlap_end,
                    file_offset: mapping.file_offset + (overlap_start - mapping.start) as u64,
                    writable: true,
                    open: Arc::clone(&mapping.open),
                })
            })
            .collect()
    }

    fn sync_mapping_slices(&self, slices: &[MappingSlice], durable: bool) -> Result<()> {
        let mut files: Vec<Arc<OpenFile>> = Vec::new();
        for slice in slices {
            if let Some(registration) = &slice.open.local
                && registration.writable
            {
                insert_dirty_range(
                    &mut lock(&registration.dirty),
                    LocalByteRange::new(slice.file_start, slice.file_end)?,
                );
            }
            if !files.iter().any(|open| Arc::ptr_eq(open, &slice.open)) {
                files.push(Arc::clone(&slice.open));
            }
        }
        for open in files {
            self.commit_open_file(-1, &open, durable)?;
        }
        Ok(())
    }

    fn flush_mapping_slices(&self, slices: &[MappingSlice], durable: bool) -> Result<()> {
        let msync = original_msync().context("msync is unavailable")?;
        for slice in slices {
            if unsafe {
                msync(
                    slice.address as *mut libc::c_void,
                    slice.length,
                    libc::MS_SYNC,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        self.sync_mapping_slices(slices, durable)
    }

    fn full_mapping_slices(&self, include: impl Fn(&MemoryMapping) -> bool) -> Vec<MappingSlice> {
        lock(&self.mappings)
            .iter()
            .filter(|mapping| mapping.writable && include(mapping))
            .map(|mapping| MappingSlice {
                address: mapping.start,
                length: mapping.end - mapping.start,
                file_start: mapping.file_offset,
                file_end: mapping.file_offset + (mapping.end - mapping.start) as u64,
                open: Arc::clone(&mapping.open),
            })
            .collect()
    }

    pub(super) fn flush_open_mappings(&self, open: &Arc<OpenFile>, durable: bool) -> Result<()> {
        let slices = self.full_mapping_slices(|mapping| Arc::ptr_eq(&mapping.open, open));
        self.flush_mapping_slices(&slices, durable)
    }

    pub(super) fn flush_logical_mappings(&self, logical: &Path, durable: bool) -> Result<()> {
        let mappings = lock(&self.mappings).clone();
        let slices = mappings
            .iter()
            .filter(|mapping| mapping.writable && mapping.open.logical() == logical)
            .map(|mapping| MappingSlice {
                address: mapping.start,
                length: mapping.end - mapping.start,
                file_start: mapping.file_offset,
                file_end: mapping.file_offset + (mapping.end - mapping.start) as u64,
                open: Arc::clone(&mapping.open),
            })
            .collect::<Vec<_>>();
        self.flush_mapping_slices(&slices, durable)
    }

    fn remove_mappings(&self, start: usize, end: usize) -> Vec<Arc<OpenFile>> {
        let mut mappings = lock(&self.mappings);
        let mut retained = Vec::with_capacity(mappings.len() + 1);
        let mut affected = Vec::new();
        for mapping in mappings.drain(..) {
            let overlap_start = start.max(mapping.start);
            let overlap_end = end.min(mapping.end);
            if overlap_start >= overlap_end {
                retained.push(mapping);
                continue;
            }
            if !affected.iter().any(|open| Arc::ptr_eq(open, &mapping.open)) {
                affected.push(Arc::clone(&mapping.open));
            }
            if mapping.start < overlap_start {
                retained.push(MemoryMapping {
                    end: overlap_start,
                    ..mapping.clone()
                });
            }
            if overlap_end < mapping.end {
                retained.push(MemoryMapping {
                    start: overlap_end,
                    file_offset: mapping.file_offset + (overlap_end - mapping.start) as u64,
                    ..mapping
                });
            }
        }
        *mappings = retained;
        affected
    }

    fn set_mapping_writable(&self, start: usize, end: usize, writable: bool) {
        let mut mappings = lock(&self.mappings);
        let mut updated = Vec::with_capacity(mappings.len() + 2);
        for mapping in mappings.drain(..) {
            let overlap_start = start.max(mapping.start);
            let overlap_end = end.min(mapping.end);
            if overlap_start >= overlap_end {
                updated.push(mapping);
                continue;
            }
            if mapping.start < overlap_start {
                updated.push(MemoryMapping {
                    end: overlap_start,
                    ..mapping.clone()
                });
            }
            let middle = MemoryMapping {
                start: overlap_start,
                end: overlap_end,
                file_offset: mapping.file_offset + (overlap_start - mapping.start) as u64,
                writable,
                open: Arc::clone(&mapping.open),
            };
            updated.push(middle);
            if overlap_end < mapping.end {
                updated.push(MemoryMapping {
                    start: overlap_end,
                    file_offset: mapping.file_offset + (overlap_end - mapping.start) as u64,
                    ..mapping
                });
            }
        }
        *mappings = updated;
    }

    pub(super) fn has_mapping(&self, open: &Arc<OpenFile>) -> bool {
        lock(&self.mappings)
            .iter()
            .any(|mapping| Arc::ptr_eq(&mapping.open, open))
    }

    fn has_descriptor(&self, open: &Arc<OpenFile>) -> bool {
        lock(&self.open_files)
            .values()
            .any(|candidate| Arc::ptr_eq(candidate, open))
    }

    fn finish_unreferenced(&self, opens: Vec<Arc<OpenFile>>) -> Result<()> {
        for open in opens {
            if !self.has_descriptor(&open) && !self.has_mapping(&open) {
                self.finish_open_file(-1, &open)?;
            }
        }
        Ok(())
    }

    pub(super) fn flush_memory_mappings(&self) -> Result<()> {
        let slices = self.full_mapping_slices(|_| true);
        self.flush_mapping_slices(&slices, true)
    }
}

unsafe fn sandbox_mmap(
    address: *mut libc::c_void,
    length: usize,
    protection: libc::c_int,
    flags: libc::c_int,
    descriptor: libc::c_int,
    offset: libc::off_t,
) -> *mut libc::c_void {
    catch_filesystem_panic(libc::MAP_FAILED, || {
        let Some(original) = original_mmap() else {
            unsafe { set_errno(libc::ENOSYS) };
            return libc::MAP_FAILED;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(address, length, protection, flags, descriptor, offset) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(address, length, protection, flags, descriptor, offset) };
        };
        let pending = match runtime.prepare_mapping(length, protection, flags, descriptor, offset) {
            Ok(pending) => pending,
            Err(error) => return unsafe { fail(&error, libc::MAP_FAILED) },
        };
        if flags & libc::MAP_FIXED != 0 {
            let Some(_) = (address as usize).checked_add(length) else {
                unsafe { set_errno(libc::EOVERFLOW) };
                return libc::MAP_FAILED;
            };
            if let Err(error) = sync_native_mappings(runtime, address as usize, length, true) {
                return unsafe { fail(&error, libc::MAP_FAILED) };
            }
        }
        let mapped = unsafe { original(address, length, protection, flags, descriptor, offset) };
        if mapped == libc::MAP_FAILED {
            return mapped;
        }
        let start = mapped as usize;
        let Some(end) = start.checked_add(length) else {
            if let Some(munmap) = original_munmap() {
                unsafe { munmap(mapped, length) };
            }
            unsafe { set_errno(libc::EOVERFLOW) };
            return libc::MAP_FAILED;
        };
        let replaced = if flags & libc::MAP_FIXED != 0 {
            runtime.remove_mappings(start, end)
        } else {
            Vec::new()
        };
        if let Err(error) = runtime.register_mapping(mapped, length, pending) {
            if let Some(munmap) = original_munmap() {
                unsafe { munmap(mapped, length) };
            }
            let _ = runtime.finish_unreferenced(replaced);
            return unsafe { fail(&error, libc::MAP_FAILED) };
        }
        let _ = runtime.finish_unreferenced(replaced);
        mapped
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_mmap(
    address: *mut libc::c_void,
    length: usize,
    protection: libc::c_int,
    flags: libc::c_int,
    descriptor: libc::c_int,
    offset: libc::off_t,
) -> *mut libc::c_void {
    unsafe { sandbox_mmap(address, length, protection, flags, descriptor, offset) }
}

unsafe fn sandbox_msync(
    address: *mut libc::c_void,
    length: usize,
    flags: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_msync() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(address, length, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(address, length, flags) };
        };
        let Some(end) = (address as usize).checked_add(length) else {
            unsafe { set_errno(libc::EOVERFLOW) };
            return -1;
        };
        let result = unsafe { original(address, length, flags) };
        if result != 0 {
            return result;
        }
        let slices = runtime.mapping_slices(address as usize, end, true);
        match runtime.sync_mapping_slices(&slices, flags & libc::MS_SYNC != 0) {
            Ok(()) => result,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_msync(
    address: *mut libc::c_void,
    length: usize,
    flags: libc::c_int,
) -> libc::c_int {
    unsafe { sandbox_msync(address, length, flags) }
}

unsafe fn sandbox_munmap(address: *mut libc::c_void, length: usize) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_munmap() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(address, length) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(address, length) };
        };
        let Some(end) = (address as usize).checked_add(length) else {
            unsafe { set_errno(libc::EOVERFLOW) };
            return -1;
        };
        if let Err(error) = sync_native_mappings(runtime, address as usize, length, true) {
            return unsafe { fail(&error, -1) };
        }
        let result = unsafe { original(address, length) };
        if result != 0 {
            return result;
        }
        let affected = runtime.remove_mappings(address as usize, end);
        let _ = runtime.finish_unreferenced(affected);
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_munmap(
    address: *mut libc::c_void,
    length: usize,
) -> libc::c_int {
    unsafe { sandbox_munmap(address, length) }
}

unsafe fn sandbox_mprotect(
    address: *mut libc::c_void,
    length: usize,
    protection: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_mprotect() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(address, length, protection) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(address, length, protection) };
        };
        let Some(end) = (address as usize).checked_add(length) else {
            unsafe { set_errno(libc::EOVERFLOW) };
            return -1;
        };
        if protection & libc::PROT_WRITE == 0
            && let Err(error) = sync_native_mappings(runtime, address as usize, length, true)
        {
            return unsafe { fail(&error, -1) };
        }
        if protection & libc::PROT_WRITE != 0 {
            for mapping in runtime.mappings_becoming_writable(address as usize, end) {
                if let Err(error) = runtime.register_potential_mapping(&mapping) {
                    return unsafe { fail(&error, -1) };
                }
            }
        }
        let result = unsafe { original(address, length, protection) };
        if result != 0 {
            return result;
        }
        let writable = protection & libc::PROT_WRITE != 0;
        runtime.set_mapping_writable(address as usize, end, writable);
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_mprotect(
    address: *mut libc::c_void,
    length: usize,
    protection: libc::c_int,
) -> libc::c_int {
    unsafe { sandbox_mprotect(address, length, protection) }
}

fn sync_native_mappings(
    runtime: &FilesystemHookRuntime,
    start: usize,
    length: usize,
    durable: bool,
) -> Result<()> {
    let end = start
        .checked_add(length)
        .context("memory mapping address overflowed")?;
    let slices = runtime.mapping_slices(start, end, true);
    runtime.flush_mapping_slices(&slices, durable)
}

fn original_mmap() -> Option<MmapFn> {
    function_from_interpose(&INTERPOSE_MMAP)
}

fn original_msync() -> Option<MemoryFlagsFn> {
    function_from_interpose(&INTERPOSE_MSYNC)
}

fn original_munmap() -> Option<MemoryFn> {
    function_from_interpose(&INTERPOSE_MUNMAP)
}

fn original_mprotect() -> Option<MemoryFlagsFn> {
    function_from_interpose(&INTERPOSE_MPROTECT)
}

dyld_interpose!(INTERPOSE_MMAP, agora_sandbox_mmap, libc::mmap);
dyld_interpose!(INTERPOSE_MSYNC, agora_sandbox_msync, libc::msync);
dyld_interpose!(INTERPOSE_MUNMAP, agora_sandbox_munmap, libc::munmap);
dyld_interpose!(INTERPOSE_MPROTECT, agora_sandbox_mprotect, libc::mprotect);

#[cfg(test)]
mod tests;
