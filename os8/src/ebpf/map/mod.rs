use lock::Mutex;
use alloc::sync::Arc;


use super::consts::*;
use super::retcode::{BpfResult, BpfErrorCode::*};
use super::*;
use super::osutil::{os_copy_from_user, os_copy_to_user, get_generic_from_user};
use self::internal::{InternalMapAttr, BpfMap};
use self::array::ArrayMap;
use self::hash::HashMap;
mod internal;
mod array;
mod hash;


pub type SharedBpfMap = Arc<Mutex<dyn BpfMap + Send + Sync>>;

// Used by BPF_MAP_CREATE
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MapAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

//  Used by BPF_MAP_*_ELEM and BPF_MAP_GET_NEXT_KEY commands 
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MapOpAttr {
    pub map_fd: u32,
    pub key: u64,
    pub value_or_nextkey: u64,
    pub flags: u64,
}

#[derive(Debug)]
pub enum BpfMapOp {
    LookUp,
    Update,
    Delete,
    GetNextKey,
}

pub fn bpf_map_create(attr: MapAttr) -> BpfResult {
    let internal_attr = InternalMapAttr::from(attr);
    match attr.map_type {
        BPF_MAP_TYPE_ARRAY => {
            // array index must have size of 4
            if internal_attr.key_size != 4 {
                return Err(EINVAL);
            }
            let map = ArrayMap::new(internal_attr);
            let shared_map = Arc::new(Mutex::new(map));
            let fd = bpf_allocate_fd();
            bpf_object_create_map(fd, shared_map);
            warn!("create array, fd:{:x}", fd);
            Ok(fd as usize)
        }
        BPF_MAP_TYPE_HASH => {
            let map = HashMap::new(internal_attr);
            let shared_map = Arc::new(Mutex::new(map));
            let fd = bpf_allocate_fd();
            bpf_object_create_map(fd, shared_map);
            warn!("create hash, fd:{:x}", fd);
            Ok(fd as usize)
        }
        _ => Err(EINVAL),
    }
}

pub fn bpf_map_close(fd: u32) -> BpfResult {
    bpf_object_remove(fd).map_or(Ok(0), |_| Err(ENOENT))
}

pub fn bpf_map_get_attr(fd: u32) -> Option<InternalMapAttr> {
    let bpf_objs = BPF_OBJECTS.lock();
    let obj = bpf_objs.get(&fd)?;
    let shared_map = obj.is_map()?;
    let attr = shared_map.lock().get_attr();
    Some(attr)
}

#[allow(unreachable_patterns)]
pub fn bpf_map_ops(fd: u32, op: BpfMapOp, key: *const u8, value: *mut u8, flags: u64) -> BpfResult {
    trace!("bpf map ops fd:{}, op:{:?} key:{:x} value:{:x}", fd, op, key as usize, value as usize);
    let bpf_objs = BPF_OBJECTS.lock();
    let obj = bpf_objs.get(&fd).ok_or(ENOENT)?;
    let shared_map = obj.is_map().ok_or(ENOENT)?;
    let mut map = shared_map.lock();
    let key_size = map.get_attr().key_size;
    let value_size = map.get_attr().value_size;

    let mut key_kern_buf = alloc::vec![0 as u8; key_size];
    let kptr = key_kern_buf.as_mut_ptr();
    os_copy_from_user(key as usize, kptr, key_size);


    let mut value_kern_buf = alloc::vec![0 as u8; value_size];
    let vptr = value_kern_buf.as_mut_ptr();

    trace!("bpf map op got shared map");
    match op {
        BpfMapOp::LookUp => {
            let ret = map.lookup(kptr, vptr);
            os_copy_to_user(value as usize, vptr, value_size);
            ret
        },
        BpfMapOp::Update => {
            os_copy_from_user(value as usize, vptr, value_size);
            let ret = map.update(kptr, vptr, flags);
            ret
        },
        BpfMapOp::Delete => map.delete(kptr),
        BpfMapOp::GetNextKey => {
            let ret = map.next_key(kptr, vptr);
            os_copy_to_user(value as usize, vptr, value_size);
            ret
        }
        _ => Err(EINVAL),
    }
}

pub fn bpf_map_lookup_elem(fd: u32, key: *const u8, value: *mut u8, flags: u64) -> BpfResult {
    bpf_map_ops(fd, BpfMapOp::LookUp, key, value, flags)   
}

pub fn bpf_map_update_elem(fd: u32, key: *const u8, value: *mut u8, flags: u64) -> BpfResult {
    bpf_map_ops(fd, BpfMapOp::Update, key, value, flags)   
}

pub fn bpf_map_delete_elem(fd: u32, key: *const u8, value: *mut u8, flags: u64) -> BpfResult {
    bpf_map_ops(fd, BpfMapOp::Delete, key, value, flags)   
}

pub fn bpf_map_get_next_key(fd: u32, key: *const u8, value: *mut u8, flags: u64) -> BpfResult {
    bpf_map_ops(fd, BpfMapOp::GetNextKey, key, value, flags)   
}

// pub fn bpf_map_lookup_helper(fd: u32, key: *const u8) -> BpfResult {
//     let bpf_objs = BPF_OBJECTS.lock();
//     let obj = bpf_objs.get(&fd).ok_or(ENOENT)?;
//     let shared_map = obj.is_map().ok_or(ENOENT)?;
//     let map = shared_map.lock();
//     map.lookup_helper(key)
// }



// pub fn bpf_map_update_elem();
