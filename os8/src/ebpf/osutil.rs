

// ! OS dependent part

use super::{
    map::*,
    map::MapAttr,
    map::MapOpAttr,
    retcode::BpfResult,
    tracepoints::KprobeAttachAttr,
    tracepoints::*,
    program::{bpf_program_load_ex, ProgramLoadExAttr, MapFdEntry},
};

use core::{mem::size_of, fmt::Write, iter::Map};

use alloc::sync::Arc;
use alloc::string::String;
use core::slice::{from_raw_parts, from_raw_parts_mut};
use downcast_rs::{impl_downcast, DowncastSync};

use crate::task::TaskControlBlock;

pub trait ThreadLike : DowncastSync {
    fn get_pid(&self) -> u64;
    fn get_tid(&self) -> u64;
    fn get_name(&self) -> String;
}

impl_downcast!(ThreadLike);

impl ThreadLike for TaskControlBlock {
    fn get_pid(&self) -> u64 {
        let proc = self.process.upgrade().unwrap();
        return proc.pid.0 as u64;
    }
    fn get_tid(&self) -> u64 {
        return 0; // no viable in rcore tutor
    }
    fn get_name(&self) -> String {
        return String::from("not viable in rcore tutorial")
    }
}

pub fn os_current_thread() -> Arc<dyn ThreadLike> {
    if let Some(thread) = crate::task::current_task() {
        thread
    } else {
        panic!("cannot get current thread!")
    }
}

pub fn os_current_time() -> u128 {
   crate::timer::get_time_us() as u128 * 1000
}

pub fn os_get_current_cpu() -> u8 {
   0 // not viable
}

pub fn os_console_write_str(s: &str) {
    crate::console::Stdout.write_str(s).unwrap();
}

pub fn os_copy_from_user(usr_addr: usize, kern_buf: *mut u8, len: usize) -> i32 {
    use crate::mm::translated_byte_buffer;
    use crate::task::current_user_token;
    let t = translated_byte_buffer(current_user_token(), usr_addr as *const u8, len);    
    copy(kern_buf, t[0].as_ptr() as *const u8, len);
    0
}
 
pub fn os_copy_to_user(usr_addr: usize, kern_buf: *const u8, len: usize) -> i32 {
    use crate::mm::translated_byte_buffer;
    use crate::task::current_user_token;
    let dst = translated_byte_buffer(current_user_token(), usr_addr as *const u8, len);
    let mut ptr = kern_buf;
    let mut total_len = len as i32;
    for seg in dst {
        let cur_len = seg.len();
        total_len -= cur_len as i32;
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, seg.as_mut_ptr(), cur_len);
            ptr = ptr.add(cur_len);   
        }
    }
    assert_eq!(total_len, 0);
    0
}

pub fn copy(dst: *mut u8, src: *const u8, len: usize) {
    let from = unsafe { from_raw_parts(src, len) };
    let to = unsafe { from_raw_parts_mut(dst, len) };
    to.copy_from_slice(from);
}

pub fn memcmp(u: *const u8, v: *const u8, len: usize) -> bool {
    return unsafe {
        from_raw_parts(u, len) == from_raw_parts(v, len)
    }
}

// dst is a vector of slice of u8, i.e. serveral non-overlapping continious memory
// src is a reference to a object<T> in kernel space, i.e. address is continious
// this scatter the memory of src to dst
pub unsafe fn scatter<T>(src: &T, dst: alloc::vec::Vec<&mut[u8]>) {
    
}


pub fn get_generic_from_user<T: Copy>(user_addr: usize) -> T {
    let size = size_of::<T>();
    let ret = vec![0 as u8; size];
    let buf = ret.as_ptr() as *const T;
    os_copy_from_user(user_addr as usize, buf as *mut u8, size_of::<T>());
    let attr = unsafe {
        *(buf as *const T)
    };
    attr
}

fn convert_result(result: BpfResult) -> i32 {
    warn!("result :{:?}", result);
    match result {
        Ok(val) => val as i32,
        Err(_) => -1,
    }
}

pub fn sys_bpf_map_create(attr: *const u8, size: usize) -> i32 {
   // assert_eq!(size as usize, size_of::<MapAttr>());
    info!("sys_bpf_map_create");
    let map_attr: MapAttr = get_generic_from_user(attr as usize);
    warn!("map create key:{}, value:{}", map_attr.key_size, map_attr.value_size);
    convert_result(bpf_map_create(map_attr))
}

pub fn sys_bpf_map_lookup_elem(attr: *const u8, size: usize) -> i32 {
   // assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr: MapOpAttr = get_generic_from_user(attr as usize);
    convert_result(bpf_map_lookup_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags))
}

pub fn sys_bpf_map_update_elem(attr: *const u8, size: usize) -> i32 {
    //assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr: MapOpAttr = get_generic_from_user(attr as usize);
    convert_result(bpf_map_update_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags))
}

pub fn sys_bpf_map_delete_elem(attr: *const u8, size: usize) -> i32 {
    //assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr: MapOpAttr = get_generic_from_user(attr as usize);
    convert_result(bpf_map_delete_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags))
}

pub fn sys_bpf_map_get_next_key(attr: *const u8, size: usize) -> i32 {
    let map_op_attr: MapOpAttr = get_generic_from_user(attr as usize);
    convert_result(bpf_map_get_next_key(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags))
}

pub fn sys_bpf_program_attach(attr: *const u8, size: usize) -> i32 {
  //  assert_eq!(size, size_of::<KprobeAttachAttr>());
    let attach_attr: KprobeAttachAttr = get_generic_from_user(attr as usize);
    let len = attach_attr.str_len as usize;
    let mut target_name_buf = vec![0 as u8; len];
    os_copy_from_user(attach_attr.target as usize, target_name_buf.as_mut_ptr(), len);
    let target_name = unsafe {
        core::str::from_utf8(
            target_name_buf.as_slice()
           // core::slice::from_raw_parts(attach_attr.target, attach_attr.str_len as usize)
        ).unwrap()
    };
    trace!("target name str: {}", target_name);
    convert_result(bpf_program_attach(target_name, attach_attr.prog_fd))
}


// this is a custome function, so we just copy from rCore
pub fn sys_bpf_program_load_ex(prog: &mut [u8], map_info: &[(String, u32)]) -> i32 {
    let ret = convert_result(bpf_program_load_ex(prog, &map_info));
    trace!("load ex ret: {}", ret);
    ret
}

#[allow(unused_mut)]
pub fn sys_preprocess_bpf_program_load_ex(attr_ptr: *const u8, size: usize) -> i32 {
    trace!("load program ex");

    let attr:ProgramLoadExAttr = get_generic_from_user(attr_ptr as usize);

    info!("prog attr\n prog_base:{:x} prog_size={} map_base:{:x} map_num={}", attr.elf_prog, attr.elf_size, attr.map_array as usize, attr.map_array_len);
    let base = attr.elf_prog as usize;
    let size = attr.elf_size as usize;
    let mut prog = vec![0 as u8; size];
    os_copy_from_user(base, prog.as_mut_ptr(), size);

    let arr_len = attr.map_array_len as usize;
    let arr_size = arr_len * core::mem::size_of::<MapFdEntry>();
    let mut map_fd_array = vec![0 as u8; arr_size];
    if arr_size > 0 {
        os_copy_from_user(attr.map_array as usize, map_fd_array.as_mut_ptr(), arr_size);
    }

    let mut map_info = alloc::vec::Vec::new();
    let start = map_fd_array.as_ptr() as *const MapFdEntry;
    for i in 0..arr_len {
        unsafe {
            let entry = &(*start.add(i));
            let name_ptr = entry.name;
            info!("name ptr {:x}", name_ptr as usize);
            let map_name = read_null_terminated_str(name_ptr);
            info!("insert map: {} fd: {}", map_name, entry.fd);
            map_info.push((map_name, entry.fd));            
        }   
    }

    sys_bpf_program_load_ex(&mut prog[..], &map_info[..])
}

unsafe fn read_null_terminated_str(mut ptr: *const u8) -> String {
    let mut ret = String::new();
    loop {
        let c: u8 = get_generic_from_user(ptr as usize);
        if c == 0 {
            break;
        }
        ret.push(c as char);
        ptr = ptr.add(1);
    }
    ret
}