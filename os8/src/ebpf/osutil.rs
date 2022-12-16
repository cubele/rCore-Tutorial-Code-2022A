

// ! OS dependent part

use super::{
    map::*,
    map::MapAttr,
    map::MapOpAttr,
    retcode::BpfResult,
    tracepoints::KprobeAttachAttr,
    tracepoints::*,
};

use core::{mem::size_of, fmt::Write};
use super::program::bpf_program_load_ex;

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
    copy(kern_buf, t.as_ptr() as *const u8, len);
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

fn convert_result(result: BpfResult) -> i32 {
    match result {
        Ok(val) => val as i32,
        Err(_) => -1,
    }
}

pub fn sys_bpf_map_create(attr: *const u8, size: usize) -> i32 {
   // assert_eq!(size as usize, size_of::<MapAttr>());
    info!("sys_bpf_map_create");
    let map_attr = unsafe {
        *(attr as *const MapAttr)
    };
    convert_result(bpf_map_create(map_attr))
}

pub fn sys_bpf_map_lookup_elem(attr: *const u8, size: usize) -> i32 {
   // assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr = unsafe {
        *(attr as *const MapOpAttr)
    };
    convert_result(bpf_map_lookup_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags))
}

pub fn sys_bpf_map_update_elem(attr: *const u8, size: usize) -> i32 {
    //assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr = unsafe {
        *(attr as *const MapOpAttr)
    };
    convert_result(bpf_map_update_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags))
}

pub fn sys_bpf_map_delete_elem(attr: *const u8, size: usize) -> i32 {
    //assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr = unsafe {
        *(attr as *const MapOpAttr)
    };
    convert_result(bpf_map_delete_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags))
}

pub fn sys_bpf_map_get_next_key(attr: *const u8, size: usize) -> i32 {
    let map_op_attr = unsafe {
        *(attr as *const MapOpAttr)
    };
    convert_result(bpf_map_get_next_key(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags))
}

pub fn sys_bpf_program_attach(attr: *const u8, size: usize) -> i32 {
  //  assert_eq!(size, size_of::<KprobeAttachAttr>());
    let attach_attr = unsafe {
        *(attr as *const KprobeAttachAttr)
    };
    let target_name = unsafe {
        core::str::from_utf8(
            core::slice::from_raw_parts(attach_attr.target, attach_attr.str_len as usize)
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