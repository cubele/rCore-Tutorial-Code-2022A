//! eBPF system call 
//!
//! - bpf(2)
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(unreachable_patterns)]

use super::*;
use alloc::string::String;

use crate::ebpf::program::MapFdEntry;
use crate::ebpf::{
    consts::BpfCommand,
    program::ProgramLoadExAttr,
    osutil::*,
};
use core::convert::TryFrom;
// use zircon_object::vm::{
//     VmObject
// };

unsafe fn read_null_terminated_str(mut ptr: *const u8) -> String {
    let mut ret = String::new();
    loop {
        let c = *ptr as char;
        if c == '\n' || c == '\0' {
            break;
        }
        ret.push(c);
        ptr = ptr.add(1);
    }
    ret
}


pub fn sys_bpf(cmd: isize, bpf_attr: usize , size: usize) -> isize {
    println!("sys bpf called");
    warn!("SYS_bpf cmd: {}, bpf_attr: {}, size: {}", cmd, bpf_attr, size);
    let ptr = bpf_attr as *const u8;
    let cmd = cmd as i32;
    if let Ok(bpf_cmd) = BpfCommand::try_from(cmd) {
        use BpfCommand::*;
        let ret = match bpf_cmd {
            BPF_MAP_CREATE => sys_bpf_map_create(ptr, size),
            BPF_MAP_LOOKUP_ELEM => sys_bpf_map_lookup_elem(ptr, size),
            BPF_MAP_UPDATE_ELEM => sys_bpf_map_update_elem(ptr, size),
            BPF_MAP_DELETE_ELEM => sys_bpf_map_delete_elem(ptr, size),
            BPF_MAP_GET_NEXT_KEY => sys_bpf_map_get_next_key(ptr, size),
            BPF_PROG_LOAD => todo!(),
            BPF_PROG_ATTACH => sys_bpf_program_attach(ptr, size),
            BPF_PROG_DETACH => todo!(),
            BPF_PROG_LOAD_EX => sys_temp_bpf_program_load_ex(ptr, size),
        };
        if ret < 0 {
            -1
        } else {
           ret as isize
        }
    } else {
        -1
    }
}

#[allow(unused_mut)]
fn sys_temp_bpf_program_load_ex(attr_ptr: *const u8, size: usize) -> i32 {
    //trace!("load program ex");
    // let ptr = UserInPtr::<ProgramLoadExAttr>::from(attr_ptr as usize);
    // let attr = ptr.read().unwrap();
    // // ELF relocatable object info
    // let base = attr.elf_prog as *mut u8;
    // let size = attr.elf_size as usize;
    // let vm = self.zircon_process().vmar();
    let mut prog = vec![0 as u8; size];
    // let buf = &mut prog[..];
    // let mut actual_read = vm.read_memory(base as usize, buf).unwrap();
    // assert_eq!(actual_read, size);

    // let arr_len = attr.map_array_len as usize;

    // let mut map_fd_array = vec![0 as u8; arr_len * core::mem::size_of::<MapFdEntry>()];
    // let buf = &mut map_fd_array[..];
    // actual_read = vm.read_memory(attr.map_array as usize, buf).unwrap();
    // assert_eq!(actual_read, arr_len * core::mem::size_of::<MapFdEntry>());


    let mut map_info = alloc::vec::Vec::new();
    // let start = buf.as_ptr() as *const MapFdEntry;
    // for i in 0..arr_len {
    //     unsafe {
    //         let entry = &(*start.add(i));
    //         let name_ptr = entry.name;
    //         let map_name = read_null_terminated_str(name_ptr);
    //         info!("insert map: {} fd: {}", map_name, entry.fd);
    //         map_info.push((map_name, entry.fd));            
    //     }   
    // }

    sys_bpf_program_load_ex(&mut prog[..], &map_info[..])
}
