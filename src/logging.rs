use crate::hooks::{getRegionAddress, Region, InlineCtx};
use crate::libc::{c_char, free, strlen};
use core::fmt;
use core::fmt::Display;
use alloc::vec::Vec;
use snafu::Snafu;
use nnsdk::{
    diag::{GetBacktrace, GetSymbolName},
    ro::LookupSymbol,
    root::cxa_demangle,
};

#[cfg(feature = "std")]
use std::ffi::CStr;

extern "C" {
    fn skyline_tcp_send_raw(bytes: *const u8, usize: u64);
}

pub fn log(message: &str) {
    unsafe {
        skyline_tcp_send_raw(message.as_bytes().as_ptr(), message.as_bytes().len() as _);
    }
}

/// Prints to the standard output, with a newline. For use in no_std plugins.
#[macro_export]
macro_rules! println {
    () => {
        $crate::log();
    };
    ($($arg:tt)*) => {
        {
            use $crate::alloc::format;
            $crate::logging::log(&format!(
                $($arg)*
            ));
        }
    };
}

/**
    Format wrapper used for displaying a [`Sized`] type to hex with 8 byte rows

    Example usage:
    ```rust
    # use skyline::logging::HexDump;
    let val: u32 = 3;
    println!("Hexdump:\n {}", HexDump(&val));
    ```
*/
pub struct HexDump<'a, T: Sized>(pub &'a T);

impl<'a, T> Display for HexDump<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex_dump_value(f, self.0)
    }
}

pub fn hex_dump_ptr<T>(ptr: *const T) {
    println!("{}", HexDump(unsafe { &*(ptr as *const u8) }))
}

pub fn hex_dump_str(ptr: *const c_char) {
    let len = unsafe { strlen(ptr) };
    let addr = ptr as usize;

    println!("{}", StrDumper(ptr, addr..addr + len));
}

struct StrDumper(pub *const c_char, core::ops::Range<usize>);

impl fmt::Display for StrDumper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex_dump(f, self.0, Some(self.1.clone()))
    }
}

const CHUNK_SIZE: usize = 0x10;
const NUMBERING_HEX: &str = "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F ";
const NUMBERING_SEP: &str = "│";
const NUMBERING_ASCII: &str = " 0123456789ABCDEF";

#[cfg(not(feature = "std"))]
const LOG2_TAB: [usize; 64] = [
    63, 0, 58, 1, 59, 47, 53, 2, 60, 39, 48, 27, 54, 33, 42, 3, 61, 51, 37, 40, 49, 18, 28, 20, 55,
    30, 34, 11, 43, 14, 22, 4, 62, 57, 46, 52, 38, 26, 32, 41, 50, 36, 17, 19, 29, 10, 13, 21, 56,
    45, 25, 31, 35, 16, 9, 12, 44, 24, 15, 8, 23, 7, 6, 5,
];

#[cfg(not(feature = "std"))]
fn log2(mut value: usize) -> f64 {
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    value |= value >> 32;
    LOG2_TAB[((value - (value >> 1)) * 0x07EDD5E59A4E28C2) >> 58] as f64
}

#[cfg(feature = "std")]
fn log2(value: usize) -> f64 {
    (value as f64).log2()
}

fn hex_num_len(val: usize) -> usize {
    (log2(val) / log2(0x10)) as usize + 1
}

fn to_ascii_dots(x: u8) -> char {
    match x {
        0..=0x1F | 0x7F..=0xA0 | 0xAD => '.',
        x => x as char,
    }
}

fn dump_hex_line(
    f: &mut fmt::Formatter,
    line: &[u8],
    addr: usize,
    highlight: &core::ops::Range<usize>,
) -> fmt::Result {
    write!(f, "{:08X}", addr)?;
    for (j, half) in line.chunks(8).enumerate() {
        write!(f, " ")?;
        for (i, x) in half.iter().enumerate() {
            let addr = addr + i + (j * 8);
            if highlight.contains(&addr) {
                write!(f, "\x1b[7m")?; // set highlight
            }
            write!(f, "{:02X}", x)?;
            if !highlight.contains(&(addr + 1)) || (j == 1 && i == 7) {
                write!(f, "\x1b[0m")?; // reset colors
            }
            write!(f, " ")?;
        }
    }
    write!(f, "│ ")?;
    for (i, &x) in line.iter().enumerate() {
        if highlight.contains(&(addr + i)) {
            write!(f, "\x1b[7m")?; // set highlight
        }
        write!(f, "{}", to_ascii_dots(x))?;
        write!(f, "\x1b[0m")?; // reset colors
    }
    writeln!(f)
}

fn hex_dump_bytes(
    f: &mut fmt::Formatter,
    byte_slice: &[u8],
    start: usize,
    highlight: core::ops::Range<usize>,
) -> fmt::Result {
    let num_spaces = hex_num_len(start.saturating_add(CHUNK_SIZE * 6)) + 1;
    for _ in 0..num_spaces {
        write!(f, " ")?;
    }
    writeln!(f, "{}{}{}", NUMBERING_HEX, NUMBERING_SEP, NUMBERING_ASCII)?;
    for _ in 0..num_spaces {
        write!(f, " ")?;
    }
    for _ in 0..NUMBERING_HEX.len() {
        write!(f, "─")?;
    }
    write!(f, "┼")?;
    for _ in 0..NUMBERING_ASCII.len() {
        write!(f, "─")?;
    }
    writeln!(f)?;

    let lines = byte_slice
        .chunks(CHUNK_SIZE)
        .zip((0..).map(|x| (x * CHUNK_SIZE) + start));

    for (x, addr) in lines {
        dump_hex_line(f, x, addr, &highlight)?;
    }

    Ok(())
}

fn hex_dump<T>(
    f: &mut fmt::Formatter,
    addr: *const T,
    highlight: Option<core::ops::Range<usize>>,
) -> fmt::Result {
    let addr = addr as usize;
    let highlight = highlight.unwrap_or(addr..addr + 1);
    let aligned_addr = addr & !0xF;
    let start = aligned_addr.saturating_sub(CHUNK_SIZE * 3);
    let num_chunks = 7 + ((highlight.end - highlight.start) / CHUNK_SIZE);
    let byte_slice =
        unsafe { core::slice::from_raw_parts(start as *const u8, CHUNK_SIZE * num_chunks) };

    hex_dump_bytes(f, byte_slice, start, highlight)
}

fn hex_dump_value<T: Sized>(f: &mut fmt::Formatter, val: &T) -> fmt::Result {
    let addr = val as *const T as usize;
    let size = core::mem::size_of::<T>();
    hex_dump(f, val as *const _, Some(addr..addr + size))
}

#[cfg(feature = "std")]
pub fn print_stack_trace() {
    let addresses = &mut [0 as *const u8; 32];
    let addr_count = unsafe { GetBacktrace(addresses.as_mut_ptr(), 32) };

    for (idx, &addr) in addresses[0..addr_count].iter().enumerate() {
        if addr.is_null() {
            continue;
        }

        let name = &mut [0u8; 255];

        unsafe { GetSymbolName(name.as_mut_ptr(), name.len() as u64, addr as u64) };

        let mut symbol_addr = 0;
        unsafe { LookupSymbol(&mut symbol_addr, name.as_ptr()) };

        let mut result = 0;
        let demangled_symbol = unsafe { cxa_demangle(name.as_ptr(), 0 as _, 0 as _, &mut result) };

        let c_name;

        if result == 0 {
            c_name = unsafe {
                CStr::from_ptr(demangled_symbol as _)
                    .to_str()
                    .unwrap_or("None")
            };
        } else {
            c_name = unsafe {
                CStr::from_ptr(name.as_ptr() as _)
                    .to_str()
                    .unwrap_or("None")
            };
        }

        println!(
            "[{}] Address: {:x}, Symbol: {}+{:x}\n",
            idx,
            (symbol_addr as u64 - unsafe { getRegionAddress(Region::Text) as u64 } + 0x7100000000),
            c_name,
            addr as u64 - symbol_addr as u64
        );
        unsafe { free(demangled_symbol as _) };
    }
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StackFrame {
    pub previous_frame: *mut StackFrame,
    pub return_address: u64,
}

#[derive(Snafu, Debug, Clone, Copy)]
pub enum BacktraceError {
    #[snafu(display("The initial frame pointer is null"))]
    InitialFPNull,

    #[snafu(display("The backtrace is recursive and the frame pointer points to itself"))]
    RecursiveFramePointer,

    #[snafu(display("The backtrace is longer than the provided limit"))]
    BacktraceLimitReached
}

#[derive(Debug)]
pub struct BacktraceEntry {
    ptr: *mut StackFrame,
    frame: StackFrame,
}

impl BacktraceEntry {
    /// Creates a backtrace entry from a given stack frame pointer
    pub fn new(ptr: *mut StackFrame) -> Self {
        Self {
            ptr,
            frame: unsafe { *ptr }
        }
    }

    /// Gets the stack pointer of the previous frame.
    pub fn get_previous_stack_pointer(&self) -> *mut u8 {
        if self.ptr.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe {
                self.ptr.add(1) as *mut u8
            }
        }
    }
}

#[derive(Debug)]
pub struct Backtrace {
    pub current_frame: Option<BacktraceEntry>,
    pub current_lr: u64,
    pub backtrace: Vec<Result<BacktraceEntry, BacktraceError>>,
}

impl Backtrace {

    /// Builds a new stack backtrace based on the provided frame pointer and return address
    /// 
    /// # Arguments
    /// * `current_fp` - The pointer to the current stack frame
    /// * `current_lr` - The current return address
    /// * `limit` - The maximum number of stack frames to move back through
    /// 
    /// # Returns
    /// * `Ok(Backtrace)` - A successfully created backtrace
    /// * `Err(BacktraceError)` - A failed backtrace
    pub fn new(mut current_fp: *mut StackFrame, current_lr: u64, mut limit: usize) -> Result<Self, BacktraceError> {
        // If the frame pointer is null then we can't really generate a stack trace any more meaningful
        // than the provided lr, which the caller should already have
        if current_fp.is_null() {
            return Err(BacktraceError::InitialFPNull);
        }

        unsafe {
            let current_frame = *current_fp;

            // If the current stack frame's LR is not the same as what
            // was provided, we can assume that the backtrace is being generated in 
            // one of two contexts:
            // 1. The surrounding function does not make use of the frame pointer and does not
            //      push it, which usually means that they aren't calling any other functions
            //      You can see an example of this here: https://godbolt.org/z/Weza98z3q
            //      Here, `main` pushes the frame pointer, calls `something` which pushes the frame pointer
            //      which then calls `something2`, which uses the stack but doesn't push the frame pointer
            //      since it doesn't need to worry about any internal function calls messing up
            //      the x30 register (which is used as the return address)
            // 2. We are generating a backtrace before the function has changed the frame pointer
            let mut prev_fp;
            let start_frame = if current_frame.return_address != current_lr {
                prev_fp = core::ptr::null_mut();
                None
            } else {
                let entry = BacktraceEntry::new(current_fp);
                prev_fp = current_fp;
                current_fp = entry.frame.previous_frame;
                Some(BacktraceEntry::new(current_fp))
            };

            // count the current entry as one of our max count
            limit -= 1;

            // create our backtrace vector
            let mut entries = Vec::with_capacity(limit);

            while limit > 0 {
                // check if the frame pointer is null, if so we are done with the backtrace
                if current_fp.is_null() {
                    break;
                }
                
                // check if the previous frame pointer is equal to our current one
                // if so, we are going to be recursive so we might as well just end
                if prev_fp == current_fp {
                    entries.push(Err(BacktraceError::RecursiveFramePointer));
                    break;
                }

                let entry = BacktraceEntry::new(current_fp);

                // move forwards in the list
                prev_fp = current_fp;
                current_fp = entry.frame.previous_frame;

                // push current entry
                entries.push(Ok(entry));

                limit -= 1;
            }

            // if we reached our limit then we should push an error to reflect that
            if limit == 0 {
                entries.push(Err(BacktraceError::BacktraceLimitReached));
            }

            Ok(Self {
                current_frame: start_frame,
                current_lr,
                backtrace: entries
            })
        }
    }

    /// Builds a new callstack backtrace based on the [`InlineCtx`]
    /// 
    /// # Arguments
    /// * `ctx` - The inline hook context
    /// * `limit` - The maximum number of stack frames to move back through
    /// 
    /// # Returns
    /// * `Ok(Backtrace)` - A successfully created backtrace
    /// * `Err(BacktraceError)` - A failed backtrace
    pub fn new_from_inline_ctx(ctx: &InlineCtx, limit: usize) -> Result<Self, BacktraceError> {
        unsafe { Self::new(ctx.registers[29].x.as_ref() as *const u64 as _, ctx.registers[30].x.as_ref() as *const u64 as _, limit) }
    }

    pub fn iter(&self) -> impl Iterator<Item = Result<&BacktraceEntry, BacktraceError>> {
        self.backtrace.iter().map(|result| match result {
          Ok(entry) => Ok(entry),
          Err(e) => Err(*e)
        })
    }
}

#[macro_export]
macro_rules! get_backtrace {
    () => {
        get_backtrace!(32)
    };
    ($limit:expr) => {{
        let fp: *mut $crate::logging::StackFrame;
        let lr: u64;

        unsafe {
            core::arch::asm!(r#"
                mov {}, x29
                mov {}, x30
            "#, out(reg) fp, out(reg) lr);
        }

        $crate::logging::Backtrace::new(fp as _, lr, $limit)
    }}
}