//! 16550A-compatible serial port (COM1) emulation.
//!
//! Handles I/O ports 0x3F8-0x3FF for bidirectional serial communication.
//! Used by the guest kernel's `console=ttyS0` for output and by a stdin
//! reader thread for input.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};

/// COM1 base port.
pub const COM1_PORT_BASE: u16 = 0x3F8;
/// Number of ports in the COM1 range.
pub const COM1_PORT_COUNT: u16 = 8;

/// 16550A serial port emulation.
pub struct Serial {
    // COM1 registers
    /// 0x3F8 - data register (also divisor latch low when DLAB set)
    data: u8,
    /// 0x3F9 - interrupt enable register (also divisor latch high when DLAB set)
    ier: u8,
    /// 0x3FA - interrupt identification register (read-only)
    iir: u8,
    /// 0x3FB - line control register
    lcr: u8,
    /// 0x3FC - modem control register
    mcr: u8,
    /// 0x3FD - line status register
    lsr: u8,
    /// 0x3FE - modem status register
    msr: u8,
    /// 0x3FF - scratch register
    scr: u8,

    /// Input buffer (stdin -> guest)
    input_buffer: VecDeque<u8>,

    /// Output buffer — flushed on newline or when full
    output_buffer: Vec<u8>,

    /// Whether DLAB (Divisor Latch Access Bit) is set (LCR bit 7)
    dlab: bool,
    /// Divisor latch low byte
    divisor_low: u8,
    /// Divisor latch high byte
    divisor_high: u8,

    /// Raw fd of an attached console socket (for `clone attach`).
    /// Serial output is tee'd to this fd when present.
    console_fd: Arc<Mutex<Option<i32>>>,
}

impl Serial {
    /// Create a new serial port with transmitter-empty status.
    pub fn new() -> Self {
        Self {
            data: 0,
            ier: 0,
            // IIR: bit 0 = 1 means no interrupt pending, bits 7:6 = 11 means FIFOs enabled
            iir: 0xC1,
            lcr: 0,
            mcr: 0,
            // LSR: bit 5 = THR empty, bit 6 = transmitter idle
            lsr: 0x60,
            msr: 0,
            scr: 0,
            input_buffer: VecDeque::new(),
            output_buffer: Vec::with_capacity(256),
            dlab: false,
            divisor_low: 0,
            divisor_high: 0,
            console_fd: Arc::new(Mutex::new(None)),
        }
    }

    /// Handle a read from a port in the COM1 range.
    /// `port_offset` is the offset from 0x3F8 (0-7).
    pub fn read(&mut self, port_offset: u16) -> u8 {
        match port_offset {
            0 => {
                // Data register / Divisor Latch Low
                if self.dlab {
                    self.divisor_low
                } else {
                    // Pop from input buffer
                    let byte = self.input_buffer.pop_front().unwrap_or(0);
                    // Update data-ready bit in LSR
                    if self.input_buffer.is_empty() {
                        self.lsr &= !0x01; // clear Data Ready
                    }
                    // Recalculate IIR (data-available interrupt clears when buffer empties)
                    self.update_iir();
                    byte
                }
            }
            1 => {
                // IER / Divisor Latch High
                if self.dlab {
                    self.divisor_high
                } else {
                    self.ier
                }
            }
            2 => {
                // IIR (read-only)
                let iir = self.iir;
                // Reading IIR clears the THR Empty interrupt (if that's what's pending)
                if iir & 0x0F == 0x02 {
                    self.update_iir();
                }
                iir
            }
            3 => {
                // LCR
                self.lcr
            }
            4 => {
                // MCR
                self.mcr
            }
            5 => {
                // LSR
                // Recompute dynamic bits
                let mut lsr = self.lsr;
                // Bit 0: Data Ready (input_buffer not empty)
                if !self.input_buffer.is_empty() {
                    lsr |= 0x01;
                } else {
                    lsr &= !0x01;
                }
                // Bits 5 and 6 are always set (THR empty, transmitter idle)
                lsr |= 0x60;
                lsr
            }
            6 => {
                // MSR
                self.msr
            }
            7 => {
                // Scratch register
                self.scr
            }
            _ => 0,
        }
    }

    /// Handle a write to a port in the COM1 range.
    /// `port_offset` is the offset from 0x3F8 (0-7).
    pub fn write(&mut self, port_offset: u16, value: u8) {
        match port_offset {
            0 => {
                // Data register / Divisor Latch Low
                if self.dlab {
                    self.divisor_low = value;
                } else {
                    // Buffer output, flush on newline or when buffer is full
                    self.output_buffer.push(value);
                    if value == b'\n' || self.output_buffer.len() >= 256 {
                        let _ = std::io::stdout().write_all(&self.output_buffer);
                        let _ = std::io::stdout().flush();
                        // Also write to attached console socket if present
                        if let Ok(guard) = self.console_fd.lock() {
                            if let Some(fd) = *guard {
                                unsafe {
                                    libc::write(
                                        fd,
                                        self.output_buffer.as_ptr() as *const libc::c_void,
                                        self.output_buffer.len(),
                                    );
                                }
                            }
                        }
                        self.output_buffer.clear();
                    }
                    // THR is immediately empty again — recalculate IIR so the
                    // 8250 driver gets a THR Empty interrupt for the next byte.
                    self.update_iir();
                }
            }
            1 => {
                // IER / Divisor Latch High
                if self.dlab {
                    self.divisor_high = value;
                } else {
                    // Real 16550A only uses IER bits 0-3; bits 4-7 are reserved
                    // and read as 0. The kernel's 8250 autoconfig probes bit 6
                    // (UART_IER_UUE) to detect XScale UARTs — if it sticks, the
                    // driver misidentifies us as XScale and uses wrong register
                    // offsets, breaking userspace serial I/O.
                    self.ier = value & 0x0F;
                    self.update_iir();
                }
            }
            2 => {
                // FCR (write-only, IIR is read-only at same offset)
                // If FIFO enable bit is set, update IIR to reflect FIFOs
                if value & 0x01 != 0 {
                    self.iir |= 0xC0; // FIFOs enabled
                } else {
                    self.iir &= !0xC0;
                }
            }
            3 => {
                // LCR
                self.lcr = value;
                self.dlab = (value & 0x80) != 0;
            }
            4 => {
                // MCR
                self.mcr = value;
            }
            5 => {
                // LSR (factory test, normally read-only, ignore writes)
            }
            6 => {
                // MSR (read-only, ignore writes)
            }
            7 => {
                // Scratch register
                self.scr = value;
            }
            _ => {}
        }
    }

    /// Enqueue a byte from stdin into the serial input buffer.
    pub fn enqueue_input(&mut self, byte: u8) {
        self.input_buffer.push_back(byte);
        // Set Data Ready bit in LSR
        self.lsr |= 0x01;
        // If Received Data Available interrupt is enabled, set IIR to indicate it
        if self.ier & 0x01 != 0 {
            self.update_iir();
        }
    }

    /// Check whether there is pending input data.
    pub fn has_pending_input(&self) -> bool {
        !self.input_buffer.is_empty()
    }

    /// Check if the guest has enabled the Received Data Available interrupt (IER bit 0).
    pub fn interrupt_enabled(&self) -> bool {
        self.ier & 0x01 != 0
    }

    /// Set or clear the console socket fd for `clone attach`.
    pub fn set_console_fd(&mut self, fd: Option<i32>) {
        if let Ok(mut guard) = self.console_fd.lock() {
            *guard = fd;
        }
    }

    /// Get a clone of the console_fd Arc for use in the console listener thread.
    pub fn console_fd_handle(&self) -> Arc<Mutex<Option<i32>>> {
        Arc::clone(&self.console_fd)
    }

    /// Flush any buffered output to stdout.
    pub fn flush_output(&mut self) {
        if !self.output_buffer.is_empty() {
            let _ = std::io::stdout().write_all(&self.output_buffer);
            let _ = std::io::stdout().flush();
            self.output_buffer.clear();
        }
    }

    /// Check if there is an interrupt pending (IIR bit 0 == 0 means pending).
    pub fn interrupt_pending(&self) -> bool {
        self.iir & 0x01 == 0
    }

    /// Recalculate the IIR based on pending interrupt conditions.
    /// Priority (highest first): Line Status > Received Data > THR Empty > Modem Status.
    fn update_iir(&mut self) {
        let fifo_bits = self.iir & 0xC0; // preserve FIFO enabled bits

        if self.ier & 0x01 != 0 && !self.input_buffer.is_empty() {
            // Received Data Available interrupt (IIR bits 3:1 = 010, bit 0 = 0 = pending)
            self.iir = fifo_bits | 0x04;
        } else if self.ier & 0x02 != 0 {
            // THR Empty interrupt (IIR bits 3:1 = 001, bit 0 = 0 = pending)
            self.iir = fifo_bits | 0x02;
        } else {
            // No interrupt pending (bit 0 = 1)
            self.iir = fifo_bits | 0x01;
        }
    }
}

/// RAII guard that saves terminal settings and restores them on drop.
pub struct RawModeGuard {
    #[cfg(unix)]
    original_termios: libc::termios,
}

impl RawModeGuard {
    /// Put the terminal into raw mode and return a guard that restores
    /// the original settings on drop.
    ///
    /// # Safety
    /// This modifies global terminal state. Only one guard should be
    /// active at a time.
    pub fn enter() -> Option<Self> {
        #[cfg(unix)]
        {
            let mut termios: libc::termios = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut termios) };
            if ret != 0 {
                tracing::warn!("tcgetattr failed, skipping raw mode");
                return None;
            }
            let original_termios = termios;
            unsafe {
                libc::cfmakeraw(&mut termios);
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &termios);
            }
            tracing::debug!("Terminal set to raw mode");
            Some(Self { original_termios })
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            unsafe {
                libc::tcsetattr(
                    libc::STDIN_FILENO,
                    libc::TCSANOW,
                    &self.original_termios,
                );
            }
            tracing::debug!("Terminal restored from raw mode");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_serial_transmitter_empty() {
        let mut serial = Serial::new();
        let lsr = serial.read(5);
        // THR empty (bit 5) and transmitter idle (bit 6) should be set
        assert_ne!(lsr & 0x60, 0);
    }

    #[test]
    fn test_enqueue_and_read_input() {
        let mut serial = Serial::new();
        serial.enqueue_input(b'A');
        assert!(serial.has_pending_input());

        // LSR should show data ready
        let lsr = serial.read(5);
        assert_ne!(lsr & 0x01, 0);

        // Read the byte
        let byte = serial.read(0);
        assert_eq!(byte, b'A');

        // Should be empty now
        assert!(!serial.has_pending_input());
    }

    #[test]
    fn test_dlab_mode() {
        let mut serial = Serial::new();
        // Set DLAB bit in LCR
        serial.write(3, 0x80);

        // Write divisor latch values
        serial.write(0, 0x01); // divisor low
        serial.write(1, 0x00); // divisor high

        // Read them back
        assert_eq!(serial.read(0), 0x01);
        assert_eq!(serial.read(1), 0x00);

        // Clear DLAB
        serial.write(3, 0x00);
    }

    #[test]
    fn test_scratch_register() {
        let mut serial = Serial::new();
        serial.write(7, 0x42);
        assert_eq!(serial.read(7), 0x42);
    }

    #[test]
    fn test_multiple_input_bytes() {
        let mut serial = Serial::new();
        serial.enqueue_input(b'H');
        serial.enqueue_input(b'i');

        assert_eq!(serial.read(0), b'H');
        assert!(serial.has_pending_input());
        assert_eq!(serial.read(0), b'i');
        assert!(!serial.has_pending_input());
    }

    #[test]
    fn test_read_empty_input_returns_zero() {
        let mut serial = Serial::new();
        assert_eq!(serial.read(0), 0);
    }
}
