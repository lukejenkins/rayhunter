use crate::config;
use crate::display::DisplayState;
use crate::display::generic_framebuffer::{self, Dimensions, GenericFramebuffer};
use async_trait::async_trait;
use log::{info, warn};
use std::os::fd::AsRawFd;

use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const FB_PATH: &str = "/dev/fb0";

const FBIOGET_VSCREENINFO: u32 = 0x4600;
const FBIOGET_FSCREENINFO: u32 = 0x4602;

// The RC400L panel. Used whenever the kernel's geometry can't be read or isn't 16bpp.
const FALLBACK_GEOMETRY: Geometry = Geometry {
    width: 128,
    height: 128,
    line_length: 128 * 2,
};

#[repr(C)]
#[derive(Default)]
struct FbBitfield {
    offset: u32,
    length: u32,
    msb_right: u32,
}

// struct fb_var_screeninfo from linux/fb.h
#[repr(C)]
#[derive(Default)]
struct FbVarScreeninfo {
    xres: u32,
    yres: u32,
    xres_virtual: u32,
    yres_virtual: u32,
    xoffset: u32,
    yoffset: u32,
    bits_per_pixel: u32,
    grayscale: u32,
    red: FbBitfield,
    green: FbBitfield,
    blue: FbBitfield,
    transp: FbBitfield,
    nonstd: u32,
    activate: u32,
    height: u32,
    width: u32,
    accel_flags: u32,
    pixclock: u32,
    left_margin: u32,
    right_margin: u32,
    upper_margin: u32,
    lower_margin: u32,
    hsync_len: u32,
    vsync_len: u32,
    sync: u32,
    vmode: u32,
    rotate: u32,
    colorspace: u32,
    reserved: [u32; 4],
}

// struct fb_fix_screeninfo from linux/fb.h
#[repr(C)]
#[derive(Default)]
struct FbFixScreeninfo {
    id: [u8; 16],
    smem_start: libc::c_ulong,
    smem_len: u32,
    type_: u32,
    type_aux: u32,
    visual: u32,
    xpanstep: u16,
    ypanstep: u16,
    ywrapstep: u16,
    line_length: u32,
    mmio_start: libc::c_ulong,
    mmio_len: u32,
    accel: u32,
    capabilities: u16,
    reserved: [u16; 2],
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct Geometry {
    width: u32,
    height: u32,
    // bytes from the start of one row to the start of the next
    line_length: u32,
}

impl Geometry {
    // Only RGB565 is supported, and a row must fit in its line.
    fn from_screeninfo(
        xres: u32,
        yres: u32,
        bits_per_pixel: u32,
        line_length: u32,
    ) -> Option<Self> {
        if bits_per_pixel != 16 || xres == 0 || yres == 0 || line_length < xres * 2 {
            return None;
        }
        Some(Geometry {
            width: xres,
            height: yres,
            line_length,
        })
    }

    fn query() -> Option<Self> {
        let file = std::fs::File::open(FB_PATH).ok()?;
        let mut var = FbVarScreeninfo::default();
        let mut fix = FbFixScreeninfo::default();
        unsafe {
            if libc::ioctl(
                file.as_raw_fd(),
                FBIOGET_VSCREENINFO as _,
                &mut var as *mut _,
            ) < 0
            {
                return None;
            }
            if libc::ioctl(
                file.as_raw_fd(),
                FBIOGET_FSCREENINFO as _,
                &mut fix as *mut _,
            ) < 0
            {
                return None;
            }
        }
        Geometry::from_screeninfo(var.xres, var.yres, var.bits_per_pixel, fix.line_length)
    }

    fn detect() -> Self {
        match Geometry::query() {
            Some(geometry) => {
                info!(
                    "framebuffer is {}x{}, {} bytes per line",
                    geometry.width, geometry.height, geometry.line_length
                );
                geometry
            }
            None => {
                warn!("couldn't read a 16bpp framebuffer geometry, assuming 128x128");
                FALLBACK_GEOMETRY
            }
        }
    }
}

// Packs rows of `geometry.width` pixels as little-endian RGB565, each row starting
// `geometry.line_length` bytes after the previous one.
fn pack_rgb565(buffer: &[(u8, u8, u8)], geometry: Geometry) -> Vec<u8> {
    let width = geometry.width as usize;
    let padding = geometry.line_length as usize - width * 2;
    let rows = buffer.len().div_ceil(width);
    let mut raw_buffer = Vec::with_capacity(rows * geometry.line_length as usize);
    for (i, row) in buffer.chunks(width).enumerate() {
        if i > 0 {
            raw_buffer.resize(raw_buffer.len() + padding, 0);
        }
        for &(r, g, b) in row {
            let mut rgb565: u16 = (r as u16 & 0b11111000) << 8;
            rgb565 |= (g as u16 & 0b11111100) << 3;
            rgb565 |= (b as u16) >> 3;
            raw_buffer.extend(rgb565.to_le_bytes());
        }
    }
    raw_buffer
}

#[derive(Copy, Clone)]
struct Framebuffer {
    geometry: Geometry,
}

#[async_trait]
impl GenericFramebuffer for Framebuffer {
    fn dimensions(&self) -> Dimensions {
        Dimensions {
            height: self.geometry.height,
            width: self.geometry.width,
        }
    }

    async fn write_buffer(&mut self, buffer: Vec<(u8, u8, u8)>) {
        let raw_buffer = pack_rgb565(&buffer, self.geometry);
        tokio::fs::write(FB_PATH, &raw_buffer).await.unwrap();
    }
}

pub fn update_ui(
    task_tracker: &TaskTracker,
    config: &config::Config,
    shutdown_token: CancellationToken,
    ui_update_rx: Receiver<DisplayState>,
) {
    let framebuffer = Framebuffer {
        geometry: Geometry::detect(),
    };
    generic_framebuffer::update_ui(
        task_tracker,
        config,
        framebuffer,
        shutdown_token,
        ui_update_rx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const GREEN: (u8, u8, u8) = (0, 0xff, 0);
    const RED: (u8, u8, u8) = (0xff, 0, 0);

    #[test]
    fn screeninfo_structs_match_the_kernel_layout() {
        assert_eq!(std::mem::size_of::<FbVarScreeninfo>(), 160);
        let ulong = std::mem::size_of::<libc::c_ulong>();
        assert_eq!(
            std::mem::size_of::<FbFixScreeninfo>(),
            if ulong == 4 { 68 } else { 80 }
        );
        assert_eq!(
            std::mem::offset_of!(FbFixScreeninfo, line_length),
            28 + ulong + 12
        );
    }

    #[test]
    fn geometry_accepts_rgb565() {
        // Orbic R500L5: ST7789V panel, 320x240, 640-byte stride
        assert_eq!(
            Geometry::from_screeninfo(320, 240, 16, 640),
            Some(Geometry {
                width: 320,
                height: 240,
                line_length: 640
            })
        );
    }

    #[test]
    fn geometry_rejects_what_it_cant_draw() {
        assert_eq!(Geometry::from_screeninfo(320, 240, 32, 1280), None);
        assert_eq!(Geometry::from_screeninfo(0, 240, 16, 640), None);
        assert_eq!(Geometry::from_screeninfo(320, 0, 16, 640), None);
        assert_eq!(Geometry::from_screeninfo(320, 240, 16, 600), None);
    }

    #[test]
    fn fallback_is_the_old_fixed_layout() {
        let raw = pack_rgb565(&[GREEN; 128 * 2], FALLBACK_GEOMETRY);
        assert_eq!(raw.len(), 128 * 2 * 2);
        assert!(raw.chunks(2).all(|px| px == [0xe0, 0x07]));
    }

    #[test]
    fn rows_start_at_the_line_length() {
        let geometry = Geometry {
            width: 2,
            height: 2,
            line_length: 8,
        };
        let raw = pack_rgb565(&[GREEN, RED, RED, GREEN], geometry);
        assert_eq!(
            raw,
            vec![0xe0, 0x07, 0x00, 0xf8, 0, 0, 0, 0, 0x00, 0xf8, 0xe0, 0x07]
        );
    }

    #[test]
    fn a_short_last_row_is_not_padded() {
        let geometry = Geometry {
            width: 2,
            height: 2,
            line_length: 6,
        };
        let raw = pack_rgb565(&[GREEN, GREEN, RED], geometry);
        assert_eq!(raw, vec![0xe0, 0x07, 0xe0, 0x07, 0, 0, 0x00, 0xf8]);
    }
}
