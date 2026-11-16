use async_trait::async_trait;
use image::{AnimationDecoder, DynamicImage, codecs::gif::GifDecoder, imageops::FilterType};
use std::io::Cursor;
use std::time::Duration;

use crate::config::{self, UiLevel};
use crate::display::DisplayState;
use rayhunter::analysis::analyzer::EventType;

use log::{error, info};
use tokio::sync::mpsc::Receiver;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use include_dir::{Dir, include_dir};

/// The daemon's embedded UI images, so other display backends can reuse them
/// without re-declaring the directory.
static IMAGE_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/images/");

/// Fetch one embedded image by filename.
pub fn image_asset(name: &str) -> Option<&'static [u8]> {
    IMAGE_ASSETS.get_file(name).map(|f| f.contents())
}

const REFRESH_RATE: u64 = 1000; //how often in milliseconds to refresh the display

/// Floor on one pass of the UI loop in `Demo`, where the GIF supplies its own
/// frame timing. Only takes effect if the GIF produced no frames (a decode
/// failure returns immediately), which would otherwise spin the loop.
const DEMO_MIN_PERIOD: u64 = 100;

#[derive(Copy, Clone)]
pub struct Dimensions {
    pub height: u32,
    pub width: u32,
}

#[derive(Copy, Clone)]
pub enum LinePattern {
    Solid,
    Dashed, // _ _ _ _
    Dotted, // . . . .
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum Color {
    Red,
    Green,
    Blue,
    White,
    Black,
    Cyan,
    Yellow,
    Pink,
    Orange,
}

impl Color {
    pub(crate) fn rgb(self) -> (u8, u8, u8) {
        match self {
            Color::Red => (0xff, 0, 0),
            Color::Green => (0, 0xff, 0),
            Color::Blue => (0, 0, 0xff),
            Color::White => (0xff, 0xff, 0xff),
            Color::Black => (0, 0, 0),
            Color::Cyan => (0, 0xff, 0xff),
            Color::Yellow => (0xff, 0xff, 0),
            Color::Pink => (0xfe, 0x24, 0xff),
            Color::Orange => (0xff, 0xa5, 0),
        }
    }
}

/// Paint the status bar over the first `height` rows of a `width`-wide buffer.
///
/// Used both to draw the bar on its own and to composite it into an animation
/// frame before that frame is written. Compositing matters: writing the frame
/// and then the bar puts two separate images on the panel per frame, so the bar
/// is absent for part of every frame and visibly flickers.
fn paint_status_bar(
    buffer: &mut [(u8, u8, u8)],
    width: u32,
    height: u32,
    color: Color,
    pattern: LinePattern,
) {
    let rgb = color.rgb();
    for row in 0..height {
        for col in 0..width {
            let Some(px) = buffer.get_mut((row * width + col) as usize) else {
                return;
            };
            let should_draw = match pattern {
                LinePattern::Solid => true,
                LinePattern::Dashed => (col / 4) % 2 == 0, // 4 pixels on, 4 pixels off
                LinePattern::Dotted => col % 4 == 0,       // 1 pixel on, 3 pixels off
            };
            *px = if should_draw { rgb } else { (0, 0, 0) };
        }
    }
}

fn display_style_from_state(state: DisplayState, colorblind_mode: bool) -> (Color, LinePattern) {
    match state {
        DisplayState::Paused => (Color::White, LinePattern::Solid),
        DisplayState::Recording => {
            if colorblind_mode {
                (Color::Blue, LinePattern::Solid)
            } else {
                (Color::Green, LinePattern::Solid)
            }
        }
        DisplayState::WarningDetected { event_type } => match event_type {
            EventType::Informational => {
                if colorblind_mode {
                    (Color::Blue, LinePattern::Solid)
                } else {
                    (Color::Green, LinePattern::Solid)
                }
            }
            EventType::Low => (Color::Yellow, LinePattern::Dotted),
            EventType::Medium => (Color::Orange, LinePattern::Dashed),
            EventType::High => (Color::Red, LinePattern::Solid),
        },
    }
}

#[async_trait]
pub trait GenericFramebuffer: Send + 'static {
    fn dimensions(&self) -> Dimensions;

    async fn write_buffer(&mut self, buffer: Vec<(u8, u8, u8)>); // rgb, row-wise, left-to-right, top-to-bottom

    /// Scale and position an image into a pixel buffer, without writing it.
    ///
    /// Split out from [`Self::write_dynamic_image`] so that animation frames can
    /// be prepared once and replayed, rather than resampled on every pass.
    /// Backends that lay an image out differently (centring it, padding to the
    /// full display) override this rather than the writing half.
    fn prepare_image(&self, img: DynamicImage) -> Vec<(u8, u8, u8)> {
        let dimensions = self.dimensions();
        let mut width = img.width();
        let mut height = img.height();
        let resized_img: DynamicImage;
        if height > dimensions.height || width > dimensions.width {
            resized_img = img.resize(dimensions.width, dimensions.height, FilterType::CatmullRom);
            width = dimensions.width.min(resized_img.width());
            height = dimensions.height.min(resized_img.height());
        } else {
            resized_img = img;
        }
        let img_rgba8 = resized_img.to_rgba8();
        let mut buf = Vec::with_capacity((height * width) as usize);
        for y in 0..height {
            for x in 0..width {
                let px = img_rgba8.get_pixel(x, y);
                buf.push((px[0], px[1], px[2]));
            }
        }
        buf
    }

    async fn write_dynamic_image(&mut self, img: DynamicImage) {
        let buf = self.prepare_image(img);
        self.write_buffer(buf).await
    }

    async fn draw_img(&mut self, img_buffer: &[u8]) {
        let img = image::load_from_memory(img_buffer).unwrap();
        self.write_dynamic_image(img).await
    }

    async fn draw_line(&mut self, color: Color, height: u32) {
        self.draw_patterned_line(color, height, LinePattern::Solid)
            .await
    }

    async fn draw_patterned_line(&mut self, color: Color, height: u32, pattern: LinePattern) {
        let width = self.dimensions().width;
        let mut buffer = vec![(0, 0, 0); (height * width) as usize];
        paint_status_bar(&mut buffer, width, height, color, pattern);
        self.write_buffer(buffer).await
    }
}

pub fn update_ui(
    task_tracker: &TaskTracker,
    config: &config::Config,
    mut fb: impl GenericFramebuffer,
    shutdown_token: CancellationToken,
    mut ui_update_rx: Receiver<DisplayState>,
) {
    static IMAGE_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/images/");
    let display_level = config.ui_level;
    if display_level == UiLevel::Invisible {
        info!("Invisible mode, not spawning UI.");
        return;
    }

    let colorblind_mode = config.colorblind_mode;
    let mut display_style = display_style_from_state(DisplayState::Recording, colorblind_mode);

    task_tracker.spawn(async move {
        // this feels wrong, is there a more rusty way to do this?
        let mut img: Option<&[u8]> = None;
        if display_level == UiLevel::Demo {
            img = Some(
                IMAGE_DIR
                    .get_file("orca.gif")
                    .expect("failed to read orca.gif")
                    .contents(),
            );
        } else if display_level == UiLevel::EffLogo {
            img = Some(
                IMAGE_DIR
                    .get_file("eff.png")
                    .expect("failed to read eff.png")
                    .contents(),
            );
        }
        // Decode the GIF once. `draw_gif` re-decoded it on every pass -- ten
        // frames of LZW plus a full frame collection, roughly twice a second --
        // which dominated CPU on a single-core device.
        let gif_frames: Vec<(Vec<(u8, u8, u8)>, u64)> = match img {
            Some(buf) if display_level == UiLevel::Demo => {
                match GifDecoder::new(Cursor::new(buf)) {
                    Ok(decoder) => decoder
                        .into_frames()
                        .filter_map(|f| f.ok())
                        .map(|frame| {
                            let (numerator, _) = frame.delay().numer_denom_ms();
                            let img = DynamicImage::from(frame.into_buffer());
                            // Scale once here, not on every pass: the frames
                            // never change, and resampling them ~17 times a
                            // second dominated CPU on a single-core device.
                            (fb.prepare_image(img), numerator as u64)
                        })
                        .collect(),
                    Err(e) => {
                        error!("failed to decode the demo gif: {e}");
                        Vec::new()
                    }
                }
            }
            _ => Vec::new(),
        };

        loop {
            let pass_started = tokio::time::Instant::now();
            if shutdown_token.is_cancelled() {
                info!("received UI shutdown");
                break;
            }
            match ui_update_rx.try_recv() {
                Ok(state) => {
                    display_style = display_style_from_state(state, colorblind_mode);
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                Err(e) => error!("error receiving framebuffer update message: {e}"),
            }

            let mut status_bar_height = 2;
            let (color, pattern) = display_style;
            match display_level {
                // Redraw the status bar after every frame. With the animation
                // running back to back, a bar drawn once per loop is painted
                // over by the next frame almost immediately, which reduces the
                // warning indicator to a flicker a few milliseconds long.
                UiLevel::Demo => {
                    let width = fb.dimensions().width;
                    for (frame, delay_ms) in &gif_frames {
                        let mut buf = frame.clone();
                        paint_status_bar(&mut buf, width, status_bar_height, color, pattern);
                        fb.write_buffer(buf).await;
                        tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
                    }
                }
                UiLevel::EffLogo => fb.draw_img(img.unwrap()).await,
                UiLevel::HighVisibility => {
                    status_bar_height = fb.dimensions().height;
                }
                UiLevel::TransFlag => {
                    fb.draw_line(Color::Cyan, 128).await;
                    fb.draw_line(Color::Pink, 102).await;
                    fb.draw_line(Color::White, 76).await;
                    fb.draw_line(Color::Pink, 50).await;
                    fb.draw_line(Color::Cyan, 25).await;
                }
                // UiLevel::Subtle (1) and anything else: just the status bar line
                _ => {}
            };
            // At `Demo` the bar is already composited into every frame; drawing
            // it again would reintroduce the second write that compositing
            // exists to avoid.
            if display_level != UiLevel::Demo {
                fb.draw_patterned_line(color, status_bar_height, pattern)
                    .await;
            }

            // Treat the delay as a period rather than a gap. `Demo` paces itself
            // through the GIF's own inter-frame delays, so adding REFRESH_RATE on
            // top of that is dead air: the animation plays, then freezes for a
            // second before looping. Every other level draws a single static
            // frame and still wants the full refresh delay.
            let target = Duration::from_millis(if display_level == UiLevel::Demo {
                DEMO_MIN_PERIOD
            } else {
                REFRESH_RATE
            });
            if let Some(remaining) = target.checked_sub(pass_started.elapsed()) {
                tokio::time::sleep(remaining).await;
            }
        }
    });
}
