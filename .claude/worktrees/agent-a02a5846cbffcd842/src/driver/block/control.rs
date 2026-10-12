//! A `/dev/<name>` control node for a block device: a thin [`Driver`] exposing geometry
//! and admin (`sync`, whole-device erase) through the standard device + ioctl + capability
//! machinery, so tooling and policy get a handle without the filesystem fast path going
//! near it. Data still flows through the [`BlockDevice`](super::BlockDevice) fast path; this
//! node is control-plane only (bulk reads/writes are not exposed here).
//!
//! Classification: L2 devices · block: /dev control node · safe · always

use super::{BlockDevice, MediaKind};
use crate::Error;
use crate::driver::ioctl;
use crate::driver::{DeviceClass, DeviceCtx, Driver, DriverInfo, IoResult, Middleware, Op, Request};

/// Control node wrapping a block device (register with `driver::register`).
pub struct BlockControl {
    dev: &'static dyn BlockDevice,
}

impl BlockControl {
    pub const fn new(dev: &'static dyn BlockDevice) -> Self {
        BlockControl { dev }
    }
}

impl Driver for BlockControl {
    fn info(&self) -> DriverInfo {
        DriverInfo { name: "block", class: DeviceClass::Block, version: (0, 1, 0), compatible: &[] }
    }

    fn middleware(&self) -> &'static [&'static dyn Middleware] {
        &[]
    }

    fn handle(&self, _ctx: &DeviceCtx, req: &mut Request<'_>) -> IoResult {
        let Op::Ioctl { cmd, .. } = &req.op else {
            return Err(Error::Unsupported); // control-plane only
        };
        let g = self.dev.geometry();
        let v = match *cmd {
            ioctl::GET_CLASS => DeviceClass::Block as usize,
            ioctl::BLOCK_GET_BLOCK_SIZE => g.block_size as usize,
            ioctl::BLOCK_GET_BLOCK_COUNT => g.block_count as usize,
            ioctl::BLOCK_GET_READ_SIZE => g.read_size as usize,
            ioctl::BLOCK_GET_PROG_SIZE => g.prog_size as usize,
            ioctl::BLOCK_GET_KIND => match g.kind {
                MediaKind::Flash { .. } => 0,
                MediaKind::Disk => 1,
                MediaKind::Ram => 2,
            },
            ioctl::BLOCK_SYNC => {
                self.dev.sync()?;
                0
            }
            ioctl::BLOCK_ERASE_ALL => {
                for b in 0..g.block_count {
                    self.dev.erase(b)?;
                }
                0
            }
            _ => return Err(Error::Unsupported),
        };
        Ok(v)
    }
}
