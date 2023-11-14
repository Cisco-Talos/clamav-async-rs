// Copyright (C) 2020-2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
// MA 02110-1301, USA.

use bitflags::bitflags;

bitflags! {
    #[repr(C)]
    #[derive(Default)]
    /// Bitfield representing attributes of a file layer encountered during file
    /// inspection
    pub struct LayerAttributes: u32 {
        /// Layer has been normalized
        const NORMALIZED = clamav_sys::LAYER_ATTRIBUTES_NORMALIZED;
        /// Layer was decrypted, or contained within another decrypted layer
        const DECRYPTED = clamav_sys::LAYER_ATTRIBUTES_DECRYPTED;
    }
}
