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
