use std::fmt;

use crate::frame::{util, Error, Frame, FrameSize, Head, Kind, StreamId};
use crate::tracing;
use bytes::{BufMut, BytesMut};
use smallvec::SmallVec;

define_enum_with_values! {
    /// An enum that lists all valid settings that can be sent in a SETTINGS
    /// frame.
    ///
    /// Each setting has a value that is a 32 bit unsigned integer (6.5.1.).
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9113#name-defined-settings>.
    @U16
    pub enum SettingId {
        /// This setting allows the sender to inform the remote endpoint
        /// of the maximum size of the compression table used to decode field blocks,
        /// in units of octets. The encoder can select any size equal to or less than
        /// this value by using signaling specific to the compression format inside
        /// a field block (see [COMPRESSION]). The initial value is 4,096 octets.
        ///
        /// [COMPRESSION]: <https://datatracker.ietf.org/doc/html/rfc7541>
        HeaderTableSize => 0x0001,

        /// Enables or disables server push.
        EnablePush => 0x0002,

        /// Specifies the maximum number of concurrent streams.
        MaxConcurrentStreams => 0x0003,

        /// Sets the initial stream-level flow control window size.
        InitialWindowSize => 0x0004,

        /// Indicates the largest acceptable frame payload size.
        MaxFrameSize => 0x0005,

        /// Advises the peer of the max field section size.
        MaxHeaderListSize => 0x0006,

        /// Enables support for the Extended CONNECT protocol.
        EnableConnectProtocol => 0x0008,

        /// Disable RFC 7540 Stream Priorities.
        /// [RFC 9218]: <https://www.rfc-editor.org/rfc/rfc9218.html#section-2.1>
        NoRfc7540Priorities => 0x0009,
    }
}

/// Represents the order of settings in a SETTINGS frame.
///
/// This structure maintains an ordered list of `SettingId` values for use when encoding or decoding
/// HTTP/2 SETTINGS frames. The order of settings can be important for protocol compliance, testing,
/// or interoperability. `SettingsOrder` ensures that the specified order is preserved and that no
/// duplicate settings are present.
///
/// Typically, a `SettingsOrder` is constructed using the [`SettingsOrderBuilder`] to enforce uniqueness
/// and protocol-compliant ordering.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct SettingsOrder {
    ids: SmallVec<[SettingId; SettingId::DEFAULT_STACK_SIZE]>,
}

/// A builder for constructing a `SettingsOrder`.
#[derive(Debug)]
pub struct SettingsOrderBuilder {
    ids: SmallVec<[SettingId; SettingId::DEFAULT_STACK_SIZE]>,
    mask: u16,
}

// ===== impl SettingsOrder =====

impl SettingsOrder {
    /// Creates a new [`SettingsOrderBuilder`].
    #[inline]
    pub fn builder() -> SettingsOrderBuilder {
        SettingsOrderBuilder {
            ids: SmallVec::new(),
            mask: 0,
        }
    }
}

impl Default for SettingsOrder {
    #[inline]
    fn default() -> Self {
        SettingsOrder {
            ids: SmallVec::from(SettingId::DEFAULT_IDS),
        }
    }
}

impl<'a> IntoIterator for &'a SettingsOrder {
    type Item = &'a SettingId;
    type IntoIter = std::slice::Iter<'a, SettingId>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.ids.iter()
    }
}

// ===== impl SettingsOrderBuilder =====

impl SettingsOrderBuilder {
    pub fn push(mut self, id: SettingId) -> Self {
        let mask_id = id.mask_id();
        if mask_id != 0 {
            if self.mask & mask_id == 0 {
                self.mask |= mask_id;
                self.ids.push(id);
            } else {
                tracing::trace!("duplicate setting ID ignored: {id:?}");
            }
        }
        self
    }

    pub fn extend(mut self, iter: impl IntoIterator<Item = SettingId>) -> Self {
        for id in iter {
            self = self.push(id);
        }
        self
    }

    pub fn build(mut self) -> SettingsOrder {
        self = self.extend(SettingId::DEFAULT_IDS);
        SettingsOrder { ids: self.ids }
    }
}

/// Extends the `Settings` struct to include experimental settings.
///
/// `ExperimentalSettings` is used to represent a collection of non-standard or extension HTTP/2 settings,
/// specifically those with unknown setting IDs (i.e., not defined in the RFC).
/// Any setting with a standard (known) ID will be ignored and not included in this collection.
/// This allows for safe experimentation and extension without interfering with standard settings.
#[cfg(feature = "unstable")]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ExperimentalSettings {
    settings: SmallVec<[Setting; SettingId::DEFAULT_STACK_SIZE]>,
}

/// A builder for constructing `ExperimentalSettings`.
#[cfg(feature = "unstable")]
#[derive(Debug)]
pub struct ExperimentalSettingsBuilder {
    settings: SmallVec<[Setting; SettingId::DEFAULT_STACK_SIZE]>,
    mask: u16,
}

// ===== impl ExperimentalSettings =====

#[cfg(feature = "unstable")]
impl ExperimentalSettings {
    pub fn builder() -> ExperimentalSettingsBuilder {
        ExperimentalSettingsBuilder {
            settings: SmallVec::new(),
            mask: 0,
        }
    }
}

#[cfg(feature = "unstable")]
impl<'a> IntoIterator for &'a ExperimentalSettings {
    type Item = &'a Setting;
    type IntoIter = std::slice::Iter<'a, Setting>;

    fn into_iter(self) -> Self::IntoIter {
        self.settings.iter()
    }
}

// ===== impl ExperimentalSettingsBuilder =====

#[cfg(feature = "unstable")]
impl ExperimentalSettingsBuilder {
    pub fn push<S>(mut self, setting: S) -> Self
    where
        S: Into<Option<Setting>>,
    {
        let setting = setting.into();
        let Some(setting) = setting else {
            return self;
        };

        // Only insert if this unknown setting ID has not been seen before (deduplication)
        if let SettingId::Unknown(id) = setting.id {
            if matches!(SettingId::from(id), SettingId::Unknown(_)) {
                let mask_id = setting.id.mask_id();
                if mask_id != 0 {
                    if self.mask & mask_id == 0 {
                        self.mask |= mask_id;
                        self.settings.push(setting);
                    } else {
                        tracing::trace!("duplicate unknown setting ID ignored: {id:?}");
                    }
                }
            }
        }

        self
    }

    pub fn extend<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<Option<Setting>>,
    {
        for setting in iter.into_iter() {
            self = self.push(setting);
        }
        self
    }

    pub fn build(self) -> ExperimentalSettings {
        ExperimentalSettings {
            settings: self.settings,
        }
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct Settings {
    flags: SettingsFlags,
    // Fields
    header_table_size: Option<u32>,
    enable_push: Option<u32>,
    max_concurrent_streams: Option<u32>,
    initial_window_size: Option<u32>,
    max_frame_size: Option<u32>,
    max_header_list_size: Option<u32>,
    enable_connect_protocol: Option<u32>,
    no_rfc7540_priorities: Option<u32>,
    #[cfg(feature = "unstable")]
    experimental_settings: Option<ExperimentalSettings>,
    // Settings order
    settings_order: SettingsOrder,
}

/// A struct representing a single HTTP/2 setting that can be sent in a SETTINGS
/// frame.
///
/// Each setting consists of an identifier and a value, where the value is a 32-bit unsigned integer (see RFC 7540, section 6.5.1).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Setting {
    id: SettingId,
    value: u32,
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub struct SettingsFlags(u8);

const ACK: u8 = 0x1;
const ALL: u8 = ACK;

/// The default value of SETTINGS_HEADER_TABLE_SIZE
pub const DEFAULT_SETTINGS_HEADER_TABLE_SIZE: usize = 4_096;

/// The default value of SETTINGS_INITIAL_WINDOW_SIZE
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// The default value of MAX_FRAME_SIZE
pub const DEFAULT_MAX_FRAME_SIZE: FrameSize = 16_384;

/// INITIAL_WINDOW_SIZE upper bound
pub const MAX_INITIAL_WINDOW_SIZE: usize = (1 << 31) - 1;

/// MAX_FRAME_SIZE upper bound
pub const MAX_MAX_FRAME_SIZE: FrameSize = (1 << 24) - 1;

// ===== impl Settings =====

impl Settings {
    pub fn ack() -> Settings {
        Settings {
            flags: SettingsFlags::ack(),
            ..Settings::default()
        }
    }

    pub fn is_ack(&self) -> bool {
        self.flags.is_ack()
    }

    pub fn initial_window_size(&self) -> Option<u32> {
        self.initial_window_size
    }

    pub fn set_initial_window_size(&mut self, size: Option<u32>) {
        self.initial_window_size = size;
    }

    pub fn max_concurrent_streams(&self) -> Option<u32> {
        self.max_concurrent_streams
    }

    pub fn set_max_concurrent_streams(&mut self, max: Option<u32>) {
        self.max_concurrent_streams = max;
    }

    pub fn max_frame_size(&self) -> Option<u32> {
        self.max_frame_size
    }

    pub fn set_max_frame_size(&mut self, size: Option<u32>) {
        if let Some(val) = size {
            assert!(DEFAULT_MAX_FRAME_SIZE <= val && val <= MAX_MAX_FRAME_SIZE);
        }
        self.max_frame_size = size;
    }

    pub fn max_header_list_size(&self) -> Option<u32> {
        self.max_header_list_size
    }

    pub fn set_max_header_list_size(&mut self, size: Option<u32>) {
        self.max_header_list_size = size;
    }

    pub fn is_push_enabled(&self) -> Option<bool> {
        self.enable_push.map(|val| val != 0)
    }

    pub fn set_enable_push(&mut self, enable: bool) {
        self.enable_push = Some(enable as u32);
    }

    pub fn is_extended_connect_protocol_enabled(&self) -> Option<bool> {
        self.enable_connect_protocol.map(|val| val != 0)
    }

    pub fn set_enable_connect_protocol(&mut self, val: Option<u32>) {
        self.enable_connect_protocol = val;
    }

    pub fn header_table_size(&self) -> Option<u32> {
        self.header_table_size
    }

    pub fn set_header_table_size(&mut self, size: Option<u32>) {
        self.header_table_size = size;
    }

    pub fn set_no_rfc7540_priorities(&mut self, enable: bool) {
        self.no_rfc7540_priorities = Some(enable as u32);
    }

    #[cfg(feature = "unstable")]
    pub fn set_experimental_settings(&mut self, experimental_settings: ExperimentalSettings) {
        self.experimental_settings = Some(experimental_settings)
    }

    pub fn set_settings_order(&mut self, settings_order: SettingsOrder) {
        self.settings_order = settings_order;
    }

    pub fn load(head: Head, payload: &[u8]) -> Result<Settings, Error> {
        debug_assert_eq!(head.kind(), crate::frame::Kind::Settings);

        if !head.stream_id().is_zero() {
            return Err(Error::InvalidStreamId);
        }

        // Load the flag
        let flag = SettingsFlags::load(head.flag());

        if flag.is_ack() {
            // Ensure that the payload is empty
            if !payload.is_empty() {
                return Err(Error::InvalidPayloadLength);
            }

            // Return the ACK frame
            return Ok(Settings::ack());
        }

        // Ensure the payload length is correct, each setting is 6 bytes long.
        if payload.len() % 6 != 0 {
            tracing::debug!("invalid settings payload length; len={:?}", payload.len());
            return Err(Error::InvalidPayloadAckSettings);
        }

        let mut settings = Settings::default();
        debug_assert!(!settings.flags.is_ack());

        for raw in payload.chunks(6) {
            if let Some(setting) = Setting::load(raw) {
                match setting.id {
                    SettingId::HeaderTableSize => {
                        settings.header_table_size = Some(setting.value);
                    }
                    SettingId::EnablePush => match setting.value {
                        0 | 1 => {
                            settings.enable_push = Some(setting.value);
                        }
                        _ => {
                            return Err(Error::InvalidSettingValue);
                        }
                    },
                    SettingId::MaxConcurrentStreams => {
                        settings.max_concurrent_streams = Some(setting.value);
                    }
                    SettingId::InitialWindowSize => {
                        if setting.value as usize > MAX_INITIAL_WINDOW_SIZE {
                            return Err(Error::InvalidSettingValue);
                        } else {
                            settings.initial_window_size = Some(setting.value);
                        }
                    }
                    SettingId::MaxFrameSize => {
                        if DEFAULT_MAX_FRAME_SIZE <= setting.value
                            && setting.value <= MAX_MAX_FRAME_SIZE
                        {
                            settings.max_frame_size = Some(setting.value);
                        } else {
                            return Err(Error::InvalidSettingValue);
                        }
                    }
                    SettingId::MaxHeaderListSize => {
                        settings.max_header_list_size = Some(setting.value);
                    }
                    SettingId::EnableConnectProtocol => match setting.value {
                        0 | 1 => {
                            settings.enable_connect_protocol = Some(setting.value);
                        }
                        _ => {
                            return Err(Error::InvalidSettingValue);
                        }
                    },
                    SettingId::NoRfc7540Priorities => match setting.value {
                        0 | 1 => {
                            settings.no_rfc7540_priorities = Some(setting.value);
                        }
                        _ => {
                            return Err(Error::InvalidSettingValue);
                        }
                    },
                    SettingId::Unknown(_) => {
                        // ignore unknown settings
                    }
                }
            }
        }

        Ok(settings)
    }

    fn payload_len(&self) -> usize {
        let mut len = 0;
        self.for_each(|_| len += 6);
        len
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        // Create & encode an appropriate frame head
        let head = Head::new(Kind::Settings, self.flags.into(), StreamId::zero());
        let payload_len = self.payload_len();

        tracing::trace!("encoding SETTINGS; len={}", payload_len);

        head.encode(payload_len, dst);

        // Encode the settings
        self.for_each(|setting| {
            tracing::trace!("encoding setting; val={:?}", setting);
            setting.encode(dst)
        });
    }

    fn for_each<F: FnMut(Setting)>(&self, mut f: F) {
        for id in &self.settings_order {
            match id {
                SettingId::HeaderTableSize => {
                    if let Some(v) = self.header_table_size {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::EnablePush => {
                    if let Some(v) = self.enable_push {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::MaxConcurrentStreams => {
                    if let Some(v) = self.max_concurrent_streams {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::InitialWindowSize => {
                    if let Some(v) = self.initial_window_size {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::MaxFrameSize => {
                    if let Some(v) = self.max_frame_size {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::MaxHeaderListSize => {
                    if let Some(v) = self.max_header_list_size {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::EnableConnectProtocol => {
                    if let Some(v) = self.enable_connect_protocol {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::NoRfc7540Priorities => {
                    if let Some(v) = self.no_rfc7540_priorities {
                        if let Some(setting) = Setting::from_id(*id, v) {
                            f(setting);
                        }
                    }
                }
                SettingId::Unknown(_id) => {
                    #[cfg(feature = "unstable")]
                    if let Some(ref unknown_settings) = self.experimental_settings {
                        if let Some(setting) = unknown_settings
                            .into_iter()
                            .find(|setting| setting.id == SettingId::Unknown(*_id))
                        {
                            f(setting.clone());
                        }
                    }
                }
            }
        }
    }
}

impl<T> From<Settings> for Frame<T> {
    fn from(src: Settings) -> Frame<T> {
        Frame::Settings(src)
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("Settings");
        builder.field("flags", &self.flags);

        self.for_each(|setting| match setting.id {
            SettingId::EnablePush => {
                builder.field("enable_push", &setting.value);
            }
            SettingId::HeaderTableSize => {
                builder.field("header_table_size", &setting.value);
            }
            SettingId::InitialWindowSize => {
                builder.field("initial_window_size", &setting.value);
            }
            SettingId::MaxConcurrentStreams => {
                builder.field("max_concurrent_streams", &setting.value);
            }
            SettingId::MaxFrameSize => {
                builder.field("max_frame_size", &setting.value);
            }
            SettingId::MaxHeaderListSize => {
                builder.field("max_header_list_size", &setting.value);
            }
            SettingId::EnableConnectProtocol => {
                builder.field("enable_connect_protocol", &setting.value);
            }
            SettingId::NoRfc7540Priorities => {
                builder.field("no_rfc7540_priorities", &setting.value);
            }
            SettingId::Unknown(id) => {
                builder.field("unknown", &format!("id={id:?}, val={}", setting.value));
            }
        });

        builder.finish()
    }
}

// ===== impl Setting =====

impl Setting {
    /// Creates a new `Setting` with the correct variant corresponding to the
    /// given setting id, based on the settings IDs defined in section
    /// 6.5.2.
    pub fn from_id(id: impl Into<SettingId>, value: u32) -> Option<Setting> {
        let id = id.into();
        if let SettingId::Unknown(id) = id {
            if id == 0 || id > SettingId::MAX_ID {
                tracing::debug!("limiting unknown setting id to 0..{}", SettingId::MAX_ID);
                return None;
            }
        }

        Some(Setting { id, value })
    }

    /// Creates a new `Setting` by parsing the given buffer of 6 bytes, which
    /// contains the raw byte representation of the setting, according to the
    /// "SETTINGS format" defined in section 6.5.1.
    ///
    /// The `raw` parameter should have length at least 6 bytes, since the
    /// length of the raw setting is exactly 6 bytes.
    ///
    /// # Panics
    ///
    /// If given a buffer shorter than 6 bytes, the function will panic.
    fn load(raw: &[u8]) -> Option<Setting> {
        let id: u16 = (u16::from(raw[0]) << 8) | u16::from(raw[1]);
        let val: u32 = unpack_octets_4!(raw, 2, u32);

        Setting::from_id(id, val)
    }

    fn encode(&self, dst: &mut BytesMut) {
        let kind = u16::from(self.id);
        let val = self.value;

        dst.put_u16(kind);
        dst.put_u32(val);
    }
}

// ===== impl SettingsFlags =====

impl SettingsFlags {
    pub fn empty() -> SettingsFlags {
        SettingsFlags(0)
    }

    pub fn load(bits: u8) -> SettingsFlags {
        SettingsFlags(bits & ALL)
    }

    pub fn ack() -> SettingsFlags {
        SettingsFlags(ACK)
    }

    pub fn is_ack(&self) -> bool {
        self.0 & ACK == ACK
    }
}

impl From<SettingsFlags> for u8 {
    fn from(src: SettingsFlags) -> u8 {
        src.0
    }
}

impl fmt::Debug for SettingsFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        util::debug_flags(f, self.0)
            .flag_if(self.is_ack(), "ACK")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_order() {
        let order = SettingsOrder::builder().build();
        assert!(!order.ids.is_empty());
        assert_eq!(order.ids.len(), SettingId::DEFAULT_IDS.len());
        assert_eq!(order.ids.as_slice(), SettingId::DEFAULT_IDS);

        let expected_order = [
            SettingId::HeaderTableSize,
            SettingId::EnablePush,
            SettingId::MaxConcurrentStreams,
            SettingId::InitialWindowSize,
            SettingId::MaxFrameSize,
            SettingId::MaxHeaderListSize,
            SettingId::NoRfc7540Priorities,
            SettingId::EnableConnectProtocol,
        ];

        let order = SettingsOrder::builder().extend(expected_order).build();
        assert_eq!(order.ids.len(), expected_order.len());
        assert_eq!(order.ids.as_slice(), expected_order);
    }

    #[test]
    fn test_settings_order_duplicate() {
        let order = SettingsOrder::builder()
            .push(SettingId::HeaderTableSize)
            .push(SettingId::HeaderTableSize)
            .build();

        assert_eq!(order.ids.len(), SettingId::DEFAULT_IDS.len());
        assert_eq!(order.ids[0], SettingId::HeaderTableSize);
        assert_ne!(order.ids[1], SettingId::HeaderTableSize);
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn test_experimental_settings_builder() {
        // ignore id > SettingId::MAX_ID
        assert!(SettingId::MAX_ID < 16);

        let unknown = ExperimentalSettings::builder()
            .extend(vec![
                Setting::from_id(SettingId::Unknown(16), 42),
                Setting::from_id(SettingId::Unknown(16), 84),
            ])
            .build();

        assert_eq!(unknown.settings.len(), 0);

        let unknown = ExperimentalSettings::builder()
            .push(Setting::from_id(SettingId::Unknown(15), 42))
            .push(Setting::from_id(SettingId::Unknown(14), 84))
            // will ignore the duplicate
            .push(Setting::from_id(SettingId::Unknown(14), 84))
            .build();

        assert_eq!(unknown.settings.len(), 2);

        // ignore non-unknown settings
        let unknown = ExperimentalSettings::builder()
            .push(Setting::from_id(SettingId::HeaderTableSize, 42))
            .push(Setting::from_id(SettingId::Unknown(15), 84))
            .build();
        assert_eq!(unknown.settings.len(), 1);
    }
}
