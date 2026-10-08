#![cfg_attr(all(target_arch = "riscv64", not(feature = "abi-gen")), no_main, no_std)]

pub const STATE_KEY: &[u8] = b"door.toggle.v1";
pub const STATE_LEN: usize = 9;

#[pvm_contract_sdk::contract(allocator = "pico", allocator_size = 4096)]
pub mod door_toggle {
    use pvm_contract_sdk::{HostApi, StorageFlags};
    use super::{STATE_KEY, STATE_LEN};

    pub struct DoorToggle;
    impl DoorToggle {
        #[pvm_contract_sdk::constructor]
        pub fn new(&mut self) {
            let mut state = [0u8; STATE_LEN];
            state[..4].copy_from_slice(b"DOR2");
            self.write(&state);
        }

        /// Deliberately public: every caller can flip the shared door state.
        #[pvm_contract_sdk::method]
        pub fn toggle(&mut self) {
            let mut state = self.read();
            let revision = u32::from_le_bytes(state[4..8].try_into().unwrap());
            state[4..8].copy_from_slice(&revision.checked_add(1).unwrap().to_le_bytes());
            state[8] ^= 1;
            self.write(&state);
        }

        #[pvm_contract_sdk::method]
        pub fn is_open(&self) -> bool { self.read()[8] == 1 }

        #[pvm_contract_sdk::method]
        pub fn revision(&self) -> u32 {
            u32::from_le_bytes(self.read()[4..8].try_into().unwrap())
        }

        fn read(&self) -> [u8; STATE_LEN] {
            let mut bytes = [0u8; STATE_LEN];
            let mut out = &mut bytes[..];
            assert!(self.host().get_storage(StorageFlags::empty(), STATE_KEY, &mut out).is_ok());
            assert_eq!(out.len(), STATE_LEN);
            bytes
        }
        fn write(&mut self, state: &[u8; STATE_LEN]) {
            self.host().set_storage(StorageFlags::empty(), STATE_KEY, state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use door_toggle::DoorToggle;
    use pvm_contract_sdk::MockHostBuilder;

    #[test]
    fn different_callers_can_open_and_close() {
        let host = MockHostBuilder::new().caller([1;20]).build();
        let mut first = DoorToggle::with_host(host.clone());
        first.new();
        assert!(!first.is_open());
        assert_eq!(first.revision(), 0);
        first.toggle();
        assert!(first.is_open());
        let state = host.get_raw_storage(STATE_KEY).unwrap();
        assert_eq!(state, b"DOR2\x01\0\0\0\x01");
        let other_host = MockHostBuilder::new().caller([2;20])
            .storage(vec![(STATE_KEY.to_vec(), state)]).build();
        let mut other = DoorToggle::with_host(other_host);
        other.toggle();
        assert!(!other.is_open());
        assert_eq!(other.revision(), 2);
    }
}
