#![cfg_attr(all(target_arch = "riscv64", not(feature = "abi-gen")), no_main, no_std)]

pub const POLICY_KEY: &[u8] = b"door.policy.v1";
pub const KEYS_KEY: &[u8] = b"door.named-keys.v1";
pub const POLICY_LEN: usize = 392;

#[pvm_contract_sdk::contract(allocator = "pico", allocator_size = 4096)]
pub mod door_keys {
    use pvm_contract_sdk::{HostApi, StorageFlags, U256};
    use super::{KEYS_KEY, POLICY_KEY, POLICY_LEN};

    pub struct DoorKeys;
    impl DoorKeys {
        /// The salt and commitments are public. No UID or pepper is passed in.
        #[pvm_contract_sdk::constructor]
        pub fn new(&mut self, salt: U256, alice: U256, bob: U256) {
            assert_ne!(salt, U256::ZERO);
            assert_ne!(alice, U256::ZERO);
            assert_ne!(bob, U256::ZERO);
            assert_ne!(alice, bob);
            let mut keys = [0u8; 64];
            keys[..32].copy_from_slice(&alice.to_be_bytes::<32>());
            keys[32..].copy_from_slice(&bob.to_be_bytes::<32>());
            self.host().set_storage(StorageFlags::empty(), KEYS_KEY, &keys);
            let mut policy = [0u8; POLICY_LEN];
            policy[..4].copy_from_slice(b"DOR1");
            policy[8..40].copy_from_slice(&salt.to_be_bytes::<32>());
            policy[40..72].copy_from_slice(&keys[..32]);
            self.write(&policy);
        }

        /// Public: choose Alice (0), Bob (1), both (2), or neither (3).
        #[pvm_contract_sdk::method]
        pub fn assign_key(&mut self, key: u32) {
            assert!(key < 4);
            let keys = self.keys();
            let mut policy = self.read();
            let mut selected = [0u8; POLICY_LEN - 40];
            match key {
                0 => selected[..32].copy_from_slice(&keys[..32]),
                1 => selected[..32].copy_from_slice(&keys[32..]),
                2 => selected[..64].copy_from_slice(&keys),
                _ => {},
            }
            if policy[40..] == selected { return; }
            let revision = u32::from_le_bytes(policy[4..8].try_into().unwrap());
            policy[4..8].copy_from_slice(&revision.checked_add(1).unwrap().to_le_bytes());
            policy[40..].copy_from_slice(&selected);
            self.write(&policy);
        }

        #[pvm_contract_sdk::method]
        pub fn assigned_key(&self) -> u32 {
            let policy = self.read();
            let keys = self.keys();
            if policy[40..104] == keys { 2 }
            else if policy[40..72] == keys[..32] { 0 }
            else if policy[40..72] == keys[32..] { 1 }
            else { 3 }
        }

        /// Bit 0 is Alice, bit 1 is Bob. Zero means neither key is enabled.
        #[pvm_contract_sdk::method]
        pub fn enabled_keys(&self) -> u32 {
            match self.assigned_key() { 0 => 1, 1 => 2, 2 => 3, _ => 0 }
        }

        /// Change only this key, preserving the other key's current chain state.
        #[pvm_contract_sdk::method]
        pub fn set_key_enabled(&mut self, key: u32, enabled: bool) {
            assert!(key < 2);
            let bit = 1 << key;
            let mask = if enabled { self.enabled_keys() | bit } else { self.enabled_keys() & !bit };
            self.assign_key(match mask { 1 => 0, 2 => 1, 3 => 2, _ => 3 });
        }

        #[pvm_contract_sdk::method]
        pub fn revision(&self) -> u32 {
            u32::from_le_bytes(self.read()[4..8].try_into().unwrap())
        }

        fn keys(&self) -> [u8; 64] {
            let mut bytes = [0u8; 64];
            let mut out = &mut bytes[..];
            assert!(self.host().get_storage(StorageFlags::empty(), KEYS_KEY, &mut out).is_ok());
            assert_eq!(out.len(), 64);
            bytes
        }
        fn read(&self) -> [u8; POLICY_LEN] {
            let mut bytes = [0u8; POLICY_LEN];
            let mut out = &mut bytes[..];
            assert!(self.host().get_storage(StorageFlags::empty(), POLICY_KEY, &mut out).is_ok());
            assert_eq!(out.len(), POLICY_LEN);
            bytes
        }
        fn write(&mut self, policy: &[u8; POLICY_LEN]) {
            self.host().set_storage(StorageFlags::empty(), POLICY_KEY, policy);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use door_keys::DoorKeys;
    use pvm_contract_sdk::{MockHostBuilder, U256};

    #[test]
    fn any_caller_can_switch_the_only_accepted_key() {
        let host = MockHostBuilder::new().caller([1;20]).build();
        let mut first = DoorKeys::with_host(host.clone());
        first.new(U256::from(123), U256::from(456), U256::from(789));
        assert_eq!(first.assigned_key(), 0);
        first.assign_key(1);
        assert_eq!(first.assigned_key(), 1);
        assert_eq!(first.revision(), 1);
        let state = host.get_raw_storage(POLICY_KEY).unwrap();
        assert_eq!(U256::from_be_slice(&state[40..72]), U256::from(789));
        assert!(state[72..].iter().all(|b| *b == 0));
        let other_host = MockHostBuilder::new().caller([2;20]).storage(vec![
            (POLICY_KEY.to_vec(), state), (KEYS_KEY.to_vec(), host.get_raw_storage(KEYS_KEY).unwrap())
        ]).build();
        let mut other = DoorKeys::with_host(other_host.clone());
        other.assign_key(0);
        assert_eq!(other.assigned_key(), 0);
        assert_eq!(other.revision(), 2);
        let state = other_host.get_raw_storage(POLICY_KEY).unwrap();
        assert_eq!(&state[..4], b"DOR1");
        assert_eq!(U256::from_be_slice(&state[8..40]), U256::from(123));
        assert_eq!(U256::from_be_slice(&state[40..72]), U256::from(456));
        assert!(state[72..].iter().all(|b| *b == 0));
        other.assign_key(0);
        assert_eq!(other.revision(), 2);
    }

    #[test]
    fn every_selection_transition_has_exact_keys_and_is_idempotent() {
        for initial in 0..4 {
            for target in 0..4 {
                let host = MockHostBuilder::new().build();
                let mut contract = DoorKeys::with_host(host.clone());
                contract.new(U256::from(123), U256::from(456), U256::from(789));
                contract.assign_key(initial);
                let revision = contract.revision();
                contract.assign_key(target);
                assert_eq!(contract.assigned_key(), target);
                assert_eq!(contract.revision(), revision + u32::from(initial != target));
                let state = host.get_raw_storage(POLICY_KEY).unwrap();
                assert_eq!(&state[..4], b"DOR1");
                assert_eq!(U256::from_be_slice(&state[8..40]), U256::from(123));
                assert_eq!(U256::from_be_slice(&state[40..72]), U256::from(if target == 1 { 789 } else if target == 3 { 0 } else { 456 }));
                assert_eq!(U256::from_be_slice(&state[72..104]), U256::from(if target == 2 { 789 } else { 0 }));
                assert!(state[104..].iter().all(|b| *b == 0));
                contract.assign_key(target);
                assert_eq!(host.get_raw_storage(POLICY_KEY).unwrap(), state);
            }
        }
    }

    #[test]
    fn independent_toggles_preserve_the_other_key_and_allow_neither() {
        for initial in 0..4 {
            for key in 0..2 {
                for enabled in [false, true] {
                    let host = MockHostBuilder::new().build();
                    let mut contract = DoorKeys::with_host(host.clone());
                    contract.new(U256::from(1), U256::from(2), U256::from(3));
                    contract.assign_key(initial);
                    let before = contract.enabled_keys();
                    let revision = contract.revision();
                    contract.set_key_enabled(key, enabled);
                    let expected = if enabled { before | (1 << key) } else { before & !(1 << key) };
                    assert_eq!(contract.enabled_keys(), expected);
                    assert_eq!(contract.revision(), revision + u32::from(before != expected));
                    let state = host.get_raw_storage(POLICY_KEY).unwrap();
                    contract.set_key_enabled(key, enabled);
                    assert_eq!(host.get_raw_storage(POLICY_KEY).unwrap(), state);
                    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| contract.set_key_enabled(2, true))).is_err());
                    assert_eq!(host.get_raw_storage(POLICY_KEY).unwrap(), state);
                }
            }
        }
    }

    #[test]
    fn rejects_unknown_key_without_changing_policy() {
        let host = MockHostBuilder::new().build();
        let mut contract = DoorKeys::with_host(host.clone());
        contract.new(U256::from(1), U256::from(2), U256::from(3));
        let before = host.get_raw_storage(POLICY_KEY).unwrap();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| contract.assign_key(4))).is_err());
        assert_eq!(host.get_raw_storage(POLICY_KEY).unwrap(), before);
    }
}
