#![cfg_attr(all(target_arch = "riscv64", not(feature = "abi-gen")), no_main, no_std)]

// A single bounded variable-key value lets a small client prove the entire
// policy atomically, without enumeration or trusting ABI query responses.
pub const POLICY_KEY: &[u8] = b"door.policy.v1";
pub const ADMIN_KEY: &[u8] = b"door.admin.v1";
pub const POLICY_LEN: usize = 392;
pub const MAX_KEYS: usize = 11;

#[pvm_contract_sdk::contract(allocator = "pico", allocator_size = 4096)]
pub mod door_policy {
    use pvm_contract_sdk::{Address, HostApi, StorageFlags, U256};
    use super::{ADMIN_KEY, MAX_KEYS, POLICY_KEY, POLICY_LEN};

    pub struct DoorPolicy;

    impl DoorPolicy {
        #[pvm_contract_sdk::constructor]
        pub fn new(&mut self) {
            let caller = self.env().caller();
            self.host().set_storage(StorageFlags::empty(), ADMIN_KEY, caller.as_ref());
            let mut policy = [0u8; POLICY_LEN];
            policy[..4].copy_from_slice(b"DOR1");
            self.write_policy(&policy);
        }

        #[pvm_contract_sdk::method]
        pub fn admin(&self) -> Address {
            let mut bytes = [0u8; 20];
            let mut out = &mut bytes[..];
            assert!(self.host().get_storage(StorageFlags::empty(), ADMIN_KEY, &mut out).is_ok());
            assert_eq!(out.len(), 20);
            Address::from(bytes)
        }

        /// Changing the salt revokes every key. The pepper never enters chain state.
        #[pvm_contract_sdk::method]
        pub fn configure_salt(&mut self, salt: U256) {
            self.require_admin();
            assert_ne!(salt, U256::ZERO);
            let mut policy = self.read_policy();
            policy[8..40].copy_from_slice(&salt.to_be_bytes::<32>());
            policy[40..].fill(0);
            self.bump(&mut policy);
            self.write_policy(&policy);
        }

        /// Zero revokes this slot. Other values are HMAC-SHA256 commitments.
        #[pvm_contract_sdk::method]
        pub fn set_key(&mut self, index: u32, digest: U256) {
            self.require_admin();
            assert!((index as usize) < MAX_KEYS);
            let mut policy = self.read_policy();
            assert!(policy[8..40].iter().any(|&b| b != 0));
            let start = 40 + index as usize * 32;
            policy[start..start + 32].copy_from_slice(&digest.to_be_bytes::<32>());
            self.bump(&mut policy);
            self.write_policy(&policy);
        }

        #[pvm_contract_sdk::method]
        pub fn key_at(&self, index: u32) -> U256 {
            assert!((index as usize) < MAX_KEYS);
            let policy = self.read_policy();
            U256::from_be_slice(&policy[40 + index as usize * 32..72 + index as usize * 32])
        }

        fn require_admin(&self) { assert_eq!(self.env().caller(), self.admin()); }
        fn read_policy(&self) -> [u8; POLICY_LEN] {
            let mut bytes = [0u8; POLICY_LEN];
            let mut out = &mut bytes[..];
            assert!(self.host().get_storage(StorageFlags::empty(), POLICY_KEY, &mut out).is_ok());
            assert_eq!(out.len(), POLICY_LEN);
            bytes
        }
        fn write_policy(&mut self, policy: &[u8; POLICY_LEN]) {
            self.host().set_storage(StorageFlags::empty(), POLICY_KEY, policy);
        }
        fn bump(&self, policy: &mut [u8; POLICY_LEN]) {
            let revision = u32::from_le_bytes(policy[4..8].try_into().unwrap());
            policy[4..8].copy_from_slice(&revision.checked_add(1).unwrap().to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pvm_contract_sdk::{MockHostBuilder, U256};
    use door_policy::DoorPolicy;

    #[test]
    fn grants_revokes_and_salt_rotation_clears_all_keys() {
        let host = MockHostBuilder::new().caller([1;20]).build();
        let mut contract = DoorPolicy::with_host(host.clone());
        contract.new();
        assert_eq!(contract.admin(), pvm_contract_sdk::Address::from([1;20]));
        contract.configure_salt(U256::from(123));
        contract.set_key(0, U256::from(456));
        assert_eq!(contract.key_at(0), U256::from(456));
        contract.set_key(0, U256::ZERO);
        assert_eq!(contract.key_at(0), U256::ZERO);
        contract.set_key(10, U256::from(789));
        contract.configure_salt(U256::from(124));
        assert_eq!(contract.key_at(10), U256::ZERO);
        let policy = host.get_raw_storage(POLICY_KEY).unwrap();
        assert_eq!(policy.len(), POLICY_LEN);
        assert_eq!(&policy[..8], b"DOR1\x05\0\0\0");
    }

    #[test]
    fn unauthorized_mutations_leave_policy_unchanged() {
        let host = MockHostBuilder::new().caller([2;20])
            .storage(vec![(ADMIN_KEY.to_vec(), vec![1;20]), (POLICY_KEY.to_vec(), vec![0;POLICY_LEN])]).build();
        let mut contract = DoorPolicy::with_host(host.clone());
        for salt in [false, true] {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if salt { contract.configure_salt(U256::from(1)); }
                else { contract.set_key(0, U256::from(1)); }
            })).is_err());
            assert_eq!(host.get_raw_storage(POLICY_KEY).unwrap(), vec![0;POLICY_LEN]);
        }
    }

    #[test]
    fn invalid_slot_and_unconfigured_salt_are_rejected() {
        let mut contract = DoorPolicy::with_host(MockHostBuilder::new().caller([1;20]).build());
        contract.new();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| contract.set_key(0, U256::from(1)))).is_err());
        contract.configure_salt(U256::from(1));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| contract.set_key(11, U256::from(1)))).is_err());
    }
}
