// src/AliasCBU.cairo — Cairo 2.6.x compatible
#[starknet::contract]
mod alias_cbu {
    // ==== imports básicos ====
    use core::panic_with_felt252;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::{Map, StoragePathEntry};

    // ==== constantes de política ====
    const MIN_LEN: u32 = 4;
    const MAX_LEN: u32 = 20;

    // sentinelas (0 = vacío)
    const ZERO_FELT: felt252 = 0;

    // ==== interfaz (resolver) ====
    #[starknet::interface]
    pub trait IAliasResolver<TContractState> {
        fn addr_of_alias(self: @TContractState, alias_key: felt252) -> ContractAddress;
        fn alias_of_addr(self: @TContractState, who: ContractAddress) -> felt252;
        fn is_available(self: @TContractState, alias_key: felt252) -> bool;
        fn get_owner(self: @TContractState) -> ContractAddress;
        fn get_fee_token(self: @TContractState) -> ContractAddress;
        fn get_fee_amount(self: @TContractState) -> u256;
        fn get_len_bounds(self: @TContractState) -> (u32, u32);
    }

    // ==== eventos ====
    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        AliasRegistered: AliasRegistered,
        AliasUpdated: AliasUpdated,
        AliasRemoved: AliasRemoved,
        OwnershipTransferred: OwnershipTransferred,
        FeeConfigUpdated: FeeConfigUpdated,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AliasRegistered {
        pub alias_key: felt252,
        pub who: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AliasUpdated {
        pub alias_key: felt252,
        pub who: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AliasRemoved {
        pub alias_key: felt252,
        pub who: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OwnershipTransferred {
        pub previous_owner: ContractAddress,
        pub new_owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct FeeConfigUpdated {
        pub token: ContractAddress,
        pub amount: u256,
    }

    // ==== storage con Map (reemplaza LegacyMap) ====
    #[storage]
    struct Storage {
        // alias_key -> address (0 = libre)
        alias_to_addr: Map<felt252, ContractAddress>,
        // address (felt) -> alias_key (0 = sin alias)
        addr_to_alias: Map<felt252, felt252>,
        // owner/admin
        owner: ContractAddress,
        // cobro informativo en AIC (para UX)
        fee_token: ContractAddress,
        fee_amount: u256,
    }

    // helper para convertir ContractAddress <-> felt
    fn addr_to_felt(addr: ContractAddress) -> felt252 {
        addr.into()
    }

    fn felt_to_addr(x: felt252) -> ContractAddress {
        x.try_into().unwrap()
    }

    // ==== constructor ====
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        fee_token: ContractAddress,
        fee_amount: u256
    ) {
        self.owner.write(owner);
        self.fee_token.write(fee_token);
        self.fee_amount.write(fee_amount);
    }

    // ==== helpers internos ====
    fn assert_owner(self: @ContractState) {
        let caller = get_caller_address();
        assert(caller == self.owner.read(), 'ONLY_OWNER');
    }

    fn assert_len_in_bounds(len: u32) {
        assert(len >= MIN_LEN && len <= MAX_LEN, 'INVALID_LENGTH');
    }

    // ==== implementación del resolver ====
    #[abi(embed_v0)]
    impl Resolver of IAliasResolver<ContractState> {
        fn addr_of_alias(self: @ContractState, alias_key: felt252) -> ContractAddress {
            self.alias_to_addr.read(alias_key)
        }

        fn alias_of_addr(self: @ContractState, who: ContractAddress) -> felt252 {
            let who_f: felt252 = addr_to_felt(who);
            self.addr_to_alias.read(who_f)
        }

        fn is_available(self: @ContractState, alias_key: felt252) -> bool {
            let a = self.alias_to_addr.read(alias_key);
            addr_to_felt(a) == ZERO_FELT
        }

        fn get_owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn get_fee_token(self: @ContractState) -> ContractAddress {
            self.fee_token.read()
        }

        fn get_fee_amount(self: @ContractState) -> u256 {
            self.fee_amount.read()
        }

        fn get_len_bounds(self: @ContractState) -> (u32, u32) {
            (MIN_LEN, MAX_LEN)
        }
    }

    // ==== mutaciones de usuario ====
    #[generate_trait]
    #[abi(per_item)]
    impl ExternalImpl of ExternalTrait {
        #[external(v0)]
        fn register_my_alias(ref self: ContractState, alias_key: felt252, len: u32) {
            let caller = get_caller_address();
            assert_len_in_bounds(len);

            // alias no usado
            let current = self.alias_to_addr.read(alias_key);
            assert(addr_to_felt(current) == ZERO_FELT, 'ALIAS_TAKEN');

            // caller sin alias
            let caller_f = addr_to_felt(caller);
            let prev_alias = self.addr_to_alias.read(caller_f);
            assert(prev_alias == ZERO_FELT, 'ADDRESS_HAS_ALIAS');

            // escribir
            self.alias_to_addr.write(alias_key, caller);
            self.addr_to_alias.write(caller_f, alias_key);

            self.emit(AliasRegistered { alias_key, who: caller });
        }

        #[external(v0)]
        fn update_my_alias(ref self: ContractState, new_alias_key: felt252, len: u32) {
            let caller = get_caller_address();
            assert_len_in_bounds(len);

            // nuevo alias libre
            let taken = self.alias_to_addr.read(new_alias_key);
            assert(addr_to_felt(taken) == ZERO_FELT, 'ALIAS_TAKEN');

            let caller_f = addr_to_felt(caller);
            let old_key = self.addr_to_alias.read(caller_f);

            // liberar alias anterior si existía
            if old_key != ZERO_FELT {
                self.alias_to_addr.write(old_key, felt_to_addr(ZERO_FELT));
            }

            // grabar el nuevo
            self.alias_to_addr.write(new_alias_key, caller);
            self.addr_to_alias.write(caller_f, new_alias_key);

            self.emit(AliasUpdated { alias_key: new_alias_key, who: caller });
        }

        #[external(v0)]
        fn remove_my_alias(ref self: ContractState) {
            let caller = get_caller_address();
            let caller_f = addr_to_felt(caller);
            let key = self.addr_to_alias.read(caller_f);

            assert(key != ZERO_FELT, 'NO_ALIAS');

            self.addr_to_alias.write(caller_f, ZERO_FELT);
            self.alias_to_addr.write(key, felt_to_addr(ZERO_FELT));

            self.emit(AliasRemoved { alias_key: key, who: caller });
        }

        // ==== admin ====
        #[external(v0)]
        fn admin_register_for(
            ref self: ContractState,
            alias_key: felt252,
            len: u32,
            who: ContractAddress
        ) {
            assert_owner(@self);
            assert_len_in_bounds(len);

            let cur = self.alias_to_addr.read(alias_key);
            assert(addr_to_felt(cur) == ZERO_FELT || cur == who, 'ALIAS_TAKEN');

            let who_f = addr_to_felt(who);
            let prev_key = self.addr_to_alias.read(who_f);
            if prev_key != ZERO_FELT && prev_key != alias_key {
                self.alias_to_addr.write(prev_key, felt_to_addr(ZERO_FELT));
            }

            self.alias_to_addr.write(alias_key, who);
            self.addr_to_alias.write(who_f, alias_key);

            self.emit(AliasRegistered { alias_key, who });
        }

        #[external(v0)]
        fn admin_remove_by_alias(ref self: ContractState, alias_key: felt252) {
            assert_owner(@self);

            let who = self.alias_to_addr.read(alias_key);
            assert(addr_to_felt(who) != ZERO_FELT, 'ALIAS_NOT_FOUND');

            let who_f = addr_to_felt(who);
            self.alias_to_addr.write(alias_key, felt_to_addr(ZERO_FELT));
            self.addr_to_alias.write(who_f, ZERO_FELT);

            self.emit(AliasRemoved { alias_key, who });
        }

        #[external(v0)]
        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            assert_owner(@self);
            let prev = self.owner.read();
            self.owner.write(new_owner);
            self.emit(OwnershipTransferred { previous_owner: prev, new_owner });
        }

        #[external(v0)]
        fn admin_set_fee(ref self: ContractState, token: ContractAddress, amount: u256) {
            assert_owner(@self);
            self.fee_token.write(token);
            self.fee_amount.write(amount);
            self.emit(FeeConfigUpdated { token, amount });
        }
    }
}