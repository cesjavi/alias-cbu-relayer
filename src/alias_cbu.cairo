// src/AliasCBU.cairo — Cairo 2.11+/2.12 compatible (sin #[view])

#[starknet::contract]
mod alias_cbu {
    // ===== Imports =====
    use core::traits::TryInto;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::{
        Map,
        StorageMapReadAccess,
        StorageMapWriteAccess,
        StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    // ===== Constantes de política =====
    const MIN_LEN: u32 = 4;
    const MAX_LEN: u32 = 20;

    // Sentinelas (0 = vacío)
    const ZERO_FELT: felt252 = 0;
    const CHAIN_ID_STARKNET: felt252 = 'STRK';
    const CHAIN_ID_ETHEREUM: felt252 = 'ETH';
    const CHAIN_ID_BITCOIN: felt252 = 'BTC';

    // ===== Interfaz pública (resolver) =====
    #[starknet::interface]
    pub trait IAliasResolver<TContractState> {
        fn addr_of_alias(self: @TContractState, alias_key: felt252) -> ContractAddress;
        fn alias_of_addr(self: @TContractState, who: ContractAddress) -> felt252;
        fn is_available(self: @TContractState, alias_key: felt252) -> bool;
        fn get_owner(self: @TContractState) -> ContractAddress;
        fn get_fee_token(self: @TContractState) -> ContractAddress;
        fn get_fee_amount(self: @TContractState) -> u256;
        fn get_len_bounds(self: @TContractState) -> (u32, u32);
        fn alias_key_of_addr(self: @TContractState, who: ContractAddress) -> felt252;
        fn eth_of_alias(self: @TContractState, alias_key: felt252) -> felt252;
        fn btc_of_alias(self: @TContractState, alias_key: felt252) -> felt252;
        fn alias_of_eth(self: @TContractState, eth_address: felt252) -> felt252;
        fn alias_of_btc(self: @TContractState, btc_address: felt252) -> felt252;
        fn external_address_of(
            self: @TContractState, alias_key: felt252, chain_id: felt252
        ) -> felt252;
        fn alias_of_external(
            self: @TContractState, chain_id: felt252, external_address: felt252
        ) -> felt252;
    }

    // ===== Eventos =====
    #[derive(Drop, starknet::Event)]
    #[event]
    pub enum Event {
        AliasRegistered: AliasRegistered,
        AliasUpdated: AliasUpdated,
        AliasRemoved: AliasRemoved,
        OwnershipTransferred: OwnershipTransferred,
        FeeConfigUpdated: FeeConfigUpdated,
        AliasExternalUpdated: AliasExternalUpdated,
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
    pub struct AliasExternalUpdated {
        pub alias_key: felt252,
        pub eth_address: felt252,
        pub btc_address: felt252,
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

    // ===== Storage =====
    #[storage]
    struct Storage {
        // alias_key -> address (0 = libre)
        alias_to_addr: Map<felt252, ContractAddress>,
        // address (felt) -> alias_key (0 = sin alias)
        addr_to_alias: Map<felt252, felt252>,
        // alias_key -> dirección ETH (0 = no informada)
        alias_to_eth: Map<felt252, felt252>,
        // alias_key -> dirección BTC (0 = no informada)
        alias_to_btc: Map<felt252, felt252>,
        // dirección ETH -> alias_key (0 = sin alias)
        eth_addr_to_alias: Map<felt252, felt252>,
        // dirección BTC -> alias_key (0 = sin alias)
        btc_addr_to_alias: Map<felt252, felt252>,
        // owner/admin
        owner: ContractAddress,
        // cobro informativo en AIC (para UX)
        fee_token: ContractAddress,
        fee_amount: u256,
    }

    // ===== Helpers ContractAddress <-> felt =====
    fn addr_to_felt(addr: ContractAddress) -> felt252 { addr.into() }
    fn felt_to_addr(x: felt252) -> ContractAddress { x.try_into().unwrap() }

    // ===== Constructor =====
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

    // ===== Helpers internos =====
    fn assert_owner(self: @ContractState) {
        let caller = get_caller_address();
        assert(caller == self.owner.read(), 'ONLY_OWNER');
    }

    fn assert_len_in_bounds(len: u32) {
        assert(len >= MIN_LEN && len <= MAX_LEN, 'INVALID_LENGTH');
    }

    fn assert_supported_chain(chain_id: felt252) {
        assert(
            chain_id == CHAIN_ID_ETHEREUM || chain_id == CHAIN_ID_BITCOIN,
            'UNSUPPORTED_CHAIN'
        );
    }

    fn update_external_mappings(
        ref self: ContractState, alias_key: felt252, eth_address: felt252, btc_address: felt252
    ) {
        if eth_address != ZERO_FELT {
            let prev = self.eth_addr_to_alias.read(eth_address);
            assert(prev == ZERO_FELT || prev == alias_key, 'ETH_ADDR_IN_USE');
        }

        if btc_address != ZERO_FELT {
            let prev = self.btc_addr_to_alias.read(btc_address);
            assert(prev == ZERO_FELT || prev == alias_key, 'BTC_ADDR_IN_USE');
        }

        let old_eth = self.alias_to_eth.read(alias_key);
        if old_eth != ZERO_FELT && old_eth != eth_address {
            self.eth_addr_to_alias.write(old_eth, ZERO_FELT);
        }

        let old_btc = self.alias_to_btc.read(alias_key);
        if old_btc != ZERO_FELT && old_btc != btc_address {
            self.btc_addr_to_alias.write(old_btc, ZERO_FELT);
        }

        self.alias_to_eth.write(alias_key, eth_address);
        self.alias_to_btc.write(alias_key, btc_address);

        if eth_address != ZERO_FELT {
            self.eth_addr_to_alias.write(eth_address, alias_key);
        }

        if btc_address != ZERO_FELT {
            self.btc_addr_to_alias.write(btc_address, alias_key);
        }
    }

    // ===== Implementación de lecturas (views) =====
    // En Cairo 2.11+ una función "view" es cualquier fn con `self: @ContractState`.
    #[abi(embed_v0)]
    impl Resolver of IAliasResolver<ContractState> {
        fn addr_of_alias(self: @ContractState, alias_key: felt252) -> ContractAddress {
            self.alias_to_addr.read(alias_key)
        }

        fn alias_of_addr(self: @ContractState, who: ContractAddress) -> felt252 {
            self.addr_to_alias.read(addr_to_felt(who))
        }

        fn is_available(self: @ContractState, alias_key: felt252) -> bool {
            let a = self.alias_to_addr.read(alias_key);
            addr_to_felt(a) == ZERO_FELT
        }

        fn get_owner(self: @ContractState) -> ContractAddress { self.owner.read() }
        fn get_fee_token(self: @ContractState) -> ContractAddress { self.fee_token.read() }
        fn get_fee_amount(self: @ContractState) -> u256 { self.fee_amount.read() }
        fn get_len_bounds(self: @ContractState) -> (u32, u32) { (MIN_LEN, MAX_LEN) }

        fn alias_key_of_addr(self: @ContractState, who: ContractAddress) -> felt252 {
            self.addr_to_alias.read(addr_to_felt(who))
        }

        fn eth_of_alias(self: @ContractState, alias_key: felt252) -> felt252 {
            self.alias_to_eth.read(alias_key)
        }

        fn btc_of_alias(self: @ContractState, alias_key: felt252) -> felt252 {
            self.alias_to_btc.read(alias_key)
        }

        fn alias_of_eth(self: @ContractState, eth_address: felt252) -> felt252 {
            self.eth_addr_to_alias.read(eth_address)
        }

        fn alias_of_btc(self: @ContractState, btc_address: felt252) -> felt252 {
            self.btc_addr_to_alias.read(btc_address)
        }

        fn external_address_of(
            self: @ContractState, alias_key: felt252, chain_id: felt252
        ) -> felt252 {
            if chain_id == CHAIN_ID_ETHEREUM {
                self.alias_to_eth.read(alias_key)
            } else {
                assert_supported_chain(chain_id);
                self.alias_to_btc.read(alias_key)
            }
        }

        fn alias_of_external(
            self: @ContractState, chain_id: felt252, external_address: felt252
        ) -> felt252 {
            if chain_id == CHAIN_ID_ETHEREUM {
                self.eth_addr_to_alias.read(external_address)
            } else {
                assert_supported_chain(chain_id);
                self.btc_addr_to_alias.read(external_address)
            }
        }
    }

    // ===== Mutaciones de usuario / admin =====
    #[generate_trait]
    #[abi(per_item)]
    impl ExternalImpl of ExternalTrait {
        // Usuario: registra su alias si está libre
        #[external(v0)]
        fn register_my_alias(
            ref self: ContractState,
            alias_key: felt252,
            len: u32,
            eth_address: felt252,
            btc_address: felt252,
        ) {
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
            update_external_mappings(ref self, alias_key, eth_address, btc_address);

            self.emit(Event::AliasRegistered(AliasRegistered { alias_key, who: caller }));
            self.emit(Event::AliasExternalUpdated(AliasExternalUpdated {
                alias_key,
                eth_address,
                btc_address,
            }));
        }

        // Usuario: actualiza su alias (libera el anterior si existía)
        #[external(v0)]
        fn update_my_alias(
            ref self: ContractState,
            new_alias_key: felt252,
            len: u32,
            eth_address: felt252,
            btc_address: felt252,
        ) {
            let caller = get_caller_address();
            assert_len_in_bounds(len);

            // nuevo alias libre
            let taken = self.alias_to_addr.read(new_alias_key);
            assert(addr_to_felt(taken) == ZERO_FELT, 'ALIAS_TAKEN');

            let caller_f = addr_to_felt(caller);
            let old_key = self.addr_to_alias.read(caller_f);

            // liberar alias anterior si existía
            if old_key != ZERO_FELT {
                let old_eth = self.alias_to_eth.read(old_key);
                if old_eth != ZERO_FELT {
                    self.eth_addr_to_alias.write(old_eth, ZERO_FELT);
                }

                let old_btc = self.alias_to_btc.read(old_key);
                if old_btc != ZERO_FELT {
                    self.btc_addr_to_alias.write(old_btc, ZERO_FELT);
                }

                self.alias_to_eth.write(old_key, ZERO_FELT);
                self.alias_to_btc.write(old_key, ZERO_FELT);
                self.alias_to_addr.write(old_key, felt_to_addr(ZERO_FELT));
            }

            // grabar el nuevo
            self.alias_to_addr.write(new_alias_key, caller);
            self.addr_to_alias.write(caller_f, new_alias_key);
            update_external_mappings(ref self, new_alias_key, eth_address, btc_address);

            self.emit(Event::AliasUpdated(AliasUpdated { alias_key: new_alias_key, who: caller }));
            self.emit(Event::AliasExternalUpdated(AliasExternalUpdated {
                alias_key: new_alias_key,
                eth_address,
                btc_address,
            }));
        }

        // Usuario: elimina su alias
        #[external(v0)]
        fn remove_my_alias(ref self: ContractState) {
            let caller = get_caller_address();
            let caller_f = addr_to_felt(caller);
            let key = self.addr_to_alias.read(caller_f);

            assert(key != ZERO_FELT, 'NO_ALIAS');

            update_external_mappings(ref self, key, ZERO_FELT, ZERO_FELT);
            self.addr_to_alias.write(caller_f, ZERO_FELT);
            self.alias_to_addr.write(key, felt_to_addr(ZERO_FELT));

            self.emit(Event::AliasRemoved(AliasRemoved { alias_key: key, who: caller }));
            self.emit(Event::AliasExternalUpdated(AliasExternalUpdated {
                alias_key: key,
                eth_address: ZERO_FELT,
                btc_address: ZERO_FELT,
            }));
        }

        #[external(v0)]
        fn set_my_external_addresses(
            ref self: ContractState,
            eth_address: felt252,
            btc_address: felt252,
        ) {
            let caller = get_caller_address();
            let caller_f = addr_to_felt(caller);
            let alias_key = self.addr_to_alias.read(caller_f);

            assert(alias_key != ZERO_FELT, 'NO_ALIAS');
            update_external_mappings(ref self, alias_key, eth_address, btc_address);

            self.emit(Event::AliasExternalUpdated(AliasExternalUpdated {
                alias_key,
                eth_address,
                btc_address,
            }));
        }

        #[external(v0)]
        fn set_my_external_address(
            ref self: ContractState, chain_id: felt252, address: felt252
        ) {
            assert_supported_chain(chain_id);

            let caller = get_caller_address();
            let caller_f = addr_to_felt(caller);
            let alias_key = self.addr_to_alias.read(caller_f);

            assert(alias_key != ZERO_FELT, 'NO_ALIAS');

            if chain_id == CHAIN_ID_ETHEREUM {
                let current_btc = self.alias_to_btc.read(alias_key);
                update_external_mappings(ref self, alias_key, address, current_btc);
                self.emit(Event::AliasExternalUpdated(AliasExternalUpdated {
                    alias_key,
                    eth_address: address,
                    btc_address: current_btc,
                }));
            } else {
                let current_eth = self.alias_to_eth.read(alias_key);
                update_external_mappings(ref self, alias_key, current_eth, address);
                self.emit(Event::AliasExternalUpdated(AliasExternalUpdated {
                    alias_key,
                    eth_address: current_eth,
                    btc_address: address,
                }));
            }
        }

        // ===== Admin =====
        #[external(v0)]
        fn admin_register_for(
            ref self: ContractState,
            alias_key: felt252,
            len: u32,
            who: ContractAddress,
            eth_address: felt252,
            btc_address: felt252,
        ) {
            assert_owner(@self);
            assert_len_in_bounds(len);

            let cur = self.alias_to_addr.read(alias_key);
            assert(addr_to_felt(cur) == ZERO_FELT || cur == who, 'ALIAS_TAKEN');

            let who_f = addr_to_felt(who);
            let prev_key = self.addr_to_alias.read(who_f);
            if prev_key != ZERO_FELT && prev_key != alias_key {
                let prev_eth = self.alias_to_eth.read(prev_key);
                if prev_eth != ZERO_FELT {
                    self.eth_addr_to_alias.write(prev_eth, ZERO_FELT);
                }

                let prev_btc = self.alias_to_btc.read(prev_key);
                if prev_btc != ZERO_FELT {
                    self.btc_addr_to_alias.write(prev_btc, ZERO_FELT);
                }

                self.alias_to_eth.write(prev_key, ZERO_FELT);
                self.alias_to_btc.write(prev_key, ZERO_FELT);
                self.alias_to_addr.write(prev_key, felt_to_addr(ZERO_FELT));
            }

            let existing_eth = self.alias_to_eth.read(alias_key);
            if existing_eth != ZERO_FELT && existing_eth != eth_address {
                self.eth_addr_to_alias.write(existing_eth, ZERO_FELT);
            }

            let existing_btc = self.alias_to_btc.read(alias_key);
            if existing_btc != ZERO_FELT && existing_btc != btc_address {
                self.btc_addr_to_alias.write(existing_btc, ZERO_FELT);
            }

            self.alias_to_addr.write(alias_key, who);
            self.addr_to_alias.write(who_f, alias_key);
            update_external_mappings(ref self, alias_key, eth_address, btc_address);

            self.emit(Event::AliasRegistered(AliasRegistered { alias_key, who }));
            self.emit(Event::AliasExternalUpdated(AliasExternalUpdated {
                alias_key,
                eth_address,
                btc_address,
            }));
        }

        #[external(v0)]
        fn admin_remove_by_alias(ref self: ContractState, alias_key: felt252) {
            assert_owner(@self);

            let who = self.alias_to_addr.read(alias_key);
            assert(addr_to_felt(who) != ZERO_FELT, 'ALIAS_NOT_FOUND');

            let who_f = addr_to_felt(who);
            update_external_mappings(ref self, alias_key, ZERO_FELT, ZERO_FELT);
            self.alias_to_addr.write(alias_key, felt_to_addr(ZERO_FELT));
            self.addr_to_alias.write(who_f, ZERO_FELT);

            self.emit(Event::AliasRemoved(AliasRemoved { alias_key, who }));
            self.emit(Event::AliasExternalUpdated(AliasExternalUpdated {
                alias_key,
                eth_address: ZERO_FELT,
                btc_address: ZERO_FELT,
            }));
        }

        #[external(v0)]
        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            assert_owner(@self);
            let prev = self.owner.read();
            self.owner.write(new_owner);
            self.emit(Event::OwnershipTransferred(OwnershipTransferred {
                previous_owner: prev, new_owner
            }));
        }

        #[external(v0)]
        fn admin_set_fee(ref self: ContractState, token: ContractAddress, amount: u256) {
            assert_owner(@self);
            self.fee_token.write(token);
            self.fee_amount.write(amount);
            self.emit(Event::FeeConfigUpdated(FeeConfigUpdated { token, amount }));
        }
    }
}
