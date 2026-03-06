use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    fn map_account() -> Weight;
    fn unmap_account() -> Weight;
    fn register_alias() -> Weight;
    fn release_alias() -> Weight;
    fn transfer_alias() -> Weight;
    fn put_alias_on_sale() -> Weight;
    fn cancel_sale() -> Weight;
    fn buy_alias() -> Weight;
    fn add_chain_link() -> Weight;
    fn remove_chain_link() -> Weight;
    fn set_account_metadata() -> Weight;
    fn dispatch_as_linked_account() -> Weight;
    fn register_private_link() -> Weight;
    fn remove_private_link() -> Weight;
    fn reveal_private_link() -> Weight;
    fn dispatch_as_private_link() -> Weight;
}

pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn map_account() -> Weight {
        T::DbWeight::get().reads_writes(2, 2)
    }

    fn unmap_account() -> Weight {
        T::DbWeight::get().reads_writes(1, 2)
    }

    fn register_alias() -> Weight {
        T::DbWeight::get().reads_writes(4, 4)
    }

    fn release_alias() -> Weight {
        T::DbWeight::get().reads_writes(3, 3)
    }

    fn transfer_alias() -> Weight {
        T::DbWeight::get().reads_writes(4, 5)
    }

    fn put_alias_on_sale() -> Weight {
        T::DbWeight::get().reads_writes(2, 1)
    }

    fn cancel_sale() -> Weight {
        T::DbWeight::get().reads_writes(2, 1)
    }

    fn buy_alias() -> Weight {
        T::DbWeight::get().reads_writes(5, 5)
    }

    fn add_chain_link() -> Weight {
        T::DbWeight::get().reads_writes(4, 1)
    }

    fn remove_chain_link() -> Weight {
        T::DbWeight::get().reads_writes(2, 1)
    }

    fn set_account_metadata() -> Weight {
        T::DbWeight::get().reads_writes(1, 1)
    }

    fn dispatch_as_linked_account() -> Weight {
        T::DbWeight::get().reads_writes(5, 0)
    }

    fn register_private_link() -> Weight {
        T::DbWeight::get().reads_writes(2, 1)
    }

    fn remove_private_link() -> Weight {
        T::DbWeight::get().reads_writes(2, 1)
    }

    fn reveal_private_link() -> Weight {
        T::DbWeight::get().reads_writes(6, 3)
    }

    fn dispatch_as_private_link() -> Weight {
        T::DbWeight::get().reads_writes(12, 0)
    }
}
