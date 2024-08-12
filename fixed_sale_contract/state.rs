use cosmwasm_std::{Addr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cw_storage_plus::{Item, Map};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub owner: Addr,
    pub tax_fee_bp: Uint128, // based on 10000
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct NFTInfo {
    pub nft_contract_addr: Addr,
    pub nft_token_id: String,
    pub denom: String,
    pub amount: Uint128,
}

// put the length bytes at the first for compatibility with legacy singleton store
pub const CONFIG: Item<Config> = Item::new("config");

// key = NFT owner
pub const NFT_LIST: Map<String, Vec<NFTInfo>> = Map::new("nft_list");

// key = nft_contract_addr + nft_token_id
pub const NFT_OWNER_INFOS: Map<String, Addr> = Map::new("nft_owner_infos");
