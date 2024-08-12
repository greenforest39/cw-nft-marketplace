use crate::state::{Config, NFTInfo, CONFIG, NFT_LIST, NFT_OWNER_INFOS};

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    attr, from_binary, to_binary, Addr, BankMsg, Binary, CosmosMsg, Deps, DepsMut, Env,
    MessageInfo, Order, Response, StdError, StdResult, Uint128, WasmMsg,
};
use cw721::{Cw721ExecuteMsg, Cw721ReceiveMsg};
use cw_storage_plus::Bound;
use nft_fixed_sale::fixed_sale::{
    ConfigResponse, Cw721HookMsg, ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg,
};

//Initialize the contract.
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let config = Config {
        owner: info.sender,
        tax_fee_bp: msg.tax_fee_bp,
    };

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new())
}

//Execute the handle messages.
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::UpdateConfig { owner, tax_fee_bp } => {
            execute_update_config(deps, env, info, owner, tax_fee_bp)
        }
        ExecuteMsg::ReceiveNft(msg) => receive_cw721(deps, env, info, msg),
        ExecuteMsg::Withdraw {
            nft_contract_addr,
            nft_token_id,
        } => execute_withdraw(deps, env, info, nft_contract_addr, nft_token_id),
        ExecuteMsg::UpdatePrice {
            nft_contract_addr,
            nft_token_id,
            denom,
            amount,
        } => execute_update_price(
            deps,
            env,
            info,
            nft_contract_addr,
            nft_token_id,
            denom,
            amount,
        ),
        ExecuteMsg::Buy {
            nft_contract_addr,
            nft_token_id,
        } => execute_buy(deps, env, info, nft_contract_addr, nft_token_id),
        ExecuteMsg::WithdrawFee { addr } => execute_withdraw_fee(deps, env, info, addr),
    }
}

pub fn receive_cw721(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw721_msg: Cw721ReceiveMsg,
) -> StdResult<Response> {
    let nft_contract_addr = info.sender;

    match from_binary(&cw721_msg.msg)? {
        Cw721HookMsg::Deposit { denom, amount } => execute_deposit(
            deps,
            env,
            Addr::unchecked(cw721_msg.sender),
            nft_contract_addr,
            cw721_msg.token_id,
            denom,
            amount,
        ),
    }
}

// Only owner can execute it.
pub fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: Option<String>,
    tax_fee_bp: Option<Uint128>,
) -> StdResult<Response> {
    let mut config: Config = CONFIG.load(deps.storage)?;
    let mut attributes = vec![attr("action", "update_config")];

    // permission check
    if info.sender != config.owner {
        return Err(StdError::generic_err("unauthorized"));
    }

    if let Some(owner) = owner {
        config.owner = deps.api.addr_validate(&owner)?;
        attributes.push(attr("new_owner", owner.as_str()))
    }

    if let Some(tax_fee_bp) = tax_fee_bp {
        config.tax_fee_bp = tax_fee_bp;
        attributes.push(attr("new_tax_fee_bp", tax_fee_bp))
    }

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attributes(attributes))
}

pub fn execute_deposit(
    deps: DepsMut,
    _env: Env,
    sender: Addr,
    nft_contract_addr: Addr,
    nft_token_id: String,
    denom: String,
    amount: Uint128,
) -> StdResult<Response> {
    let mut nft_list: Vec<NFTInfo> =
        if let Some(nft_list) = NFT_LIST.may_load(deps.storage, sender.to_string())? {
            nft_list
        } else {
            vec![]
        };

    nft_list.push(NFTInfo {
        nft_contract_addr: nft_contract_addr.clone(),
        nft_token_id: nft_token_id.clone(),
        denom,
        amount,
    });
    NFT_LIST.save(deps.storage, sender.to_string(), &nft_list)?;

    let owner_info_key = nft_contract_addr.to_string() + &nft_token_id;
    NFT_OWNER_INFOS.save(deps.storage, owner_info_key, &sender)?;

    Ok(
        Response::new()
            .add_attributes(vec![("action", "deposit"), ("sender", &sender.to_string())]),
    )
}

pub fn execute_withdraw(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    nft_contract_addr: String,
    nft_token_id: String,
) -> StdResult<Response> {
    let mut messages: Vec<CosmosMsg> = vec![];
    let mut nft_list: Vec<NFTInfo> =
        if let Some(nft_list) = NFT_LIST.may_load(deps.storage, info.sender.to_string())? {
            nft_list
        } else {
            vec![]
        };

    let index = nft_list.iter().position(|item| {
        item.nft_contract_addr == nft_contract_addr && item.nft_token_id == nft_token_id
    });
    if index.is_none() {
        return Err(StdError::generic_err("This NFT is not owned to the user!"));
    }
    nft_list.remove(index.unwrap());

    messages.push(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: nft_contract_addr,
        msg: to_binary(&Cw721ExecuteMsg::TransferNft {
            recipient: info.sender.to_string(),
            token_id: nft_token_id,
        })?,
        funds: vec![],
    }));

    NFT_LIST.save(deps.storage, info.sender.to_string(), &nft_list)?;

    Ok(Response::new()
        .add_messages(messages)
        .add_attribute("action", "withdraw"))
}

pub fn execute_update_price(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    nft_contract_addr: String,
    nft_token_id: String,
    denom: String,
    amount: Uint128,
) -> StdResult<Response> {
    let mut nft_list: Vec<NFTInfo> =
        if let Some(nft_list) = NFT_LIST.may_load(deps.storage, info.sender.to_string())? {
            nft_list
        } else {
            vec![]
        };

    let index = nft_list.iter().position(|item| {
        item.nft_contract_addr == nft_contract_addr && item.nft_token_id == nft_token_id
    });
    if index.is_none() {
        return Err(StdError::generic_err("This NFT is not owned to the user!"));
    }

    let mut new_nft_info = nft_list.get(index.unwrap()).unwrap().clone();
    new_nft_info.denom = denom;
    new_nft_info.amount = amount;
    nft_list.remove(index.unwrap());
    nft_list.push(new_nft_info);

    NFT_LIST.save(deps.storage, info.sender.to_string(), &nft_list)?;

    Ok(Response::new().add_attribute("action", "update_price"))
}

pub fn execute_buy(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    nft_contract_addr: String,
    nft_token_id: String,
) -> StdResult<Response> {
    let mut messages: Vec<CosmosMsg> = vec![];
    let config: Config = CONFIG.load(deps.storage)?;
    let owner_info_key = nft_contract_addr.clone() + &nft_token_id;
    let owner_info = NFT_OWNER_INFOS.may_load(deps.storage, owner_info_key.clone())?;
    if owner_info.is_none() {
        return Err(StdError::generic_err(
            "This NFT is not available in the vault!",
        ));
    }
    let nft_seller: String = owner_info.unwrap().to_string();
    let mut fund = info.funds[0].clone();

    let mut seller_nft_list: Vec<NFTInfo> =
        if let Some(nft_list) = NFT_LIST.may_load(deps.storage, nft_seller.clone())? {
            nft_list
        } else {
            vec![]
        };

    let index = seller_nft_list
        .iter()
        .position(|item| {
            item.nft_contract_addr == nft_contract_addr && item.nft_token_id == nft_token_id
        })
        .unwrap();
    let nft_info = seller_nft_list.get(index).unwrap().clone();

    if nft_info.denom != fund.denom || nft_info.amount != fund.amount {
        return Err(StdError::generic_err(
            "The payment is not matched with the selling price!",
        ));
    }

    seller_nft_list.remove(index);

    messages.push(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: nft_contract_addr,
        msg: to_binary(&Cw721ExecuteMsg::TransferNft {
            recipient: info.sender.to_string(),
            token_id: nft_token_id,
        })?,
        funds: vec![],
    }));

    NFT_LIST.save(deps.storage, nft_seller.clone(), &seller_nft_list)?;
    NFT_OWNER_INFOS.remove(deps.storage, owner_info_key);

    let fee_amount = fund
        .amount
        .checked_mul(config.tax_fee_bp)?
        .checked_div(Uint128::from(10000u128))?;
    fund.amount = fund.amount.checked_sub(fee_amount)?;

    messages.push(CosmosMsg::Bank(BankMsg::Send {
        to_address: nft_seller,
        amount: vec![fund],
    }));

    Ok(Response::new()
        .add_messages(messages)
        .add_attribute("action", "buy"))
}

// Only owner can execute it.
pub fn execute_withdraw_fee(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    addr: String,
) -> StdResult<Response> {
    let config: Config = CONFIG.load(deps.storage)?;
    // permission check
    if info.sender != config.owner {
        return Err(StdError::generic_err("unauthorized"));
    }

    let coins = deps.querier.query_all_balances(env.contract.address)?;

    Ok(Response::new()
        .add_message(CosmosMsg::Bank(BankMsg::Send {
            to_address: deps.api.addr_validate(&addr)?.to_string(),
            amount: coins,
        }))
        .add_attributes(vec![attr("action", "withdraw_fee")]))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::NftList { wallet } => to_binary(&query_nft_list(deps, wallet)?),
        QueryMsg::AllNftsInVault { start_after, limit } => {
            to_binary(&query_all_nft_list(deps, start_after, limit)?)
        }
        QueryMsg::NftInfo {
            wallet,
            nft_contract_addr,
            nft_token_id,
        } => to_binary(&query_nft_info(
            deps,
            wallet,
            nft_contract_addr,
            nft_token_id,
        )?),
        QueryMsg::NftOwnerInfo {
            nft_contract_addr,
            nft_token_id,
        } => to_binary(&query_nft_owner_info(
            deps,
            nft_contract_addr,
            nft_token_id,
        )?),
    }
}

pub fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;

    Ok(ConfigResponse {
        owner: config.owner.to_string(),
        tax_fee_bp: config.tax_fee_bp,
    })
}

pub fn query_nft_list(deps: Deps, wallet: String) -> StdResult<Vec<NFTInfo>> {
    let nft_list: Vec<NFTInfo> = if let Some(nft_list) = NFT_LIST.may_load(deps.storage, wallet)? {
        nft_list
    } else {
        vec![]
    };

    Ok(nft_list)
}

// settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;
pub fn query_all_nft_list(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Vec<NFTInfo>> {
    let mut nft_list: Vec<NFTInfo> = vec![];

    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    NFT_LIST
        .range(
            deps.storage,
            start_after.map(Bound::exclusive),
            None,
            Order::Ascending,
        )
        .take(limit)
        .map(|item| {
            let (_, v) = item.unwrap();
            v
        })
        .for_each(|mut item| nft_list.append(&mut item));

    Ok(nft_list)
}

pub fn query_nft_owner_info(
    deps: Deps,
    nft_contract_addr: String,
    nft_token_id: String,
) -> StdResult<String> {
    let owner_info_key = nft_contract_addr + &nft_token_id;
    let owner_info = NFT_OWNER_INFOS.may_load(deps.storage, owner_info_key)?;
    if owner_info.is_none() {
        return Err(StdError::generic_err(
            "This NFT is not available in the vault!",
        ));
    }

    Ok(owner_info.unwrap().to_string())
}

pub fn query_nft_info(
    deps: Deps,
    wallet: String,
    nft_contract_addr: String,
    nft_token_id: String,
) -> StdResult<NFTInfo> {
    let nft_list: Vec<NFTInfo> = if let Some(nft_list) = NFT_LIST.may_load(deps.storage, wallet)? {
        nft_list
    } else {
        vec![]
    };

    let index = nft_list
        .iter()
        .position(|item| {
            item.nft_contract_addr == nft_contract_addr && item.nft_token_id == nft_token_id
        })
        .unwrap();
    let nft_info = nft_list.get(index).unwrap().clone();

    Ok(nft_info)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default())
}
