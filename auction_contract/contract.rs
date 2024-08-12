use std::vec;

use crate::state::{
    auction_infos, read_auction_infos, read_bids, AuctionInfo, Config, TokenAuctionState,
    ACTIVE_AUCTION_INFOS_BY_OWNER, BIDS, CONFIG, NEXT_AUCTION_ID, TOKEN_AUCTION_STATE,
};
use cosmwasm_std::{
    attr, coin, coins, entry_point, from_binary, has_coins, to_binary, Addr, BankMsg, Binary, Coin,
    CosmosMsg, Deps, DepsMut, Env, MessageInfo, QuerierWrapper, QueryRequest, Response, StdError,
    StdResult, Storage, Uint128, WasmMsg, WasmQuery,
};
use cw721::{Cw721ExecuteMsg, Cw721QueryMsg, Cw721ReceiveMsg, OwnerOfResponse};
use project_auction::{
    auction::{
        AuctionStateResponse, Bid, BidsResponse, ConfigResponse, Cw721HookMsg, ExecuteMsg,
        InstantiateMsg, MigrateMsg, OrderBy, QueryMsg,
    },
    error::ContractError,
    require,
};

#[entry_point]
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
    NEXT_AUCTION_ID.save(deps.storage, &Uint128::from(1u128))?;

    Ok(Response::new().add_attribute("method", "instantiate"))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::UpdateConfig { owner, tax_fee_bp } => {
            execute_update_config(deps, env, info, owner, tax_fee_bp)
        }
        ExecuteMsg::ReceiveNft(msg) => handle_receive_cw721(deps, env, info, msg),
        ExecuteMsg::PlaceBid {
            token_id,
            token_address,
        } => execute_place_bid(deps, env, info, token_id, token_address),
        ExecuteMsg::CancelAuction {
            token_id,
            token_address,
        } => execute_cancel(deps, env, info, token_id, token_address),
        ExecuteMsg::Claim {
            token_id,
            token_address,
        } => execute_claim(deps, env, info, token_id, token_address),
        ExecuteMsg::WithdrawFee { addr } => execute_withdraw_fee(deps, env, info, addr),
    }
}

fn handle_receive_cw721(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: Cw721ReceiveMsg,
) -> Result<Response, ContractError> {
    match from_binary(&msg.msg)? {
        Cw721HookMsg::StartAuction {
            end_time,
            coin_denom,
            min_amount,
        } => execute_start_auction(
            deps,
            env,
            msg.sender,
            msg.token_id,
            info.sender.to_string(),
            end_time,
            coin_denom,
            min_amount,
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
) -> Result<Response, ContractError> {
    let mut config: Config = CONFIG.load(deps.storage)?;
    let mut attributes = vec![attr("action", "update_config")];

    // permission check
    if info.sender != config.owner {
        return Err(ContractError::Unauthorized {});
    }

    if let Some(owner) = owner {
        config.owner = deps.api.addr_validate(&owner)?;
        attributes.push(attr("new_owner", owner.as_str()))
    }

    if let Some(tax_fee_bp) = tax_fee_bp {
        config.tax_fee_bp = tax_fee_bp;
        attributes.push(attr("new_tax_fee_bp", tax_fee_bp.to_string()))
    }

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attributes(attributes))
}

#[allow(clippy::too_many_arguments)]
fn execute_start_auction(
    deps: DepsMut,
    env: Env,
    sender: String,
    token_id: String,
    token_address: String,
    end_time: u64,
    coin_denom: String,
    min_amount: Uint128,
) -> Result<Response, ContractError> {
    let start_time = env.block.time.seconds();

    require(end_time != 0, ContractError::ExpirationMustNotBeNever {})?;
    require(
        start_time.partial_cmp(&end_time) != None,
        ContractError::ExpirationsMustBeOfSameType {},
    )?;
    require(
        start_time < end_time,
        ContractError::StartTimeAfterEndTime {},
    )?;

    let auction_id = get_and_increment_next_auction_id(deps.storage, &token_id, &token_address)?;
    BIDS.save(deps.storage, auction_id.u128(), &vec![])?;
    let mut auction_infos: Vec<AuctionInfo> = vec![];
    if let Some(mut auction_infos_by_owner) =
        ACTIVE_AUCTION_INFOS_BY_OWNER.may_load(deps.storage, sender.clone())?
    {
        auction_infos.append(&mut auction_infos_by_owner);
    }
    auction_infos.push(AuctionInfo {
        auction_id,
        token_address: token_address.clone(),
        token_id: token_id.clone(),
    });
    ACTIVE_AUCTION_INFOS_BY_OWNER.save(deps.storage, sender.clone(), &auction_infos)?;

    TOKEN_AUCTION_STATE.save(
        deps.storage,
        auction_id.u128(),
        &TokenAuctionState {
            start_time,
            end_time,
            high_bidder_addr: Addr::unchecked(""),
            high_bidder_amount: Uint128::zero(),
            coin_denom: coin_denom.clone(),
            min_amount,
            auction_id,
            owner: sender,
            token_id,
            token_address,
            is_cancelled: false,
        },
    )?;
    Ok(Response::new().add_attributes(vec![
        attr("action", "start_auction"),
        attr("start_time", start_time.to_string()),
        attr("end_time", end_time.to_string()),
        attr("coin_denom", coin_denom),
        attr("auction_id", auction_id.to_string()),
    ]))
}

fn execute_place_bid(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    token_id: String,
    token_address: String,
) -> Result<Response, ContractError> {
    let mut token_auction_state =
        get_existing_token_auction_state(deps.storage, &token_id, &token_address)?;

    require(
        !token_auction_state.is_cancelled,
        ContractError::AuctionCancelled {},
    )?;

    require(
        token_auction_state.end_time > env.block.time.seconds(),
        ContractError::AuctionEnded {},
    )?;

    require(
        token_auction_state.owner != info.sender,
        ContractError::TokenOwnerCannotBid {},
    )?;

    require(
        info.funds.len() == 1,
        ContractError::InvalidFunds {
            msg: "Auctions require exactly one coin to be sent.".to_string(),
        },
    )?;

    require(
        token_auction_state.high_bidder_addr != info.sender,
        ContractError::HighestBidderCannotOutBid {},
    )?;

    let coin_denom = token_auction_state.coin_denom.clone();
    let payment: &Coin = &info.funds[0];
    require(
        payment.denom == coin_denom && payment.amount > Uint128::zero(),
        ContractError::InvalidFunds {
            msg: format!("No {} assets are provided to auction", coin_denom),
        },
    )?;
    require(
        token_auction_state.high_bidder_amount < payment.amount,
        ContractError::BidSmallerThanHighestBid {},
    )?;
    require(
        payment.amount >= token_auction_state.min_amount,
        ContractError::InvalidFunds {
            msg: "Bid amount is smaller than auction min amount.".to_string(),
        },
    )?;

    let mut messages: Vec<CosmosMsg> = vec![];
    // Send back previous bid unless there was no previous bid.
    if token_auction_state.high_bidder_amount > Uint128::zero() {
        let bank_msg = BankMsg::Send {
            to_address: token_auction_state.high_bidder_addr.to_string(),
            amount: coins(
                token_auction_state.high_bidder_amount.u128(),
                token_auction_state.coin_denom.clone(),
            ),
        };
        messages.push(CosmosMsg::Bank(bank_msg));
    }

    token_auction_state.high_bidder_addr = info.sender.clone();
    token_auction_state.high_bidder_amount = payment.amount;

    let key = token_auction_state.auction_id.u128();
    TOKEN_AUCTION_STATE.save(deps.storage, key, &token_auction_state)?;
    let mut bids_for_auction = BIDS.load(deps.storage, key)?;
    bids_for_auction.push(Bid {
        bidder: info.sender.to_string(),
        amount: payment.amount,
        timestamp: env.block.time.seconds(),
    });
    BIDS.save(deps.storage, key, &bids_for_auction)?;
    Ok(Response::new().add_messages(messages).add_attributes(vec![
        attr("action", "bid"),
        attr("token_id", token_id),
        attr("bider", info.sender.to_string()),
        attr("amount", payment.amount.to_string()),
    ]))
}

fn execute_cancel(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    token_id: String,
    token_address: String,
) -> Result<Response, ContractError> {
    let mut token_auction_state =
        get_existing_token_auction_state(deps.storage, &token_id, &token_address)?;
    require(
        info.sender == token_auction_state.owner,
        ContractError::Unauthorized {},
    )?;
    require(
        token_auction_state.end_time > env.block.time.seconds(),
        ContractError::AuctionEnded {},
    )?;
    let mut messages: Vec<CosmosMsg> = vec![CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: token_auction_state.token_address.clone(),
        msg: to_binary(&Cw721ExecuteMsg::TransferNft {
            recipient: info.sender.to_string(),
            token_id: token_id.clone(),
        })?,
        funds: vec![],
    })];

    // Refund highest bid, if it exists.
    if !token_auction_state.high_bidder_amount.is_zero() {
        messages.push(CosmosMsg::Bank(BankMsg::Send {
            to_address: token_auction_state.high_bidder_addr.to_string(),
            amount: coins(
                token_auction_state.high_bidder_amount.u128(),
                token_auction_state.coin_denom.clone(),
            ),
        }));
    }

    token_auction_state.is_cancelled = true;
    TOKEN_AUCTION_STATE.save(
        deps.storage,
        token_auction_state.auction_id.u128(),
        &token_auction_state,
    )?;

    let mut auction_infos_by_owner =
        ACTIVE_AUCTION_INFOS_BY_OWNER.load(deps.storage, info.sender.to_string())?;
    let index = auction_infos_by_owner
        .iter()
        .position(|auction_info| {
            auction_info.token_address == token_address && auction_info.token_id == token_id
        })
        .unwrap();
    auction_infos_by_owner.remove(index);
    ACTIVE_AUCTION_INFOS_BY_OWNER.save(
        deps.storage,
        info.sender.to_string(),
        &auction_infos_by_owner,
    )?;

    Ok(Response::new().add_messages(messages))
}

fn execute_claim(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    token_id: String,
    token_address: String,
) -> Result<Response, ContractError> {
    let token_auction_state =
        get_existing_token_auction_state(deps.storage, &token_id, &token_address)?;
    require(
        token_auction_state.end_time < env.block.time.seconds(),
        ContractError::AuctionNotEnded {},
    )?;
    let token_owner = query_owner_of(
        deps.querier,
        token_auction_state.token_address.clone(),
        token_id.clone(),
    )?
    .owner;
    require(
        // If this is false then the token is no longer held by the contract so the token has been
        // claimed.
        token_owner == env.contract.address,
        ContractError::AuctionAlreadyClaimed {},
    )?;

    let mut resp = Response::new()
        .add_attribute("action", "claim")
        .add_attribute("token_id", token_id.clone())
        .add_attribute("token_contract", token_auction_state.token_address.clone())
        .add_attribute("recipient", &token_auction_state.high_bidder_addr)
        .add_attribute("winning_bid_amount", token_auction_state.high_bidder_amount)
        .add_attribute("auction_id", token_auction_state.auction_id);

    // This is the case where no-one bid on the token.
    if token_auction_state.high_bidder_amount.is_zero() {
        return Ok(resp
            // Send NFT back to the original owner.
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: token_auction_state.token_address.clone(),
                msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                    recipient: token_auction_state.owner,
                    token_id,
                })?,
                funds: vec![],
            })));
    }

    let config = CONFIG.load(deps.storage)?;

    let sale_amount = coin(
        token_auction_state.high_bidder_amount.clone().u128(),
        token_auction_state.coin_denom.clone(),
    );
    let contract_amount = deps
        .querier
        .query_balance(env.contract.address, token_auction_state.coin_denom.clone())?;
    require(
        has_coins(&[contract_amount], &sale_amount),
        ContractError::InsufficientFunds {},
    )?;
    let tax_fee_amount = sale_amount.amount.u128() * config.tax_fee_bp.u128() / 10000_u128;
    let seller_receives = coins(
        sale_amount.amount.u128() - tax_fee_amount,
        token_auction_state.coin_denom.clone(),
    );

    resp = resp // Send funds to the original owner.
        .add_message(CosmosMsg::Bank(BankMsg::Send {
            to_address: token_auction_state.owner.clone(),
            amount: seller_receives,
        }))
        // Send NFT to auction winner.
        .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token_auction_state.token_address.clone(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: token_auction_state.high_bidder_addr.to_string(),
                token_id: token_id.clone(),
            })?,
            funds: vec![],
        }));

    let mut auction_infos_by_owner =
        ACTIVE_AUCTION_INFOS_BY_OWNER.load(deps.storage, token_auction_state.owner.clone())?;
    let index = auction_infos_by_owner
        .iter()
        .position(|auction_info| {
            auction_info.token_address == token_address && auction_info.token_id == token_id
        })
        .unwrap();
    auction_infos_by_owner.remove(index);
    ACTIVE_AUCTION_INFOS_BY_OWNER.save(
        deps.storage,
        token_auction_state.owner,
        &auction_infos_by_owner,
    )?;

    Ok(resp)
}

// Only owner can execute it.
pub fn execute_withdraw_fee(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    addr: String,
) -> Result<Response, ContractError> {
    let config: Config = CONFIG.load(deps.storage)?;
    // permission check
    if info.sender != config.owner {
        return Err(ContractError::Unauthorized {});
    }

    let coins = deps.querier.query_all_balances(env.contract.address)?;

    Ok(Response::new()
        .add_message(CosmosMsg::Bank(BankMsg::Send {
            to_address: deps.api.addr_validate(&addr)?.to_string(),
            amount: coins,
        }))
        .add_attributes(vec![attr("action", "withdraw_fee")]))
}

fn get_existing_token_auction_state(
    storage: &dyn Storage,
    token_id: &str,
    token_address: &str,
) -> Result<TokenAuctionState, ContractError> {
    let key = token_id.to_owned() + token_address;
    let auction_id: Uint128 = match auction_infos().may_load(storage, &key)? {
        None => return Err(ContractError::AuctionDoesNotExist {}),
        Some(auction_info) => auction_info.auction_id,
    };
    let token_auction_state = TOKEN_AUCTION_STATE.load(storage, auction_id.u128())?;

    Ok(token_auction_state)
}

fn get_and_increment_next_auction_id(
    storage: &mut dyn Storage,
    token_id: &str,
    token_address: &str,
) -> Result<Uint128, ContractError> {
    let next_auction_id = NEXT_AUCTION_ID.load(storage)?;
    let incremented_next_auction_id = next_auction_id.checked_add(Uint128::from(1u128))?;
    NEXT_AUCTION_ID.save(storage, &incremented_next_auction_id)?;

    let key = token_id.to_owned() + token_address;

    let mut auction_info = auction_infos().load(storage, &key).unwrap_or_default();
    auction_info.auction_id = next_auction_id;
    if auction_info.token_address.is_empty() {
        auction_info.token_address = token_address.to_owned();
        auction_info.token_id = token_id.to_owned();
    }
    auction_infos().save(storage, &key, &auction_info)?;
    Ok(next_auction_id)
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::AuctionState {
            token_id,
            token_address,
        } => to_binary(&query_auction_state(deps, token_id, token_address)?),
        QueryMsg::AuctionStateById { auction_id } => {
            to_binary(&query_auction_state_by_id(deps, auction_id)?)
        }
        QueryMsg::Bids {
            auction_id,
            start_after,
            limit,
            order_by,
        } => to_binary(&query_bids(deps, auction_id, start_after, limit, order_by)?),
        QueryMsg::AuctionId {
            token_id,
            token_address,
        } => to_binary(&query_auction_id(deps, token_id, token_address)?),
        QueryMsg::AuctionInfosForAddress {
            token_address,
            start_after,
            limit,
        } => to_binary(&query_auction_infos_for_address(
            deps,
            token_address,
            start_after,
            limit,
        )?),
        QueryMsg::ActiveAuctionInfos { wallet } => {
            to_binary(&query_active_auction_infos(deps, wallet)?)
        }
    }
}

pub fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;

    Ok(ConfigResponse {
        owner: config.owner.to_string(),
        tax_fee_bp: config.tax_fee_bp,
    })
}

fn query_auction_id(deps: Deps, token_id: String, token_address: String) -> StdResult<Uint128> {
    let key = token_id + &token_address;
    let auction_info = auction_infos().may_load(deps.storage, &key)?;
    if let Some(auction_info) = auction_info {
        return Ok(auction_info.auction_id);
    }
    Err(StdError::generic_err("AuctionDoesNotExist"))
}

pub fn query_auction_infos_for_address(
    deps: Deps,
    token_address: String,
    start_after: Option<String>,
    limit: Option<u64>,
) -> StdResult<Vec<AuctionInfo>> {
    read_auction_infos(deps.storage, token_address, start_after, limit)
}

pub fn query_active_auction_infos(deps: Deps, wallet: String) -> StdResult<Vec<AuctionInfo>> {
    let auction_infos = ACTIVE_AUCTION_INFOS_BY_OWNER.may_load(deps.storage, wallet)?;
    if let Some(auction_infos) = auction_infos {
        Ok(auction_infos)
    } else {
        Ok(vec![])
    }
}

fn query_bids(
    deps: Deps,
    auction_id: Uint128,
    start_after: Option<u64>,
    limit: Option<u64>,
    order_by: Option<OrderBy>,
) -> StdResult<BidsResponse> {
    let bids = read_bids(
        deps.storage,
        auction_id.u128(),
        start_after,
        limit,
        order_by,
    )?;
    Ok(BidsResponse { bids })
}

fn query_auction_state(
    deps: Deps,
    token_id: String,
    token_address: String,
) -> StdResult<AuctionStateResponse> {
    let token_auction_state_result =
        get_existing_token_auction_state(deps.storage, &token_id, &token_address);
    if let Ok(token_auction_state) = token_auction_state_result {
        return Ok(token_auction_state.into());
    }
    Err(StdError::generic_err("AuctionDoesNotExist"))
}

fn query_auction_state_by_id(deps: Deps, auction_id: Uint128) -> StdResult<AuctionStateResponse> {
    let token_auction_state = TOKEN_AUCTION_STATE.load(deps.storage, auction_id.u128())?;
    Ok(token_auction_state.into())
}

fn query_owner_of(
    querier: QuerierWrapper,
    token_addr: String,
    token_id: String,
) -> Result<OwnerOfResponse, ContractError> {
    let res: OwnerOfResponse = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: token_addr,
        msg: to_binary(&Cw721QueryMsg::OwnerOf {
            token_id,
            include_expired: None,
        })?,
    }))?;

    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default())
}
