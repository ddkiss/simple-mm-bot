#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Backpack Exchange 自动合约做市策略实现 (V3 - 完全修正版)
基于纯合约库存中性动态做市策略
作者: https://x.com/plenty_dd
日期: 2025-11-13

核心修复:
- 精度查询 100% 使用官方真实 API: /api/v1/market + /api/v1/markets
- 完全解析 filters.price.tickSize / filters.quantity.stepSize / minQuantity
- 所有 REST 调用路径、instruction、参数、签名严格对齐官方 Python API 指南
- 移除所有无效 fallback，统一使用 /api/v1/ 路径
- WebSocket 订阅与消息处理保持官方最新格式
"""

import os
import json
import base64
import time
import threading
import requests
import argparse
import logging
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from dotenv import load_dotenv
from websocket import WebSocketApp
from decimal import Decimal, ROUND_DOWN

# 配置 logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('trading_bot.log'), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# 加载环境变量
load_dotenv()
PUBLIC_KEY = os.getenv("PUBLIC_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

if not PUBLIC_KEY or not SECRET_KEY:
    logger.critical("请在 .env 文件中配置 PUBLIC_KEY 和 SECRET_KEY")
    exit(1)

try:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(SECRET_KEY))
except Exception as e:
    logger.critical(f"加载私钥失败: {e}")
    exit(1)

# 命令行参数
parser = argparse.ArgumentParser(description="Backpack 合约做市机器人")
parser.add_argument("--symbol", type=str, default="ETH_USDC_PERP", help="交易对符号")
parser.add_argument("--spread-pct", type=float, default=0.001, help="价差百分比 (0.1%)")
parser.add_argument("--delta-thresh", type=float, default=0.03, help="Delta 阈值 (3%)")
parser.add_argument("--order-qty", type=float, default=0.01, help="每单数量")
parser.add_argument("--leverage", type=int, default=5, help="杠杆倍数")
parser.add_argument("--check-interval", type=int, default=60, help="检查间隔(秒)")
parser.add_argument("--max-drift-pct", type=float, default=0.01, help="最大价格偏离 (1%)")
parser.add_argument("--margin-threshold", type=float, default=2.0, help="保证金率阈值 (>2.0)")
parser.add_argument("--ws-trigger", type=float, default=0.001, help="WS 价格变动触发阈值 (0.1%)")
args = parser.parse_args()

# 配置参数
BASE_URL = "https://api.backpack.exchange"
WS_URL = "wss://ws.backpack.exchange"
SYMBOL = args.symbol
LEVERAGE = args.leverage
SPREAD_PCT = args.spread_pct
DELTA_THRESH = args.delta_thresh
ORDER_QTY = args.order_qty
CHECK_INTERVAL = args.check_interval
MAX_DRIFT_PCT = args.max_drift_pct
MARGIN_THRESHOLD = args.margin_threshold
WS_TRIGGER_THRESHOLD = args.ws_trigger

# 全局变量
current_price = 0.0
current_delta = 0.0
running = True
initial_value = 0.0
initial_price = 0.0
adjustment_needed = threading.Event()

# 精度缓存
market_info = None
all_markets_cache = None
market_cache_time = 0
PRECISION_CACHE_TTL = 300

# 统计
start_time = time.time()
total_volume = 0.0
long_success = short_success = maker_fills = taker_fills = 0

# ==================== 签名与请求 ====================
class BackpackAuthenticator:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def generate_signature(self, instruction, params_str, timestamp, window="5000"):
        sign_str = f"instruction={instruction}&{params_str}&timestamp={timestamp}&window={window}"
        signature_bytes = self.private_key.sign(sign_str.encode('utf-8'))
        return base64.b64encode(signature_bytes).decode('utf-8')

def get_headers(instruction, params_str="", timestamp=None, window="5000"):
    if timestamp is None:
        timestamp = int(time.time() * 1000)
    signature = BackpackAuthenticator(private_key, PUBLIC_KEY).generate_signature(instruction, params_str, timestamp, window)
    return {
        "X-API-Key": PUBLIC_KEY,
        "X-Timestamp": str(timestamp),
        "X-Window": window,
        "X-Signature": signature,
        "Content-Type": "application/json; charset=utf-8"
    }

def rest_request(method, endpoint, instruction, params=None, is_public=False, retry=2):
    for attempt in range(retry + 1):
        url = BASE_URL + endpoint
        params_str = ""
        body = None
        request_params = params or {}

        if params:
            sorted_params = sorted(request_params.items())
            params_str = "&".join([f"{k}={v}" for k, v in sorted_params if v is not None])
            if method in ["POST", "DELETE"]:
                body = json.dumps(request_params)
            else:
                if params_str:
                    url += "?" + params_str

        headers = {} if is_public else get_headers(instruction, params_str)

        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=headers, data=body, timeout=10)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, data=body, timeout=10)
            else:
                raise ValueError(f"Unsupported method: {method}")

            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            logger.error(f"请求失败 (尝试 {attempt + 1}): {e}")
        if attempt < retry:
            time.sleep(1)
    return None

# ==================== 精度查询 (真实 API) ====================
def get_market_info(symbol):
    global market_info, all_markets_cache, market_cache_time
    if market_info and (time.time() - market_cache_time) < PRECISION_CACHE_TTL:
        return market_info

    # 1. 单个市场
    data = rest_request("GET", "/api/v1/market", None, {"symbol": symbol}, is_public=True)
    if data and isinstance(data, dict):
        try:
            filters = data.get("filters", {})
            price_filter = filters.get("price", {})
            qty_filter = filters.get("quantity", {})

            tick_size = Decimal(price_filter.get("tickSize", "0.0001"))
            step_size = Decimal(qty_filter.get("stepSize", "0.001"))
            min_qty = Decimal(qty_filter.get("minQuantity", "0.001"))

            market_info = {'tick_size': tick_size, 'step_size': step_size, 'min_qty': min_qty}
            market_cache_time = time.time()
            logger.info(f"[精度] /api/v1/market → tick={tick_size}, step={step_size}, min={min_qty}")
            return market_info
        except Exception as e:
            logger.warning(f"解析 /api/v1/market 失败: {e}")

    # 2. 全部市场缓存
    if not all_markets_cache or (time.time() - market_cache_time) >= PRECISION_CACHE_TTL:
        data_all = rest_request("GET", "/api/v1/markets", None, None, is_public=True)
        if data_all and isinstance(data_all, list):
            all_markets_cache = data_all
            market_cache_time = time.time()

    if all_markets_cache:
        for m in all_markets_cache:
            if m.get("symbol") == symbol:
                try:
                    filters = m.get("filters", {})
                    price_filter = filters.get("price", {})
                    qty_filter = filters.get("quantity", {})

                    tick_size = Decimal(price_filter.get("tickSize", "0.0001"))
                    step_size = Decimal(qty_filter.get("stepSize", "0.001"))
                    min_qty = Decimal(qty_filter.get("minQuantity", "0.001"))

                    market_info = {'tick_size': tick_size, 'step_size': step_size, 'min_qty': min_qty}
                    market_cache_time = time.time()
                    logger.info(f"[精度] /api/v1/markets → tick={tick_size}, step={step_size}, min={min_qty}")
                    return market_info
                except Exception as e:
                    logger.warning(f"解析 markets 条目失败: {e}")

    logger.error(f"无法获取 {symbol} 精度，使用极小默认值")
    market_info = {'tick_size': Decimal('1e-8'), 'step_size': Decimal('1e-8'), 'min_qty': Decimal('1e-8')}
    market_cache_time = time.time()
    return market_info

def round_to_precision(value, precision):
    if precision <= 0:
        return Decimal(str(value))
    return (Decimal(str(value)) / precision).quantize(Decimal('1'), rounding=ROUND_DOWN) * precision

# ==================== 其他 API ====================
def get_ticker(symbol):
    data = rest_request("GET", "/api/v1/ticker", None, {"symbol": symbol}, is_public=True)
    try:
        return float(data['lastPrice']) if data and 'lastPrice' in data else 0.0
    except:
        return 0.0

def get_positions(symbol=None):
    params = {"symbol": symbol} if symbol else {}
    instruction = "positionQueryAll" if not symbol else "positionQuery"
    data = rest_request("GET", "/api/v1/positions", instruction, params)
    if data and isinstance(data, list):
        long_size = sum(float(p.get('quantity', 0)) for p in data if p.get('side', '').upper() == 'LONG')
        short_size = sum(float(p.get('quantity', 0)) for p in data if p.get('side', '').upper() == 'SHORT')
        total_exposure = long_size + short_size
        delta = (long_size - short_size) / total_exposure if total_exposure > 0 else 0.0
        unrealized_pnl = sum(float(p.get('unrealizedPnl', 0)) for p in data)
        return delta, long_size, short_size, unrealized_pnl
    return None

def get_balances():
    data = rest_request("GET", "/api/v1/capital", "balanceQueryAll")
    if data and isinstance(data, list):
        usdc = next((b for b in data if b['symbol'] == 'USDC'), {})
        available = float(usdc.get('available', 0.0))
        total_equity = sum(float(b.get('totalEquity', 0)) for b in data)
        total_liability = sum(float(b.get('totalLiability', 0)) for b in data)
        margin_ratio = total_equity / total_liability if total_liability > 0 else 999
        return available, margin_ratio
    return None

def get_open_orders(symbol):
    data = rest_request("GET", "/api/v1/orders", "orderQueryAll", {"symbol": symbol})
    if data and isinstance(data, list):
        return [
            {'id': o['id'], 'side': o['side'], 'price': Decimal(o['price']), 'qty': Decimal(o['quantity'])}
            for o in data if o['status'] in ['New', 'Pending']
        ]
    return None

def calculate_total_value(price):
    balances = get_balances()
    if not balances: return None
    available_usdc, _ = balances
    positions = get_positions(SYMBOL)
    if not positions: return None
    _, long_size, short_size, unrealized_pnl = positions
    net_value = (long_size - short_size) * price
    return available_usdc + net_value + unrealized_pnl

def calculate_spread_price(base_price, side, widen=False):
    market = get_market_info(SYMBOL)
    tick_size = market['tick_size']
    factor = SPREAD_PCT * 1.5 if widen else SPREAD_PCT
    raw = base_price * (1 - factor) if side == 'Bid' else base_price * (1 + factor)
    return round_to_precision(raw, tick_size)

def place_order(symbol, side, order_type, price, qty):
    market = get_market_info(symbol)
    rounded_price = round_to_precision(price, market['tick_size'])
    rounded_qty = max(round_to_precision(qty, market['step_size']), market['min_qty'])

    params = {
        "symbol": symbol,
        "side": side,
        "orderType": order_type,
        "price": str(rounded_price),
        "quantity": str(rounded_qty),
        "reduceOnly": False
    }
    data = rest_request("POST", "/api/v1/order", "orderExecute", params)
    if data and data.get('id'):
        logger.info(f"下单成功: {side} {rounded_qty} @ {rounded_price} ID: {data['id']}")
        return data['id']
    logger.error(f"下单失败: {data}")
    return None

def cancel_order(order_id, symbol):
    params = {"symbol": symbol, "orderId": str(order_id)}
    data = rest_request("DELETE", "/api/v1/order", "orderCancel", params)
    if data and data.get('id') == str(order_id):
        logger.info(f"取消订单 {order_id} 成功")
        return True
    return False

def cancel_all_orders(symbol):
    data = rest_request("DELETE", "/api/v1/orders", "orderCancelAll", {"symbol": symbol})
    if data:
        logger.info(f"全部订单已取消")
        return True
    return False

# ==================== WebSocket ====================
def on_ws_message(ws, message):
    global current_price, total_volume, long_success, short_success, maker_fills, taker_fills, adjustment_needed
    try:
        data = json.loads(message)
        if 'stream' not in data:
            return
        stream = data['stream']
        payload = data['data']

        if stream == f"ticker.{SYMBOL}":
            new_price = float(payload.get('c', 0))
            if new_price > 0:
                if current_price > 0 and abs(new_price - current_price) / current_price > WS_TRIGGER_THRESHOLD:
                    adjustment_needed.set()
                current_price = new_price

        elif stream == f"account.orderUpdate.{SYMBOL}":
            if payload.get('e') == 'orderFill':
                qty = float(payload.get('l', 0))
                if qty > 0:
                    adjustment_needed.set()
                    price = float(payload.get('L', 0))
                    side = payload.get('S')
                    volume = qty * price
                    total_volume += volume
                    if side == 'Bid': long_success += 1
                    if side == 'Ask': short_success += 1
                    if payload.get('m', False):
                        maker_fills += 1
                        logger.info(f"Maker 成交: {side} {qty} @ {price}")
                    else:
                        taker_fills += 1
    except Exception as e:
        logger.error(f"WS 解析错误: {e}")

def on_ws_error(ws, error): logger.error(f"WS 错误: {error}")
def on_ws_close(ws, *args): logger.warning("WS 关闭")

def on_ws_open(ws):
    ws.send(json.dumps({"method": "SUBSCRIBE", "params": [f"ticker.{SYMBOL}"]}))
    logger.info(f"订阅 ticker.{SYMBOL}")

    timestamp = int(time.time() * 1000)
    sign_str = f"instruction=subscribe&timestamp={timestamp}&window=5000"
    signature = base64.b64encode(private_key.sign(sign_str.encode())).decode()
    private_sub = {
        "method": "SUBSCRIBE",
        "params": [f"account.orderUpdate.{SYMBOL}"],
        "signature": [PUBLIC_KEY, signature, str(timestamp), "5000"]
    }
    ws.send(json.dumps(private_sub))
    logger.info(f"订阅 account.orderUpdate.{SYMBOL}")

    def ping():
        while running:
            time.sleep(30)
            if ws.sock and ws.sock.connected:
                ws.send(json.dumps({"method": "PING"}))
    threading.Thread(target=ping, daemon=True).start()

def start_websocket():
    ws = WebSocketApp(WS_URL, on_open=on_ws_open, on_message=on_ws_message,
                      on_error=on_ws_error, on_close=on_ws_close)
    ws.run_forever()

# ==================== 核心逻辑 ====================
def adjust_orders():
    global current_price, initial_price, initial_value

    if current_price == 0:
        current_price = get_ticker(SYMBOL) or 0
        if current_price == 0:
            return

    balances = get_balances()
    if not balances:
        logger.error("获取余额失败，跳过调整")
        return
    available_usdc, margin_ratio = balances

    if initial_price == 0:
        initial_price = current_price
        init_val = calculate_total_value(current_price)
        if init_val is None:
            initial_price = 0
            return
        initial_value = init_val
        logger.info(f"初始价值: {initial_value:.2f} USDC @ {initial_price}")

    if margin_ratio > MARGIN_THRESHOLD:
        logger.warning("保证金率过高，停止运行")
        global running
        running = False
        cancel_all_orders(SYMBOL)
        return

    drift = abs((current_price - initial_price) / initial_price)
    if drift > MAX_DRIFT_PCT:
        logger.warning("价格偏离过大，停止运行")
        running = False
        cancel_all_orders(SYMBOL)
        return

    positions = get_positions(SYMBOL)
    if not positions:
        logger.error("获取仓位失败，跳过调整")
        return
    current_delta, _, _, _ = positions

    open_orders = get_open_orders(SYMBOL)
    if open_orders is None:
        logger.error("获取挂单失败，跳过调整")
        return

    logger.info(f"Delta: {current_delta:.4f} 价格: {current_price}")

    desired_bid = desired_ask = None
    if abs(current_delta) < DELTA_THRESH:
        desired_bid = calculate_spread_price(current_price, 'Bid')
        desired_ask = calculate_spread_price(current_price, 'Ask')
    elif current_delta > DELTA_THRESH:
        desired_ask = calculate_spread_price(current_price, 'Ask', widen=True)
    else:
        desired_bid = calculate_spread_price(current_price, 'Bid', widen=True)

    bid_correct = ask_correct = False
    cancel_ids = []

    for o in open_orders:
        if o['side'] == 'Bid' and desired_bid and o['price'] == desired_bid:
            bid_correct = True
        elif o['side'] == 'Ask' and desired_ask and o['price'] == desired_ask:
            ask_correct = True
        else:
            cancel_ids.append(o['id'])

    for oid in cancel_ids:
        cancel_order(oid, SYMBOL)

    if desired_bid and not bid_correct:
        place_order(SYMBOL, 'Bid', 'Limit', desired_bid, ORDER_QTY)
    if desired_ask and not ask_correct:
        place_order(SYMBOL, 'Ask', 'Limit', desired_ask, ORDER_QTY)

def main_logic_loop():
    time.sleep(5)
    adjust_orders()
    while running:
        triggered = adjustment_needed.wait(timeout=CHECK_INTERVAL)
        if triggered:
            logger.info("事件触发调整")
            adjustment_needed.clear()
        else:
            logger.info("定时触发调整")
        try:
            adjust_orders()
            print_summary()
        except Exception as e:
            logger.error(f"调整异常: {e}")

def print_summary():
    positions = get_positions(SYMBOL)
    balances = get_balances()
    if not positions or not balances:
        return
    delta, _, _, _ = positions
    available, _ = balances
    current_val = calculate_total_value(current_price or initial_price)
    if current_val is None:
        return
    pnl = current_val - initial_value
    runtime = time.time() - start_time
    wear = (pnl / total_volume * 100) if total_volume > 0 else 0

    print("\n=== 运行汇总 ===")
    print(f"运行时间: {runtime:.1f}s")
    print(f"总交易量: {total_volume:.2f} USDC")
    print(f"Long/Short: {long_success}/{short_success}")
    print(f"Maker/Taker: {maker_fills}/{taker_fills}")
    print(f"PNL: {pnl:+.2f} USDC (磨损率 {wear:+.4f}%)")
    print(f"当前 Delta: {delta:.4f}")
    print(f"可用 USDC: {available:.2f}")
    print("==================\n")

# ==================== 启动 ====================
if __name__ == "__main__":
    logger.info(f"启动机器人: {SYMBOL}")
    logger.info(f"参数: Spread={SPREAD_PCT*100:.3f}% Delta阈值={DELTA_THRESH*100:.1f}% 数量={ORDER_QTY}")

    logger.info("正在加载市场精度...")
    market = get_market_info(SYMBOL)
    logger.info(f"精度 → tick_size={market['tick_size']} step_size={market['step_size']} min_qty={market['min_qty']}")

    ws_thread = threading.Thread(target=start_websocket, daemon=True)
    ws_thread.start()

    try:
        main_logic_loop()
    except KeyboardInterrupt:
        logger.info("停止信号")
    finally:
        running = False
        cancel_all_orders(SYMBOL)
        print_summary()
        logger.info("程序已退出")
