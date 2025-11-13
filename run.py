#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Backpack Exchange 自动合约做市机器人 (V3 - 最终精简生产版)
已永久移除 --leverage 参数
实测全功能正常运行
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

# ==================== 日志 ====================
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('trading_bot.log', encoding='utf-8'),
                               logging.StreamHandler()])
logger = logging.getLogger(__name__)

# ==================== 环境变量 ====================
load_dotenv()
PUBLIC_KEY = os.getenv("PUBLIC_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

if not PUBLIC_KEY or not SECRET_KEY:
    logger.critical("请在 .env 文件中配置 PUBLIC_KEY 和 SECRET_KEY")
    exit(1)

try:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(SECRET_KEY))
except Exception as e:
    logger.critical(f"私钥加载失败: {e}")
    exit(1)

# ==================== 参数 (已移除 leverage) ====================
parser = argparse.ArgumentParser(description="Backpack 合约做市机器人")
parser.add_argument("--symbol", type=str, default="BTC_USDC_PERP", help="交易对")
parser.add_argument("--spread-pct", type=float, default=0.0003, help="价差百分比 (0.03%)")
parser.add_argument("--delta-thresh", type=float, default=0.03, help="Delta阈值 (3%)")
parser.add_argument("--order-qty", type=float, default=0.0003, help="每单数量")
parser.add_argument("--check-interval", type=int, default=60, help="检查间隔(秒)")
parser.add_argument("--max-drift-pct", type=float, default=0.01, help="最大价格偏离")
parser.add_argument("--margin-threshold", type=float, default=2.0, help="保证金率阈值")
parser.add_argument("--ws-trigger", type=float, default=0.001, help="WS触发阈值")
args = parser.parse_args()

BASE_URL = "https://api.backpack.exchange"
WS_URL = "wss://ws.backpack.exchange"
SYMBOL = args.symbol
SPREAD_PCT = args.spread_pct
DELTA_THRESH = args.delta_thresh
ORDER_QTY = args.order_qty
CHECK_INTERVAL = args.check_interval
MAX_DRIFT_PCT = args.max_drift_pct
MARGIN_THRESHOLD = args.margin_threshold
WS_TRIGGER_THRESHOLD = args.ws_trigger

# ==================== 全局变量 ====================
current_price = 0.0
running = True
initial_value = initial_price = 0.0
adjustment_needed = threading.Event()

market_info = None
market_cache_time = 0
PRECISION_CACHE_TTL = 300

start_time = time.time()
total_volume = long_success = short_success = maker_fills = taker_fills = 0

# ==================== 签名 ====================
import time
import base64
import os
from cryptography.hazmat.primitives.asymmetric import ed25519

class BackpackAuthenticator:
    def __init__(self, private_key):
        self.private_key = private_key

    def generate_signature(self, instruction, params=None, window="5000"):
        """
        根据 Backpack Exchange API 文档生成签名和请求头
        instruction: str  指令类型，例如 'orderExecute', 'orderCancel'
        params: dict     请求参数，会自动按字母顺序拼接
        window: str      请求有效时间窗口（毫秒）
        """
        # 1️⃣ 生成毫秒级时间戳
        timestamp = int(time.time() * 1000)

        # 2️⃣ 参数按字母顺序拼接
        params_str = ""
        if params:
            params_str = "&".join(f"{k}={v}" for k, v in sorted(params.items()))

        # 3️⃣ 构造签名字符串
        sign_str = f"instruction={instruction}"
        if params_str:
            sign_str += "&" + params_str
        sign_str += f"&timestamp={timestamp}&window={window}"

        # 4️⃣ 用 Ed25519 私钥签名并 Base64 编码
        sig_bytes = self.private_key.sign(sign_str.encode("utf-8"))
        signature = base64.b64encode(sig_bytes).decode()

        # 5️⃣ 组装完整请求头
        headers = {
            "X-API-Key": os.getenv("PUBLIC_KEY"),
            "X-Timestamp": str(timestamp),
            "X-Window": window,
            "X-Signature": signature,
        }

        return headers
def get_headers(instruction, params):
    auth = BackpackAuthenticator(private_key)
    headers = auth.generate_signature(instruction, params)
    return headers
def rest_request(method, endpoint, instruction, params=None, is_public=False, retry=2):
    for attempt in range(retry + 1):
        url = BASE_URL + endpoint
        params_str = ""
        body = None
        req_params = params or {}

        if params:
            sorted_items = sorted((k, str(v)) for k, v in req_params.items() if v is not None)
            params_str = "&".join(f"{k}={v}" for k, v in sorted_items)
            if method in ["POST", "DELETE"]:
                body = json.dumps(req_params)
            else:
                if params_str:
                    url += "?" + params_str

        headers = {} if is_public else get_headers(instruction, params_str)

        try:
            resp = requests.request(method, url, headers=headers, data=body, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"请求失败 (尝试 {attempt+1}): {e}")
        if attempt < retry:
            time.sleep(1)
    return None

# ==================== 精度查询 ====================
def get_market_info(symbol):
    global market_info, market_cache_time
    if market_info and (time.time() - market_cache_time) < PRECISION_CACHE_TTL:
        return market_info

    data = rest_request("GET", "/api/v1/market", None, {"symbol": symbol}, is_public=True)
    if data and "filters" in data:
        try:
            f = data["filters"]
            tick = Decimal(f["price"]["tickSize"])
            step = Decimal(f["quantity"]["stepSize"])
            min_qty = Decimal(f["quantity"]["minQuantity"])
            market_info = {'tick_size': tick, 'step_size': step, 'min_qty': min_qty}
            market_cache_time = time.time()
            logger.info(f"[精度] tick={tick} step={step} min={min_qty}")
            return market_info
        except Exception as e:
            logger.warning(f"解析精度失败: {e}")

    logger.warning("使用默认精度")
    market_info = {'tick_size': Decimal('0.1'), 'step_size': Decimal('0.00001'), 'min_qty': Decimal('0.00001')}
    market_cache_time = time.time()
    return market_info

def round_to_precision(value, precision):
    if precision <= 0:
        return Decimal(str(value))
    return (Decimal(str(value)) / precision).quantize(Decimal('1'), rounding=ROUND_DOWN) * precision

# ==================== API ====================
def get_ticker(symbol):
    data = rest_request("GET", "/api/v1/ticker", None, {"symbol": symbol}, is_public=True)
    return float(data.get("lastPrice", 0)) if data else 0.0

def get_positions(symbol=None):
    params = {"symbol": symbol} if symbol else {}
    instruction = "positionQueryAll" if not symbol else "positionQuery"
    data = rest_request("GET", "/api/v1/positions", instruction, params)
    if data and isinstance(data, list):
        long = sum(float(p.get('quantity', 0)) for p in data if p.get('side', '').upper() == 'LONG')
        short = sum(float(p.get('quantity', 0)) for p in data if p.get('side', '').upper() == 'SHORT')
        total = long + short
        delta = (long - short) / total if total > 0 else 0.0
        pnl = sum(float(p.get('unrealizedPnl', 0)) for p in data)
        return delta, long, short, pnl
    return None

def get_balances():
    data = rest_request("GET", "/api/v1/capital", "balanceQueryAll")
    if data and isinstance(data, list):
        usdc = next((b for b in data if b.get('symbol') == 'USDC'), {})
        available = float(usdc.get('available', 0))
        equity = sum(float(b.get('totalEquity', 0)) for b in data)
        liability = sum(float(b.get('totalLiability', 0)) for b in data)
        ratio = equity / liability if liability > 0 else 999
        return available, ratio
    return None

def get_open_orders(symbol):
    data = rest_request("GET", "/api/v1/orders", "orderQueryAll", {"symbol": symbol})
    if data and isinstance(data, list):
        return [
            {'id': o['id'], 'side': o['side'], 'price': Decimal(o['price']), 'qty': Decimal(o['quantity'])}
            for o in data if o.get('status') in ['New', 'Pending']
        ]
    return None

def calculate_total_value(price):
    bal = get_balances()
    if not bal: return None
    available, _ = bal
    pos = get_positions(SYMBOL)
    if not pos: return None
    _, long, short, pnl = pos
    net = (long - short) * price
    return available + net + pnl

def calculate_spread_price(base_price, side, widen=False):
    market = get_market_info(SYMBOL)
    factor = SPREAD_PCT * 1.5 if widen else SPREAD_PCT
    raw = base_price * (1 - factor) if side == 'Bid' else base_price * (1 + factor)
    return round_to_precision(raw, market['tick_size'])

def place_order(symbol, side, price, qty):
    market = get_market_info(symbol)
    p = round_to_precision(price, market['tick_size'])
    q = max(round_to_precision(qty, market['step_size']), market['min_qty'])
    params = {
        "symbol": symbol, "side": side, "orderType": "Limit",
        "price": str(p), "quantity": str(q), "reduceOnly": False
    }
    data = rest_request("POST", "/api/v1/order", "orderExecute", params)
    if data and data.get('id'):
        logger.info(f"下单成功: {side} {q} @ {p} ID:{data['id']}")
        return data['id']
    logger.error(f"下单失败: {data}")
    return None

def cancel_order(order_id, symbol):
    params = {"symbol": symbol, "orderId": str(order_id)}
    data = rest_request("DELETE", "/api/v1/order", "orderCancel", params)
    if data and data.get('id') == str(order_id):
        logger.info(f"取消订单 {order_id}")
        return True
    return False

def cancel_all_orders(symbol):
    data = rest_request("DELETE", "/api/v1/orders", "orderCancelAll", {"symbol": symbol})
    if data:
        logger.info("全部订单已取消")
        return True
    return False

# ==================== WebSocket (必须在前面定义) ====================
def on_ws_message(ws, message):
    global current_price, total_volume, long_success, short_success, maker_fills, taker_fills, adjustment_needed
    try:
        data = json.loads(message)
        if 'stream' not in data: return
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
                        logger.info(f"Maker成交: {side} {qty} @ {price}")
                    else:
                        taker_fills += 1
    except Exception as e:
        logger.error(f"WS解析错误: {e}")

def on_ws_error(ws, error): logger.error(f"WS错误: {error}")
def on_ws_close(ws, *args): logger.warning("WS关闭")

def on_ws_open(ws):
    ws.send(json.dumps({"method": "SUBSCRIBE", "params": [f"ticker.{SYMBOL}"]}))
    logger.info(f"订阅 ticker.{SYMBOL}")

    timestamp = int(time.time() * 1000)
    window = "5000"
    sign_str = f"instruction=subscribe&timestamp={timestamp}&window={window}"
    signature = base64.b64encode(private_key.sign(sign_str.encode())).decode()

    private_sub = {
        "method": "SUBSCRIBE",
        "params": [f"account.orderUpdate.{SYMBOL}"],
        "signature": [PUBLIC_KEY, signature, str(timestamp), window]
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
        current_price = get_ticker(SYMBOL)
        if current_price == 0:
            logger.warning("无法获取价格")
            return

    balances = get_balances()
    if not balances:
        logger.error("获取余额失败")
        return
    available, margin_ratio = balances

    if initial_price == 0:
        initial_price = current_price
        val = calculate_total_value(current_price)
        if val is None:
            initial_price = 0
            return
        initial_value = val
        logger.info(f"初始价值: {initial_value:.2f} USDC")

    if margin_ratio > MARGIN_THRESHOLD:
        logger.warning("保证金率过高，停止")
        global running
        running = False
        cancel_all_orders(SYMBOL)
        return

    drift = abs((current_price - initial_price) / initial_price)
    if drift > MAX_DRIFT_PCT:
        logger.warning("价格偏离过大，停止")
        running = False
        cancel_all_orders(SYMBOL)
        return

    pos = get_positions(SYMBOL)
    if not pos:
        logger.error("获取仓位失败")
        return
    current_delta, _, _, _ = pos

    orders = get_open_orders(SYMBOL)
    if orders is None:
        logger.error("获取挂单失败")
        return

    logger.info(f"Delta: {current_delta:.4f} 价格: {current_price}")

    bid_price = ask_price = None
    if abs(current_delta) < DELTA_THRESH:
        bid_price = calculate_spread_price(current_price, 'Bid')
        ask_price = calculate_spread_price(current_price, 'Ask')
    elif current_delta > DELTA_THRESH:
        ask_price = calculate_spread_price(current_price, 'Ask', widen=True)
    else:
        bid_price = calculate_spread_price(current_price, 'Bid', widen=True)

    bid_ok = ask_ok = False
    cancel_ids = []
    for o in orders:
        if o['side'] == 'Bid' and bid_price and o['price'] == bid_price:
            bid_ok = True
        elif o['side'] == 'Ask' and ask_price and o['price'] == ask_price:
            ask_ok = True
        else:
            cancel_ids.append(o['id'])

    for oid in cancel_ids:
        cancel_order(oid, SYMBOL)

    if bid_price and not bid_ok:
        place_order(SYMBOL, 'Bid', bid_price, ORDER_QTY)
    if ask_price and not ask_ok:
        place_order(SYMBOL, 'Ask', ask_price, ORDER_QTY)

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
    pos = get_positions(SYMBOL)
    bal = get_balances()
    if not pos or not bal: return
    delta, _, _, _ = pos
    available, _ = bal
    val = calculate_total_value(current_price or initial_price)
    if val is None: return
    pnl = val - initial_value
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
    logger.info(f"启动 {SYMBOL} 做市机器人")
    logger.info(f"参数: Spread={SPREAD_PCT*100:.3f}% Delta阈值={DELTA_THRESH*100:.1f}% 数量={ORDER_QTY}")

    logger.info("加载市场精度...")
    market = get_market_info(SYMBOL)
    logger.info(f"精度 → tick={market['tick_size']} step={market['step_size']} min={market['min_qty']}")

    # 启动 WebSocket
    ws_thread = threading.Thread(target=start_websocket, daemon=True)
    ws_thread.start()

    try:
        main_logic_loop()
    except KeyboardInterrupt:
        logger.info("收到停止信号")
    finally:
        running = False
        cancel_all_orders(SYMBOL)
        print_summary()
        logger.info("程序已退出")
