# -*- coding: utf-8 -*-
"""
Backpack Exchange 自动合约做市策略实现 (精度查询版)
基于纯合约库存中性动态做市策略
作者: Grok (基于用户需求生成)
日期: 2025-11-12

更新: 添加 /markets 查询精度 (tickSize/stepSize), 用于价格/数量 round
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
from websocket import WebSocketApp, enableTrace
from decimal import Decimal, ROUND_DOWN  # 新增: 精度 round

# 配置 logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('trading_bot.log'), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# 加载环境变量
load_dotenv()
PUBLIC_KEY = os.getenv("PUBLIC_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

if not PUBLIC_KEY or not SECRET_KEY:
    PUBLIC_KEY = "your_base64_public_key_here"
    SECRET_KEY = "your_base64_secret_key_here"

private_key = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(SECRET_KEY))

# 命令行参数解析
parser = argparse.ArgumentParser(description="Backpack 合约做市机器人")
parser.add_argument("--symbol", type=str, default="ETH_USDC_PERP", help="交易对符号 (e.g., ETH_USDC_PERP)")
parser.add_argument("--spread-pct", type=float, default=0.001, help="价差百分比 (e.g., 0.001 for 0.1%)")
parser.add_argument("--delta-thresh", type=float, default=0.03, help="Delta 阈值 (e.g., 0.03 for 3%)")
parser.add_argument("--order-qty", type=float, default=0.01, help="每单数量 (e.g., 0.01 ETH)")
parser.add_argument("--leverage", type=int, default=5, help="杠杆倍数 (e.g., 5)")
parser.add_argument("--check-interval", type=int, default=60, help="检查间隔 (秒)")
parser.add_argument("--max-drift-pct", type=float, default=0.01, help="最大价格偏离 (e.g., 0.01 for 1%)")
parser.add_argument("--margin-threshold", type=float, default=2.0, help="维持保证金率阈值 (>2.0)")

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

# 全局变量
current_price = 0.0
current_delta = 0.0
active_orders = []
running = True
initial_value = 0.0
initial_price = 0.0
initial_positions_data = None

# 精度缓存 (5min 过期)
market_info = None
market_cache_time = 0
PRECISION_CACHE_TTL = 300  # 5min

# 日志计数器
start_time = time.time()
total_volume = 0.0
long_success = 0
short_success = 0
maker_fills = 0
taker_fills = 0

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
        "Content-Type": "application/json"
    }

def rest_request(method, endpoint, instruction, params=None, is_public=False, retry=1):
    for attempt in range(retry + 1):
        url = BASE_URL + endpoint
        params_str = ""
        request_params = params
        if params:
            if method == "GET":
                sorted_params = sorted(params.items())
                query_str = "&".join([f"{k}={v}" for k, v in sorted_params])
                url += "?" + query_str
                params_str = query_str
            else:
                if isinstance(params, list):
                    order_strs = []
                    for order in sorted(params, key=lambda o: ''.join(sorted(o.keys()))):
                        order_params = '&'.join([f"{k}={v}" for k, v in sorted(order.items())])
                        order_strs.append(order_params)
                    params_str = '&'.join(order_strs)
                else:
                    sorted_params = sorted(params.items())
                    params_str = "&".join([f"{k}={v}" for k, v in sorted_params])
                request_params = json.dumps(params)

        headers = {"Content-Type": "application/json"} if is_public else get_headers(instruction, params_str)

        try:
            if method == "GET":
                response = requests.get(url, headers=headers)
            else:
                response = requests.post(url, headers=headers, json=request_params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"REST 请求失败 (尝试 {attempt + 1}): {e}")
            if attempt < retry:
                time.sleep(1)
            else:
                return None

def get_market_info(symbol):
    """
    查询交易对精度 (tickSize, stepSize, minQty)
    :param symbol: 交易对
    :return: dict {'tick_size': Decimal, 'step_size': Decimal, 'min_qty': Decimal}
    """
    global market_info, market_cache_time
    if market_info and (time.time() - market_cache_time) < PRECISION_CACHE_TTL:
        return market_info

    data = rest_request("GET", "/markets", None, None, is_public=True)
    if data and 'data' in data:
        for market in data['data']:
            if market.get('symbol') == symbol:
                tick_size = Decimal(market.get('tickSize', '0.1'))  # 默认 0.1
                step_size = Decimal(market.get('stepSize', '0.01'))  # 默认 0.01
                min_qty = Decimal(market.get('minQty', '0.001'))  # 默认 0.001
                market_info = {'tick_size': tick_size, 'step_size': step_size, 'min_qty': min_qty}
                market_cache_time = time.time()
                logger.info(f"{symbol} 精度: tickSize={tick_size}, stepSize={step_size}, minQty={min_qty}")
                return market_info
    logger.warning(f"未找到 {symbol} 精度，使用默认")
    return {'tick_size': Decimal('0.1'), 'step_size': Decimal('0.01'), 'min_qty': Decimal('0.001')}

def round_to_precision(value, precision):
    """
    Round value to precision (tickSize or stepSize)
    :param value: float/Decimal
    :param precision: Decimal tick/step size
    :return: rounded Decimal
    """
    if precision == 0:
        return Decimal(str(value))
    return (Decimal(str(value)) / precision).quantize(Decimal('1'), rounding=ROUND_DOWN) * precision

def get_ticker(symbol):
    data = rest_request("GET", "/ticker", None, {"symbol": symbol}, is_public=True)
    try:
        return float(data['data'][0]['lastPrice']) if data and 'data' in data and data['data'] else 0.0
    except (KeyError, IndexError, ValueError):
        return 0.0

def get_positions(symbol=None):
    params = {"symbol": symbol} if symbol else {}
    data = rest_request("GET", "/position", "positionQuery", params)
    if data and 'data' in data:
        long_size = sum(float(p.get('size', 0)) for p in data['data'] if p.get('positionSide', '').upper() == 'LONG')
        short_size = sum(float(p.get('size', 0)) for p in data['data'] if p.get('positionSide', '').upper() == 'SHORT')
        total_exposure = long_size + short_size
        delta = (long_size - short_size) / total_exposure if total_exposure > 0 else 0.0
        unrealized_pnl = sum(float(p.get('unrealizedPnL', 0)) for p in data['data'])
        return delta, long_size, short_size, unrealized_pnl
    return 0.0, 0.0, 0.0, 0.0

def get_balances():
    data = rest_request("GET", "/balance", "balanceQuery")
    try:
        usdc_balance = next((b for b in data['data'] if b['asset'] == 'USDC'), {})
        available = float(usdc_balance.get('available', 0.0))
        total_equity = float(data.get('totalEquity', 1.0))
        total_liability = float(data.get('totalLiability', 1.0))
        margin_ratio = total_equity / total_liability if total_liability > 0 else 1.0
        return available, margin_ratio
    except (KeyError, ValueError):
        return 0.0, 1.0

def calculate_total_value(price):
    available_usdc, _ = get_balances()
    _, long_size, short_size, unrealized_pnl = get_positions(SYMBOL)
    net_position_value = (long_size - short_size) * price
    return available_usdc + net_position_value + unrealized_pnl

def calculate_spread_price(base_price, side, widen=False):
    """
    计算挂单价格 (应用 tickSize round)
    """
    market = get_market_info(SYMBOL)
    tick_size = market['tick_size']
    factor = SPREAD_PCT * 1.5 if widen else SPREAD_PCT
    if side == 'Bid':
        raw_price = base_price * (1 - factor)
    else:
        raw_price = base_price * (1 + factor)
    return round_to_precision(raw_price, tick_size)

def place_order(symbol, side, order_type, price, qty):
    """
    下单 (应用 stepSize round for qty, tickSize for price)
    """
    market = get_market_info(symbol)
    step_size = market['step_size']
    min_qty = market['min_qty']
    rounded_price = round_to_precision(price, market['tick_size'])
    rounded_qty = max(round_to_precision(qty, step_size), min_qty)  # 确保 >= min_qty

    order_params = [{
        "symbol": symbol,
        "side": side,
        "orderType": order_type,
        "price": str(rounded_price),
        "quantity": str(rounded_qty),
        "reduceOnly": False
    }]
    data = rest_request("POST", "/orders", "orderExecute", order_params)
    try:
        order_id = data['data'][0].get('orderId')
        active_orders.append(order_id)
        logger.info(f"下单成功: {side} {rounded_qty} @ {rounded_price}, ID: {order_id}")
        return order_id
    except (KeyError, IndexError):
        logger.error(f"下单失败: {data}")
        return None

def cancel_all_orders(symbol):
    params = {"symbol": symbol} if symbol else {}
    data = rest_request("POST", "/order/cancelAll", "orderCancelAll", params)
    if data:
        global active_orders
        active_orders = []
        logger.info("所有订单已取消")

# WebSocket 处理 (不变)
def on_ws_message(ws, message):
    global current_price, total_volume, long_success, short_success, maker_fills, taker_fills
    try:
        data = json.loads(message)
        stream = data.get('stream')
        payload = data.get('data', data)

        if stream == f"ticker.{SYMBOL}":
            new_price = float(payload.get('lastPrice', 0))
            if abs(new_price - current_price) / current_price > WS_TRIGGER_THRESHOLD:
                logger.info(f"价格变化触发调整: {current_price} -> {new_price}")
                adjust_orders()  # 实时触发
            current_price = new_price
            logger.info(f"实时价格更新: {current_price}")

        elif stream == f"orderUpdate.{SYMBOL}":
            last_qty = float(payload.get('l', 0))
            if last_qty > 0:
                logger.info("填充事件触发调整")
                adjust_orders()  # 填充后立即调整
                qty = last_qty
                price = float(payload.get('L', 0))
                side = payload.get('S')
                volume = qty * price
                total_volume += volume
                
                if side == 'Bid':
                    long_success += 1
                elif side == 'Ask':
                    short_success += 1
                
                is_maker = payload.get('m', False)
                if is_maker:
                    maker_fills += 1
                    logger.info(f"订单填充 (Maker): {side} {qty} @ {price}, 交易量: {volume} USDC")
                else:
                    taker_fills += 1
                    logger.info(f"订单填充 (Taker): {side} {qty} @ {price}, 交易量: {volume} USDC")
    except Exception as e:
        logger.error(f"WS 消息处理错误: {e}")

def on_ws_error(ws, error):
    logger.error(f"WebSocket 错误: {error}")

def on_ws_close(ws, close_status_code, close_msg):
    logger.warning("WebSocket 关闭")

def on_ws_open(ws):
    subscribe_msg = {"method": "SUBSCRIBE", "params": [f"ticker.{SYMBOL}"]}
    ws.send(json.dumps(subscribe_msg))
    logger.info(f"订阅公共流: ticker.{SYMBOL}")

    timestamp = int(time.time() * 1000)
    window = "5000"
    params_list = [f"orderUpdate.{SYMBOL}"]
    params_str = f"streams={json.dumps(params_list)}"
    sign_str = f"instruction=subscribe&{params_str}&timestamp={timestamp}&window={window}"
    signature_bytes = private_key.sign(sign_str.encode('utf-8'))
    encoded_signature = base64.b64encode(signature_bytes).decode('utf-8')
    private_sub = {
        "method": "SUBSCRIBE",
        "params": params_list,
        "signature": encoded_signature,
        "timestamp": timestamp,
        "window": window
    }
    ws.send(json.dumps(private_sub))
    logger.info(f"订阅私有流: orderUpdate.{SYMBOL}")

    def ping_loop():
        while running:
            time.sleep(30)
            if ws.sock and ws.sock.connected:
                ws.send(json.dumps({"method": "PING"}))
                logger.debug("发送 WS PING")
    ping_thread = threading.Thread(target=ping_loop)
    ping_thread.daemon = True
    ping_thread.start()

def start_websocket():
    ws = WebSocketApp(WS_URL,
                      on_open=on_ws_open,
                      on_message=on_ws_message,
                      on_error=on_ws_error,
                      on_close=on_ws_close)
    ws.run_forever()

def calculate_spread_price(base_price, side, widen=False):
    market = get_market_info(SYMBOL)
    tick_size = market['tick_size']
    factor = SPREAD_PCT * 1.5 if widen else SPREAD_PCT
    if side == 'Bid':
        raw_price = base_price * (1 - factor)
    else:
        raw_price = base_price * (1 + factor)
    return round_to_precision(raw_price, tick_size)

def adjust_orders():
    """
    订单调整逻辑 (实时或定时调用)
    """
    with adjust_lock:  # 防并发
        if current_price == 0:
            current_price = get_ticker(SYMBOL)
            if current_price == 0:
                logger.warning("无法获取价格，跳过调整")
                return
            global initial_price, initial_value, initial_positions_data
            if initial_price == 0:
                initial_price = current_price
                initial_value = calculate_total_value(current_price)
                initial_positions_data = get_positions(SYMBOL)
                logger.info(f"初始价格: {initial_price}, 初始总价值: {initial_value:.2f} USDC")

        _, margin_ratio = get_balances()
        if margin_ratio > MARGIN_THRESHOLD:
            logger.warning(f"保证金率过高 ({margin_ratio:.2f})，暂停运行")
            running = False
            cancel_all_orders(SYMBOL)
            return

        drift = abs((current_price - initial_price) / initial_price)
        if drift > MAX_DRIFT_PCT:
            logger.warning(f"价格偏离过大 ({drift:.2%})，暂停运行")
            running = False
            cancel_all_orders(SYMBOL)
            return

        current_delta, _, _, _ = get_positions(SYMBOL)

        if active_orders:
            cancel_all_orders(SYMBOL)

        if abs(current_delta) < DELTA_THRESH:
            buy_price = calculate_spread_price(current_price, 'Bid')
            sell_price = calculate_spread_price(current_price, 'Ask')
            place_order(SYMBOL, 'Bid', 'Limit', buy_price, ORDER_QTY)
            place_order(SYMBOL, 'Ask', 'Limit', sell_price, ORDER_QTY)
        elif current_delta > DELTA_THRESH:
            sell_price = calculate_spread_price(current_price, 'Ask', widen=True)
            place_order(SYMBOL, 'Ask', 'Limit', sell_price, ORDER_QTY)
        else:
            buy_price = calculate_spread_price(current_price, 'Bid', widen=True)
            place_order(SYMBOL, 'Bid', 'Limit', buy_price, ORDER_QTY)

        logger.info(f"Delta: {current_delta:.4f}, 价格: {current_price}, 已调整订单")

def fallback_adjust_loop():
    """
    Fallback 定时调整 (WS 断连时)
    """
    while running:
        time.sleep(CHECK_INTERVAL)
        if running:
            adjust_orders()

def print_summary():
    global current_delta, start_time, total_volume, initial_value
    runtime = time.time() - start_time
    current_delta, _, _, _ = get_positions(SYMBOL)
    available_usdc, _ = get_balances()
    current_value = calculate_total_value(current_price)
    pnl = current_value - initial_value
    wear_rate = (pnl / total_volume * 100) if total_volume > 0 else 0.0

    print("\n=== 运行汇总日志 ===")
    print(f"运行时间: {runtime:.2f} 秒 ({datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')} 启动)")
    print(f"总交易量: {total_volume:.2f} USDC")
    print(f"成功 Long 次数: {long_success}")
    print(f"成功 Short 次数: {short_success}")
    print(f"Make 填充次数: {maker_fills}")
    print(f"Take 填充次数: {taker_fills}")
    print(f"总盈亏 (PNL): {pnl:.2f} USDC (当前价值: {current_value:.2f}, 初始价值: {initial_value:.2f})")
    print(f"磨损率: {wear_rate:.4f}% (PNL / Volume)")
    print(f"当前仓位 Delta: {current_delta:.4f}")
    print(f"Delta 阈值: {DELTA_THRESH:.4f} ({DELTA_THRESH*100:.2f}%)")
    print(f"当前 USDC 可用余额: {available_usdc:.2f}")
    print("==================\n")

if __name__ == "__main__":
    logger.info("启动 Backpack 合约做市机器人")
    print(f"配置: 符号={SYMBOL}, 价差={SPREAD_PCT*100:.2f}%, Delta阈值={DELTA_THRESH*100:.2f}%, 订单量={ORDER_QTY}, 杠杆={LEVERAGE}")

    # 启动 WebSocket 线程
    ws_thread = threading.Thread(target=start_websocket)
    ws_thread.daemon = True
    ws_thread.start()

    # 启动 fallback 定时线程
    fallback_thread = threading.Thread(target=fallback_adjust_loop)
    fallback_thread.daemon = True
    fallback_thread.start()

    # 等待 WS 就绪
    time.sleep(5)

    # 设置杠杆
    leverage_params = {"leverageLimit": str(LEVERAGE)}
    rest_request("POST", "/account", "accountUpdate", leverage_params)

    # 初始调整
    adjust_orders()

    try:
        # 主线程等待 (WS 驱动)
        while running:
            time.sleep(1)  # 轻量等待
    except KeyboardInterrupt:
        logger.info("收到中断信号，停止机器人")
    finally:
        running = False
        cancel_all_orders(SYMBOL)
        time.sleep(2)  # 等待线程结束
        print_summary()
        logger.info("机器人已停止")
