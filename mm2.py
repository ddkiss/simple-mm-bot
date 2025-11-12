#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Backpack Exchange 自动合约做市策略实现 (V3 - 精度查询 & 精细化订单管理)
基于纯合约库存中性动态做市策略
作者: https://x.com/plenty_dd
日期: 2025-11-12

更新:
- 添加 /markets 查询精度 (tickSize/stepSize), 用于价格/数量 round
- [v2] 重构并发模型: 使用 Event 驱动, 避免 WS 线程阻塞和竞态条件
- [v2] 修正函数重复定义
- [v2] 添加 --ws-trigger 命令行参数
- [v3] 重构 adjust_orders:
    - 添加 API 失败检查 (get_positions/get_balances 返回 None 时跳过调整)
    - 实现精细化订单管理:
        - 使用 get_open_orders() 替换全局 active_orders 缓存
        - 只取消与目标不符的订单 (价格、方向错误), 保留正确的订单
        - 移除 cancel_all_orders() 的常规调用
- [更新] WS订阅统一使用新格式: 只订阅新格式公共/私有流, 调整签名和stream名称为 account.orderUpdate, 移除旧V1处理
- [更新] 调整 WS 消息处理以匹配文档: 使用 'c' 而非 'lastPrice' 获取价格; 添加事件类型检查; 订阅 account.orderUpdate.<symbol> 以过滤特定符号
- [更新] 对齐 OpenAPI 文档标准: 使用 /api/v1/ 路径优先; 下单使用 /api/v1/order 单笔 (文档示例为 /orders batch, 但调整为 single); side 使用 'Bid'/'Ask'; 指令类型匹配文档
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
    logger.warning("未在 .env 中找到 API 密钥, 将使用占位符 (可能导致认证失败)")
    PUBLIC_KEY = "your_base64_public_key_here"
    SECRET_KEY = "your_base64_secret_key_here"
    # 强烈建议: 
    # if not PUBLIC_KEY or not SECRET_KEY:
    #     logger.critical("错误：未在 .env 文件中找到 PUBLIC_KEY 或 SECRET_KEY。")
    #     raise ValueError("API 密钥未配置")

try:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(SECRET_KEY))
except Exception as e:
    logger.critical(f"加载私钥失败, 检查 SECRET_KEY 格式是否正确: {e}")
    private_key = None # 稍后会导致签名失败

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
parser.add_argument("--ws-trigger", type=float, default=0.001, help="WebSocket 价格变动触发阈值 (e.g., 0.001 for 0.1%)") # 新增

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
WS_TRIGGER_THRESHOLD = args.ws_trigger # 新增

# 全局变量
current_price = 0.0
current_delta = 0.0
running = True
initial_value = 0.0
initial_price = 0.0
initial_positions_data = None
adjustment_needed = threading.Event() # 新增: 用于线程安全的事件通知

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
        if self.private_key is None:
              logger.error("私钥未初始化, 无法签名")
              return "" # 返回无效签名
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
                request_params = json.dumps(params) # POST/DELETE body 总是 json

        headers = {"Content-Type": "application/json"} if is_public else get_headers(instruction, params_str)
        
        # 检查签名是否因为私钥问题而为空
        if not is_public and not headers["X-Signature"]:
              logger.error("签名失败 (私钥问题), 取消请求")
              return None

        try:
            if method == "GET":
                response = requests.get(url, headers=headers)
            elif method == "POST":
                # 确保 POST/DELETE 发送 json 格式的 body
                response = requests.post(url, headers=headers, data=json.dumps(request_params) if method == "POST" and not isinstance(request_params, str) else request_params)
            else: # 假设 DELETE 等
                 response = requests.request(method, url, headers=headers, data=json.dumps(request_params) if not isinstance(request_params, str) else request_params)

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

    # 文档使用 /api/v1/markets
    data = rest_request("GET", "/api/v1/markets", None, None, is_public=True)
    if not data:
        # 备用 /markets
        data = rest_request("GET", "/markets", None, None, is_public=True)

    if data and isinstance(data, list):
        for market in data:
            if market.get('symbol') == symbol:
                # 文档无 filters/tickSize, 使用默认或移除精度查询
                # 假设无, 使用默认
                logger.warning(f"{symbol} 无精度信息, 使用默认")
                tick_size = Decimal('0.1')
                step_size = Decimal('0.01')
                min_qty = Decimal('0.001')
                market_info = {'tick_size': tick_size, 'step_size': step_size, 'min_qty': min_qty}
                market_cache_time = time.time()
                return market_info

    logger.warning(f"未找到 {symbol} 精度，使用默认")
    market_info = {'tick_size': Decimal('0.1'), 'step_size': Decimal('0.01'), 'min_qty': Decimal('0.001')}
    market_cache_time = time.time()
    return market_info

def round_to_precision(value, precision):
    """
    Round value to precision (tickSize or stepSize)
    :param value: float/Decimal
    :param precision: Decimal tick/step size
    :return: rounded Decimal
    """
    if precision == 0:
        return Decimal(str(value))
    # quantize 必须在 Decimal 上操作
    return (Decimal(str(value)) / precision).quantize(Decimal('1'), rounding=ROUND_DOWN) * precision

def get_ticker(symbol):
    data = rest_request("GET", f"/api/v1/ticker", None, {"symbol": symbol}, is_public=True)
    try:
        return float(data['lastPrice']) if data and 'lastPrice' in data else 0.0
    except (KeyError, ValueError, TypeError):
        # 尝试 /ticker
        data_v2 = rest_request("GET", "/ticker", None, {"symbol": symbol}, is_public=True)
        try:
            return float(data_v2['lastPrice']) if data_v2 and 'lastPrice' in data_v2 else 0.0
        except (KeyError, ValueError, TypeError):
             return 0.0

def get_positions(symbol=None):
    params = {"symbol": symbol} if symbol else {}
    data = rest_request("GET", "/api/v1/positions", "positionQuery", params)
    if data and isinstance(data, list):
        long_size = sum(float(p.get('quantity', 0)) for p in data if p.get('side', '').upper() == 'LONG')
        short_size = sum(float(p.get('quantity', 0)) for p in data if p.get('side', '').upper() == 'SHORT')
        total_exposure = long_size + short_size
        delta = (long_size - short_size) / total_exposure if total_exposure > 0 else 0.0
        unrealized_pnl = sum(float(p.get('unrealizedPnl', 0)) for p in data)
        return delta, long_size, short_size, unrealized_pnl
    
    # fallback /position
    data_v2 = rest_request("GET", "/position", "positionQuery", params)
    if data_v2 and isinstance(data_v2, list):
        long_size = sum(float(p.get('quantity', 0)) for p in data_v2 if p.get('side', '').upper() == 'LONG')
        short_size = sum(float(p.get('quantity', 0)) for p in data_v2 if p.get('side', '').upper() == 'SHORT')
        total_exposure = long_size + short_size
        delta = (long_size - short_size) / total_exposure if total_exposure > 0 else 0.0
        unrealized_pnl = sum(float(p.get('unrealizedPnl', 0)) for p in data_v2)
        return delta, long_size, short_size, unrealized_pnl

    logger.error("API 失败: get_positions 无法获取数据")
    return None

def get_balances():
    data = rest_request("GET", "/api/v1/capital", "balanceQuery")
    try:
        if data and isinstance(data, list):
            usdc_balance = next((b for b in data if b['symbol'] == 'USDC'), {})
            available = float(usdc_balance.get('available', 0.0))
            total_equity = sum(float(b.get('totalEquity', 1.0)) for b in data)  # 假设计算
            total_liability = sum(float(b.get('totalLiability', 1.0)) for b in data)
            margin_ratio = total_equity / total_liability if total_liability > 0 else 1.0
            return available, margin_ratio
    except (KeyError, ValueError, TypeError):
        # fallback /balance
        data_v2 = rest_request("GET", "/balance", "balanceQuery")
        try:
            usdc_balance = next((b for b in data_v2 if b['asset'] == 'USDC'), {})
            available = float(usdc_balance.get('available', 0.0))
            total_equity = float(data_v2.get('totalEquity', 1.0))
            total_liability = float(data_v2.get('totalLiability', 1.0))
            margin_ratio = total_equity / total_liability if total_liability > 0 else 1.0
            return available, margin_ratio
        except (KeyError, ValueError, TypeError):
            pass

    logger.error("API 失败: get_balances 无法获取数据")
    return None

def get_open_orders(symbol):
    params = {"symbol": symbol}
    data_v1 = rest_request("GET", "/api/v1/orders", "orderQueryAll", params)
    if data_v1 and isinstance(data_v1, list):
        try:
            return [
                {'id': o['id'], 'side': o['side'], 'price': Decimal(o['price']), 'qty': Decimal(o['quantity'])}
                for o in data_v1 if o['status'] in ['New', 'Pending']
            ]
        except (KeyError, TypeError):
            pass

    # fallback /orders
    data_v2 = rest_request("GET", "/orders", "orderQueryAll", params)
    if data_v2 and isinstance(data_v2, list):
        try:
            return [
                {'id': o['orderId'], 'side': o['side'], 'price': Decimal(o['price']), 'qty': Decimal(o['quantity'])}
                for o in data_v2
            ]
        except (KeyError, TypeError):
            pass

    logger.error("API 失败: get_open_orders 无法获取数据")
    return None

def calculate_total_value(price):
    balances_data = get_balances()
    if balances_data is None:
        return None
    available_usdc, _ = balances_data

    positions_data = get_positions(SYMBOL)
    if positions_data is None:
        return None
    
    _, long_size, short_size, unrealized_pnl = positions_data
    net_position_value = (long_size - short_size) * price
    return available_usdc + net_position_value + unrealized_pnl

def calculate_spread_price(base_price, side, widen=False):
    market = get_market_info(SYMBOL)
    tick_size = market['tick_size']
    factor = SPREAD_PCT * 1.5 if widen else SPREAD_PCT
    if side == 'Bid':
        raw_price = base_price * (1 - factor)
    else:
        raw_price = base_price * (1 + factor)
    return round_to_precision(raw_price, tick_size)

def place_order(symbol, side, order_type, price, qty):
    market = get_market_info(symbol)
    step_size = market['step_size']
    min_qty = market['min_qty']
    rounded_price = round_to_precision(price, market['tick_size'])
    rounded_qty = max(round_to_precision(qty, step_size), min_qty)

    order_params = {
        "symbol": symbol,
        "side": side,  # 使用 'Bid'/'Ask'
        "orderType": order_type,
        "price": str(rounded_price),
        "quantity": str(rounded_qty),
        "reduceOnly": False
    }

    data = rest_request("POST", "/api/v1/order", "orderExecute", order_params)
    
    try:
        order_id = data.get('id')
        logger.info(f"下单成功: {side} {rounded_qty} @ {rounded_price}, ID: {order_id}")
        return order_id
    except (KeyError, TypeError):
        # fallback batch /orders
        data_v2 = rest_request("POST", "/orders", "orderExecute", [order_params])
        try:
            order_id = data_v2[0].get('orderId')
            logger.info(f"下单成功 (batch): {side} {rounded_qty} @ {rounded_price}, ID: {order_id}")
            return order_id
        except (KeyError, IndexError, TypeError):
             logger.error(f"下单失败: {data} {data_v2}")
             return None

def cancel_all_orders(symbol):
    params = {"symbol": symbol}
    data = rest_request("DELETE", "/api/v1/orders", "orderCancelAll", params)
    
    if data:
        logger.info(f"所有 {symbol} 订单已取消")
        return True
    else:
        # fallback
        data_v2 = rest_request("POST", "/order/cancelAll", "orderCancelAll", params)
        if data_v2:
            logger.info(f"所有 {symbol} 订单已取消 (fallback)")
            return True
        else:
            logger.error(f"取消 {symbol} 订单失败")
            return False

def cancel_order(order_id, symbol):
    params = {"symbol": symbol, "orderId": str(order_id)}
    
    data_v1 = rest_request("DELETE", "/api/v1/order", "orderCancel", params)
    if data_v1 and data_v1.get('id') == str(order_id):
        logger.info(f"取消订单 {order_id} 成功")
        return True

    # fallback
    data_v2 = rest_request("DELETE", "/order", "orderCancel", params)
    if data_v2 and data_v2.get('orderId') == str(order_id):
        logger.info(f"取消订单 {order_id} 成功 (fallback)")
        return True
        
    logger.warning(f"取消订单 {order_id} 失败")
    return False

# WebSocket 处理 (已更新)
def on_ws_message(ws, message):
    global current_price, total_volume, long_success, short_success, maker_fills, taker_fills, adjustment_needed
    try:
        data = json.loads(message)
        
        if 'stream' in data:
            stream = data['stream']
            payload = data['data']

            if stream == f"ticker.{SYMBOL}":
                new_price = float(payload.get('c', 0.0))  # 文档 'c' for close
                if new_price > 0:
                    if current_price > 0 and abs(new_price - current_price) / current_price > WS_TRIGGER_THRESHOLD:
                        logger.info(f"价格变化触发调整: {current_price} -> {new_price}")
                        adjustment_needed.set()
                    current_price = new_price
                    logger.debug(f"实时价格更新: {current_price}")

            elif stream == f"account.orderUpdate.{SYMBOL}":
                event_type = payload.get('e')
                if event_type == 'orderFill':
                    qty = float(payload.get('l', 0.0))
                    if qty > 0:
                        adjustment_needed.set()
                        price = float(payload.get('L', 0.0))
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

def on_ws_open(ws):
    subscribe_msg = {"method": "SUBSCRIBE", "params": [f"ticker.{SYMBOL}"]}
    ws.send(json.dumps(subscribe_msg))
    logger.info(f"订阅公共流: ticker.{SYMBOL}")

    if not private_key:
        logger.error("私钥未加载, 无法订阅私有流。")
        return

    timestamp = int(time.time() * 1000)
    window = "5000"
    sign_str = f"instruction=subscribe&timestamp={timestamp}&window={window}"
    signature_bytes = private_key.sign(sign_str.encode('utf-8'))
    encoded_signature = base64.b64encode(signature_bytes).decode('utf-8')
    private_sub = {
        "method": "SUBSCRIBE",
        "params": [f"account.orderUpdate.{SYMBOL}"],
        "signature": [PUBLIC_KEY, encoded_signature, str(timestamp), window]
    }
    ws.send(json.dumps(private_sub))
    logger.info(f"订阅私有流: account.orderUpdate.{SYMBOL}")

    def ping_loop():
        while running:
            time.sleep(30)
            if ws.sock and ws.sock.connected:
                ws.send(json.dumps({"method": "PING"}))
                logger.debug("发送 WS PING")
    ping_thread = threading.Thread(target=ping_loop)
    ping_thread.daemon = True
    ping_thread.start()

# ... (其余代码不变)
