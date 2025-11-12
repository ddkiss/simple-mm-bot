# -*- coding: utf-8 -*-
"""
Backpack Exchange 自动合约做市策略实现 (精度查询版)
基于纯合约库存中性动态做市策略
作者: Grok (基于用户需求生成)
日期: 2025-11-12

更新: 
- 添加 /markets 查询精度 (tickSize/stepSize), 用于价格/数量 round
- [v2] 重构并发模型: 使用 Event 驱动, 避免 WS 线程阻塞和竞态条件
- [v2] 修正函数重复定义
- [v2] 添加 --ws-trigger 命令行参数
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
    # 鉴于原始代码的回退逻辑, 我们在此处保留它, 但建议在生产中改为抛出错误
    logger.warning("未在 .env 中找到 API 密钥, 将使用占位符 (可能导致认证失败)")
    PUBLIC_KEY = "your_base64_public_key_here"
    SECRET_KEY = "your_base64_secret_key_here"
    # 强烈建议: 
    # if not PUBLIC_KEY or not SECRET_KEY:
    #     logger.critical("错误：未在 .env 文件中找到 PUBLIC_KEY 或 SECRET_KEY。")
    #     raise ValueError("API 密钥未配置")

try:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(base664.b64decode(SECRET_KEY))
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
active_orders = []
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

    data = rest_request("GET", "/api/v1/markets", None, None, is_public=True) # 注意: 路径可能是 /api/v1/markets
    if not data:
        # 尝试备用路径
        data = rest_request("GET", "/markets", None, None, is_public=True)

    if data: # V1 API 格式 (data 是列表)
        for market in data:
            if market.get('symbol') == symbol:
                # v1 精度在 'filters' -> 'price' / 'quantity'
                filters = market.get('filters', {})
                tick_size = Decimal(filters.get('price', {}).get('tickSize', '0.1'))
                step_size = Decimal(filters.get('quantity', {}).get('stepSize', '0.01'))
                min_qty = Decimal(filters.get('quantity', {}).get('minQuantity', '0.001'))
                
                market_info = {'tick_size': tick_size, 'step_size': step_size, 'min_qty': min_qty}
                market_cache_time = time.time()
                logger.info(f"{symbol} 精度: tickSize={tick_size}, stepSize={step_size}, minQty={min_qty}")
                return market_info
    
    # 兼容原始代码的 data['data'] 格式 (如果 API 变更)
    if data and 'data' in data and isinstance(data['data'], list):
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
    # 确保默认值也被缓存, 避免频繁查询
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
    # V1 API
    data = rest_request("GET", f"/api/v1/ticker", None, {"symbol": symbol}, is_public=True)
    try:
         # V1 格式 (data 是 dict)
        return float(data['lastPrice']) if data and 'lastPrice' in data else 0.0
    except (KeyError, IndexError, ValueError, TypeError):
        # 尝试 V2 (原始) 格式
        try:
            data_v2 = rest_request("GET", "/ticker", None, {"symbol": symbol}, is_public=True)
            return float(data_v2['data'][0]['lastPrice']) if data_v2 and 'data' in data_v2 and data_v2['data'] else 0.0
        except (KeyError, IndexError, ValueError, TypeError):
             return 0.0

def get_positions(symbol=None):
    params = {"symbol": symbol} if symbol else {}
    # V1 路径
    data = rest_request("GET", "/api/v1/positions", "positionQuery", params)
    if data and isinstance(data, list): # V1 (data 是列表)
        long_size = sum(float(p.get('quantity', 0)) for p in data if p.get('side', '').upper() == 'LONG')
        short_size = sum(float(p.get('quantity', 0)) for p in data if p.get('side', '').upper() == 'SHORT')
        total_exposure = long_size + short_size
        delta = (long_size - short_size) / total_exposure if total_exposure > 0 else 0.0
        unrealized_pnl = sum(float(p.get('unrealizedPnl', 0)) for p in data)
        return delta, long_size, short_size, unrealized_pnl
    
    # 尝试 V2 (原始) 路径
    data_v2 = rest_request("GET", "/position", "positionQuery", params)
    if data_v2 and 'data' in data_v2: # V2 (data['data'] 是列表)
        long_size = sum(float(p.get('size', 0)) for p in data_v2['data'] if p.get('positionSide', '').upper() == 'LONG')
        short_size = sum(float(p.get('size', 0)) for p in data_v2['data'] if p.get('positionSide', '').upper() == 'SHORT')
        total_exposure = long_size + short_size
        delta = (long_size - short_size) / total_exposure if total_exposure > 0 else 0.0
        unrealized_pnl = sum(float(p.get('unrealizedPnL', 0)) for p in data_v2['data'])
        return delta, long_size, short_size, unrealized_pnl

    return 0.0, 0.0, 0.0, 0.0

def get_balances():
    # V1
    data = rest_request("GET", "/api/v1/capital", "balanceQuery")
    try:
        if data and isinstance(data, list): # V1
            usdc_balance = next((b for b in data if b['symbol'] == 'USDC'), {})
            available = float(usdc_balance.get('available', 0.0))
            # V1 中没有 totalEquity/Liability, 需要自行计算或使用 account-level API
            # 此处简化, 假设 V1 失败, 回退到 V2
        else:
            raise KeyError("V1 格式不匹配或数据为空")
    except (KeyError, ValueError, TypeError):
         # V2 (原始)
        data_v2 = rest_request("GET", "/balance", "balanceQuery")
        try:
            usdc_balance = next((b for b in data_v2['data'] if b['asset'] == 'USDC'), {})
            available = float(usdc_balance.get('available', 0.0))
            total_equity = float(data_v2.get('totalEquity', 1.0))
            total_liability = float(data_v2.get('totalLiability', 1.0))
            margin_ratio = total_equity / total_liability if total_liability > 0 else 1.0
            return available, margin_ratio
        except (KeyError, ValueError, TypeError):
            pass # 最终失败

    logger.warning("获取余额失败, 返回默认值")
    return 0.0, 1.0

def calculate_total_value(price):
    available_usdc, _ = get_balances()
    _, long_size, short_size, unrealized_pnl = get_positions(SYMBOL)
    net_position_value = (long_size - short_size) * price
    return available_usdc + net_position_value + unrealized_pnl

def calculate_spread_price(base_price, side, widen=False):
    """
    计算挂单价格 (应用 tickSize round)
    (已移除重复定义)
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

    # V1 API
    order_params = {
        "symbol": symbol,
        "side": side.capitalize(), # V1: 'Buy' / 'Sell'
        "orderType": order_type.capitalize(), # V1: 'Limit'
        "price": str(rounded_price),
        "quantity": str(rounded_qty),
        "reduceOnly": False
    }

    # V1 API
    data = rest_request("POST", "/api/v1/order", "orderExecute", order_params)
    
    try:
        # V1 格式 (data 是 dict)
        order_id = data.get('id')
        if not order_id:
             # 兼容 V2 (原始) 格式
             order_id = data['data'][0].get('orderId')
        
        active_orders.append(order_id)
        logger.info(f"下单成功: {side} {rounded_qty} @ {rounded_price}, ID: {order_id}")
        return order_id
    except (KeyError, IndexError, TypeError):
        # 尝试 V2 (原始)
        order_params_v2 = [{
            "symbol": symbol,
            "side": side, # V2: 'Bid' / 'Ask'
            "orderType": order_type,
            "price": str(rounded_price),
            "quantity": str(rounded_qty),
            "reduceOnly": False
        }]
        data_v2 = rest_request("POST", "/orders", "orderExecute", order_params_v2)
        try:
            order_id = data_v2['data'][0].get('orderId')
            active_orders.append(order_id)
            logger.info(f"下单成功 (V2): {side} {rounded_qty} @ {rounded_price}, ID: {order_id}")
            return order_id
        except (KeyError, IndexError, TypeError):
             logger.error(f"下单失败: V1={data}, V2={data_v2}")
             return None


def cancel_all_orders(symbol):
    params = {"symbol": symbol}
    # V1
    data = rest_request("DELETE", "/api/v1/orders", "orderCancelAll", params)
    
    if data: # V1 成功 (data 是列表)
        global active_orders
        active_orders = []
        logger.info(f"所有 {symbol} 订单已取消 (V1)")
    else:
        # 尝试 V2 (原始)
        data_v2 = rest_request("POST", "/order/cancelAll", "orderCancelAll", params)
        if data_v2:
            global active_orders
            active_orders = []
            logger.info(f"所有 {symbol} 订单已取消 (V2)")
        else:
            logger.error(f"取消 {symbol} 订单失败")


# WebSocket 处理
def on_ws_message(ws, message):
    global current_price, total_volume, long_success, short_success, maker_fills, taker_fills, adjustment_needed
    try:
        data = json.loads(message)
        
        # V1 Stream 格式
        if 'event' in data:
            event_type = data['event']
            payload = data
            
            if event_type == f"ticker": # V1: { "event": "ticker", "symbol": "SOL_USDC", "price": "140.0" }
                if data.get('symbol') != SYMBOL:
                    return
                new_price = float(payload.get('price', 0))
            
            elif event_type == "fill": # V1: { "event": "fill", ... }
                 last_qty = float(payload.get('quantity', 0))
                 if last_qty > 0:
                    logger.info("填充事件触发调整 (V1)")
                    adjustment_needed.set() # 仅设置事件
                    
                    qty = last_qty
                    price = float(payload.get('price', 0))
                    side = payload.get('side') # 'Buy' or 'Sell'
                    volume = qty * price
                    total_volume += volume
                    
                    if side == 'Buy':
                        long_success += 1
                    elif side == 'Sell':
                        short_success += 1
                    
                    is_maker = payload.get('isMaker', False)
                    if is_maker:
                        maker_fills += 1
                        logger.info(f"订单填充 (Maker): {side} {qty} @ {price}, 交易量: {volume} USDC")
                    else:
                        taker_fills += 1
                        logger.info(f"订单填充 (Taker): {side} {qty} @ {price}, 交易量: {volume} USDC")
                 return # V1 填充事件处理完毕
            
            else: # 其他 V1 事件 (depth, kline)
                return

        # V2 (原始) Stream 格式
        elif 'stream' in data:
            stream = data.get('stream')
            payload = data.get('data', data)

            if stream == f"ticker.{SYMBOL}":
                new_price = float(payload.get('lastPrice', 0))
            
            elif stream == f"orderUpdate.{SYMBOL}":
                last_qty = float(payload.get('l', 0))
                if last_qty > 0:
                    logger.info("填充事件触发调整 (V2)")
                    adjustment_needed.set() # 仅设置事件
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
                return # V2 填充事件处理完毕
            
            else: # 其他 V2 事件
                return

        else: # 未知格式
             logger.debug(f"收到未知 WS 消息: {message}")
             return

        # --- 价格更新逻辑 (V1 和 V2 均执行) ---
        if new_price > 0 and current_price > 0:
            if abs(new_price - current_price) / current_price > WS_TRIGGER_THRESHOLD:
                logger.info(f"价格变化触发调整: {current_price} -> {new_price}")
                adjustment_needed.set() # 仅设置事件, 不阻塞
        elif new_price > 0:
             logger.info(f"获取到初始价格: {new_price}")
             
        current_price = new_price
        # logger.info(f"实时价格更新: {current_price}") # 过于频繁, 改为 DEBUG
        logger.debug(f"实时价格更新: {current_price}")

    except Exception as e:
        logger.error(f"WS 消息处理错误: {e}")

def on_ws_error(ws, error):
    logger.error(f"WebSocket 错误: {error}")

def on_ws_close(ws, close_status_code, close_msg):
    logger.warning("WebSocket 关闭")

def on_ws_open(ws):
    # V1 (Public)
    subscribe_msg_v1 = {"method": "SUBSCRIBE", "params": [f"ticker@{SYMBOL}"]}
    ws.send(json.dumps(subscribe_msg_v1))
    logger.info(f"订阅 V1 公共流: ticker@{SYMBOL}")
    
    # V2 (Public)
    subscribe_msg_v2 = {"method": "SUBSCRIBE", "params": [f"ticker.{SYMBOL}"]}
    ws.send(json.dumps(subscribe_msg_v2))
    logger.info(f"订阅 V2 公共流: ticker.{SYMBOL}")

    timestamp = int(time.time() * 1000)
    window = "5000"

    # V1 (Private)
    params_list_v1 = ["fills"] # V1 订阅 'fills'
    params_str_v1 = f"streams={json.dumps(params_list_v1)}"
    sign_str_v1 = f"instruction=subscribe&{params_str_v1}&timestamp={timestamp}&window={window}"
    signature_bytes_v1 = private_key.sign(sign_str_v1.encode('utf-8'))
    encoded_signature_v1 = base64.b64encode(signature_bytes_v1).decode('utf-8')
    private_sub_v1 = {
        "method": "SUBSCRIBE",
        "params": params_list_v1,
        "signature": encoded_signature_v1,
        "timestamp": timestamp,
        "window": window
    }
    ws.send(json.dumps(private_sub_v1))
    logger.info(f"订阅 V1 私有流: fills")

    # V2 (Private)
    # V2 签名需要新的时间戳
    time.sleep(0.1) # 确保时间戳不同
    timestamp_v2 = int(time.time() * 1000)
    params_list_v2 = [f"orderUpdate.{SYMBOL}"]
    params_str_v2 = f"streams={json.dumps(params_list_v2)}"
    sign_str_v2 = f"instruction=subscribe&{params_str_v2}&timestamp={timestamp_v2}&window={window}"
    signature_bytes_v2 = private_key.sign(sign_str_v2.encode('utf-8'))
    encoded_signature_v2 = base64.b64encode(signature_bytes_v2).decode('utf-8')
    private_sub_v2 = {
        "method": "SUBSCRIBE",
        "params": params_list_v2,
        "signature": encoded_signature_v2,
        "timestamp": timestamp_v2,
        "window": window
    }
    ws.send(json.dumps(private_sub_v2))
    logger.info(f"订阅 V2 私有流: orderUpdate.{SYMBOL}")


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


def adjust_orders():
    """
    订单调整逻辑 (由 main_logic_loop 独占调用)
    """
    # 移除 adjust_lock, 因为这是单线程调用的
    
    if current_price == 0:
        logger.info("等待 WS 价格... 尝试 REST API 回退")
        price_from_rest = get_ticker(SYMBOL)
        if price_from_rest == 0:
            logger.warning("无法获取价格，跳过调整")
            return
        global current_price # 允许在 WS 未连接时使用 REST 价格
        current_price = price_from_rest
    
    global initial_price, initial_value, initial_positions_data
    if initial_price == 0:
        initial_price = current_price
        initial_value = calculate_total_value(current_price)
        initial_positions_data = get_positions(SYMBOL)
        logger.info(f"初始价格: {initial_price}, 初始总价值: {initial_value:.2f} USDC")

    _, margin_ratio = get_balances()
    if margin_ratio > MARGIN_THRESHOLD:
        logger.warning(f"保证金率过高 ({margin_ratio:.2f})，暂停运行")
        global running
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

def main_logic_loop():
    """
    主逻辑循环，由事件或定时器驱动。
    这是唯一调用 adjust_orders 的线程。
    (替换 fallback_adjust_loop)
    """
    # 初始启动时, 先等待几秒让 WS 获取价格
    logger.info("主循环启动, 等待 5 秒让 WS 连接和获取初始价格...")
    time.sleep(5)
    
    while running:
        # .wait() 返回 True (if event set) or False (if timed out)
        event_was_set = adjustment_needed.wait(timeout=CHECK_INTERVAL)
        
        if not running:
            break

        if event_was_set:
            logger.info("事件 (价格/填充) 触发调整...")
            adjustment_needed.clear() # 清除事件，等待下次
        else:
            logger.info(f"定时检查 (Fallback, {CHECK_INTERVAL}s) 触发调整...")
        
        try:
            # 由于这是唯一调用者，不再需要 adjust_lock
            adjust_orders()
        except Exception as e:
            logger.error(f"main_logic_loop 中 adjust_orders 异常: {e}")

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
