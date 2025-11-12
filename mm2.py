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
- [更新] 每次循环中显示汇总数据: 在 main_logic_loop 的每次调整后调用 print_summary()
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

def on_ws_error(ws, error):
    logger.error(f"WebSocket 错误: {error}")

def on_ws_close(ws, close_status_code, close_msg):
    logger.warning("WebSocket 关闭")

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
    (V3 重构: API 失败检查 + 精细化订单管理)
    """
    
    # --- 1. 获取价格 (同 V2) ---
    global current_price # 允许在 WS 未连接时使用 REST 价格
    if current_price == 0:
        logger.info("等待 WS 价格... 尝试 REST API 回退")
        price_from_rest = get_ticker(SYMBOL)
        if price_from_rest == 0:
            logger.warning("无法获取价格，跳过调整")
            return
        
        current_price = price_from_rest
    
    # --- 2. 检查 API 失败：余额和保证金 ---
    balances_data = get_balances()
    if balances_data is None:
        logger.error("API 失败: 无法获取余额。跳过此轮调整。")
        return # 关键：API 失败检查
        
    available_usdc, margin_ratio = balances_data
    
    global initial_price, initial_value, initial_positions_data
    if initial_price == 0:
        # 仅在第一次时设置
        initial_price = current_price
        initial_value_data = calculate_total_value(current_price)
        initial_positions_data = get_positions(SYMBOL)
        
        # 关键：启动时也必须检查 API 失败
        if initial_value_data is None or initial_positions_data is None:
            logger.error("API 失败: 无法初始化基线价值或仓位。")
            initial_price = 0 # 强制下次重试
            return
            
        initial_value = initial_value_data
        logger.info(f"初始价格: {initial_price}, 初始总价值: {initial_value:.2f} USDC")

    # --- 3. 风控检查 ---
    if margin_ratio > MARGIN_THRESHOLD:
        logger.warning(f"保证金率过高 ({margin_ratio:.2f})，暂停运行")
        global running
        running = False
        cancel_all_orders(SYMBOL) # 紧急停止
        return

    drift = abs((current_price - initial_price) / initial_price)
    if drift > MAX_DRIFT_PCT:
        logger.warning(f"价格偏离过大 ({drift:.2%})，暂停运行")
        running = False
        cancel_all_orders(SYMBOL) # 紧急停止
        return

    # --- 4. 检查 API 失败：仓位 ---
    positions_data = get_positions(SYMBOL)
    if positions_data is None:
        logger.error("API 失败: 无法获取仓位。跳过此轮调整。")
        return # 关键：API 失败检查
        
    current_delta, _, _, _ = positions_data

    # --- 5. 检查 API 失败：当前挂单 ---
    open_orders = get_open_orders(SYMBOL)
    if open_orders is None:
        logger.error("API 失败: 无法获取当前挂单。为安全起见，跳过此轮调整。")
        # 不取消订单, 因为我们不知道仓位是否准确, 等待 API 恢复
        return

    # --- 6. 核心：精细化订单管理逻辑 ---
    logger.info(f"Delta: {current_delta:.4f}, 价格: {current_price}, 检查 {len(open_orders)} 个挂单...")

    orders_to_cancel = []
    desired_bid_price = None
    desired_ask_price = None
    
    # 确定我们的 *目标* 状态
    if abs(current_delta) < DELTA_THRESH:
        # 中性: 挂双边
        desired_bid_price = calculate_spread_price(current_price, 'Bid')
        desired_ask_price = calculate_spread_price(current_price, 'Ask')
    elif current_delta > DELTA_THRESH:
        # 多头过高: 只挂卖单 (widen)
        desired_ask_price = calculate_spread_price(current_price, 'Ask', widen=True)
    else:
        # 空头过高: 只挂买单 (widen)
        desired_bid_price = calculate_spread_price(current_price, 'Bid', widen=True)

    bid_order_correct = False
    ask_order_correct = False

    for order in open_orders:
        is_correct = False
        # 检查买单
        if order['side'] == 'Bid':
            if desired_bid_price and not bid_order_correct and order['price'] == desired_bid_price:
                # 这是一个正确的买单, 保留它
                # (TODO: 也可以检查数量是否大致相符)
                bid_order_correct = True
                is_correct = True
            
        # 检查卖单
        elif order['side'] == 'Ask':
            if desired_ask_price and not ask_order_correct and order['price'] == desired_ask_price:
                # 这是一个正确的卖单, 保留它
                ask_order_correct = True
                is_correct = True

        if not is_correct:
            # 任何不符合我们 *当前* 目标的订单 (价格错误、方向错误、或多余)
            orders_to_cancel.append(order['id'])

    # --- 7. 执行调整 ---
    
    # 7a. 取消不正确的订单
    if orders_to_cancel:
        logger.info(f"需要取消 {len(orders_to_cancel)} 个不匹配的订单: {orders_to_cancel}")
        for order_id in orders_to_cancel:
            cancel_order(order_id, SYMBOL)
            # time.sleep(0.1) # 如果担心速率限制, 可以启用

    # 7b. 下达缺失的订单
    if desired_bid_price and not bid_order_correct:
        logger.info(f"下达缺失的 Bid 订单 @ {desired_bid_price}")
        place_order(SYMBOL, 'Bid', 'Limit', desired_bid_price, ORDER_QTY)

    if desired_ask_price and not ask_order_correct:
        logger.info(f"下达缺失的 Ask 订单 @ {desired_ask_price}")
        place_order(SYMBOL, 'Ask', 'Limit', desired_ask_price, ORDER_QTY)
        
    if not orders_to_cancel and bid_order_correct and (desired_ask_price is None or ask_order_correct):
        logger.debug("订单状态正确 (双边或目标单边), 无需调整")
    elif not orders_to_cancel and ask_order_correct and (desired_bid_price is None or bid_order_correct):
        logger.debug("订单状态正确 (双边或目标单边), 无需调整")


def main_logic_loop():
    """
    主逻辑循环，由事件或定时器驱动。
    这是唯一调用 adjust_orders 的线程。
    (替换 fallback_adjust_loop)
    """
    # 初始启动时, 先等待几秒让 WS 获取价格
    logger.info("主循环启动, 等待 5 秒让 WS 连接和获取初始价格...")
    time.sleep(5)
    
    # 第一次启动时, 立即执行一次调整
    logger.info("执行初始订单布局...")
    try:
        adjust_orders()
    except Exception as e:
        logger.error(f"初始 adjust_orders 异常: {e}")

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
            print_summary()  # 每次调整后显示汇总数据
        except Exception as e:
            logger.error(f"main_logic_loop 中 adjust_orders 异常: {e}")

def print_summary():
    global current_delta, start_time, total_volume, initial_value
    runtime = time.time() - start_time
    
    # 确保在打印汇总时获取最新数据
    positions_data = get_positions(SYMBOL)
    balances_data = get_balances()
    
    if positions_data is None or balances_data is None:
        logger.error("汇总失败：无法获取 API 数据")
        return

    current_delta, _, _, _ = positions_data
    available_usdc, _ = balances_data
    
    current_value = calculate_total_value(current_price if current_price > 0 else initial_price)
    if current_value is None:
        logger.error("汇总失败：无法计算当前价值")
        return

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

# --- 主程序入口 ---
if __name__ == "__main__":
    if private_key is None:
        logger.critical("私钥加载失败, 无法启动机器人。")
        exit(1)
        
    logger.info(f"启动做市机器人: {SYMBOL}")
    logger.info(f"参数: Spread={SPREAD_PCT*100:.3f}%, DeltaThresh={DELTA_THRESH*100:.2f}%, OrderQty={ORDER_QTY}")
    logger.info(f"风控: MaxDrift={MAX_DRIFT_PCT*100:.2f}%, MarginThresh={MARGIN_THRESHOLD}")
    logger.info(f"触发: WS Trigger={WS_TRIGGER_THRESHOLD*100:.3f}%, Fallback Timer={CHECK_INTERVAL}s")

    # 1. 初始化市场精度 (在启动时)
    logger.info("正在获取市场精度...")
    if not get_market_info(SYMBOL):
        logger.warning("无法获取市场精度, 将使用默认值, 可能会导致下单失败。")
        # 即使失败, get_market_info 内部也会设置默认值, 所以可以继续

    # 2. 启动 WebSocket 线程
    ws_thread = threading.Thread(target=start_websocket)
    ws_thread.daemon = True
    ws_thread.start()

    # 3. 启动主逻辑循环 (在主线程)
    try:
        main_logic_loop()
    except KeyboardInterrupt:
        logger.info("收到停止信号, 正在关闭...")
        running = False
    finally:
        logger.info("正在取消所有订单...")
        cancel_all_orders(SYMBOL)
        print_summary()
        logger.info("程序已退出。")
