# Retry: write the file again
file_path = "/mnt/data/mm2_full_trigger.py"
script = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mm2_full_trigger.py
修正版：恢复 ws_trigger 与 check_interval 逻辑，保留真实 REST 调用。
生成于交互会话。请在运行前确认 .env 中有 PUBLIC_KEY 与 SECRET_KEY。
"""

import os
import sys
import time
import json
import base64
import logging
import argparse
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519
from dotenv import load_dotenv

# --- logging ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(h)

# --- load env ---
load_dotenv()
PUBLIC_KEY = os.getenv("PUBLIC_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

if not PUBLIC_KEY or not SECRET_KEY:
    logger.critical("错误：未在环境变量中找到 PUBLIC_KEY 或 SECRET_KEY，请检查 .env 配置。")
    sys.exit(1)

try:
    private_seed = base64.b64decode(SECRET_KEY)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_seed)
except Exception as e:
    logger.critical(f"加载私钥失败: {e} — 请确认 SECRET_KEY 为 base64 编码的 32 字节 seed。")
    sys.exit(1)

# --- Backpack auth & REST wrapper ---
BASE_URL = "https://api.backpack.exchange"

class BackpackAuthenticator:
    def __init__(self, private_key_obj, public_key_b64):
        self.private_key = private_key_obj
        self.public_key = public_key_b64

    def generate_signature(self, instruction, params_str, timestamp_ms, window_ms="5000"):
        if not self.private_key:
            raise ValueError("私钥未初始化")
        if params_str:
            sign_str = f"instruction={instruction}&{params_str}&timestamp={timestamp_ms}&window={window_ms}"
        else:
            sign_str = f"instruction={instruction}&timestamp={timestamp_ms}&window={window_ms}"
        sig_bytes = self.private_key.sign(sign_str.encode("utf-8"))
        return base64.b64encode(sig_bytes).decode("utf-8")

def get_headers(instruction, params_str="", timestamp=None, window="5000"):
    if timestamp is None:
        timestamp = int(time.time() * 1000)
    auth = BackpackAuthenticator(private_key, PUBLIC_KEY)
    sig = auth.generate_signature(instruction, params_str, timestamp, window)
    return {
        "X-API-Key": PUBLIC_KEY,
        "X-Timestamp": str(timestamp),
        "X-Window": str(window),
        "X-Signature": sig,
        "Content-Type": "application/json"
    }

def _params_to_sorted_query(params):
    if not params:
        return ""
    if isinstance(params, dict):
        return "&".join(f"{k}={params[k]}" for k in sorted(params))
    return str(params)

def rest_request(method, endpoint, instruction, params=None, is_public=False, retry=2, window="5000"):
    for attempt in range(retry + 1):
        try:
            url = BASE_URL + endpoint
            params_str = ""
            json_body = None
            if method.upper() == "GET":
                params_str = _params_to_sorted_query(params)
                if params_str:
                    url += "?" + params_str
            else:
                if isinstance(params, dict):
                    params_str = _params_to_sorted_query(params)
                    json_body = params
                elif isinstance(params, list):
                    params_str = "&".join(_params_to_sorted_query(p) for p in params)
                    json_body = params
            timestamp = int(time.time() * 1000)
            headers = get_headers(instruction, params_str, timestamp, window)
            resp = requests.request(method.upper(), url, headers=headers, json=json_body, timeout=10)
            resp.raise_for_status()
            return resp.json() if resp.text else {}
        except requests.HTTPError as http_e:
            txt = ""
            try:
                txt = http_e.response.text
            except Exception:
                txt = str(http_e)
            logger.error(f"REST 请求失败 (HTTP) {method} {endpoint} attempt={attempt+1}: {txt}")
            if attempt < retry:
                time.sleep(0.5)
                continue
            return None
        except Exception as e:
            logger.error(f"REST 请求异常 {method} {endpoint} attempt={attempt+1}: {e}")
            if attempt < retry:
                time.sleep(0.5)
                continue
            return None

# --- API helpers ---
def get_balances():
    data = rest_request("GET", "/api/v1/capital", "balanceQuery")
    if not data:
        logger.error("get_balances: 无法获取余额")
        return None
    try:
        usdc_balance = next((b for b in data if b.get("symbol") in ("USDC", "USD")), {})
        avail = float(usdc_balance.get("available", 0))
        eq = sum(float(b.get("totalEquity", 0)) for b in data)
        liab = sum(float(b.get("totalLiability", 0)) for b in data)
        margin = eq / liab if liab > 0 else 1.0
        return avail, margin
    except Exception as e:
        logger.error(f"解析余额数据出错: {e}")
        return None

def get_positions(symbol=None):
    params = {"symbol": symbol} if symbol else None
    data = rest_request("GET", "/api/v1/position", "positionQuery", params)
    return data

def cancel_all_orders(symbol):
    params = {"symbol": symbol}
    data = rest_request("DELETE", "/api/v1/orders", "orderCancelAll", params)
    if not data:
        # try fallback endpoint
        data2 = rest_request("POST", "/order/cancelAll", "orderCancelAll", params)
        if data2:
            logger.info(f"取消 {symbol} 所有订单 (fallback) 成功")
            return True
        logger.error(f"取消 {symbol} 订单失败")
        return False
    logger.info(f"取消 {symbol} 所有订单成功")
    return True

def place_order(symbol, side, price, size, order_type="LIMIT", reduce_only=False):
    params = {
        "symbol": symbol,
        "side": side,
        "price": str(price),
        "size": str(size),
        "type": order_type,
        "reduceOnly": reduce_only
    }
    data = rest_request("POST", "/api/v1/order", "orderPlace", params)
    if not data:
        logger.error(f"{symbol} 下单失败: {side} {size}@{price}")
        return None
    logger.info(f"{symbol} 下单成功: {side} {size}@{price}")
    return data

def get_ticker(symbol):
    params = {"symbol": symbol}
    data = rest_request("GET", "/api/v1/ticker", "tickerQuery", params)
    # expect data to contain 'bid' and 'ask' or similar
    if not data:
        return None
    # try common shapes
    if isinstance(data, dict):
        return {"bid": float(data.get("bid", 0)), "ask": float(data.get("ask", 0))}
    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        d = data[0]
        return {"bid": float(d.get("bid", 0)), "ask": float(d.get("ask", 0))}
    return None

# --- MarketMaker ---
class MarketMaker:
    def __init__(
        self,
        symbol,
        spread=0.03,
        delta_thresh=3.0,
        order_qty=0.0003,
        max_drift=2.0,
        margin_thresh=1.5,
        ws_trigger=0.015,
        check_interval=60,
    ):
        self.symbol = symbol
        self.spread = spread / 100 if spread > 1 else spread  # allow either 0.03 or 3%
        self.delta_thresh = delta_thresh / 100 if delta_thresh > 1 else delta_thresh
        self.order_qty = order_qty
        self.max_drift = max_drift / 100 if max_drift > 1 else max_drift
        self.margin_thresh = margin_thresh
        self.ws_trigger = ws_trigger / 100 if ws_trigger > 1 else ws_trigger
        self.check_interval = check_interval

        self.last_price = None
        self.last_update_time = time.time()
        self.running = False

        logger.info(f"启动做市机器人: {self.symbol}")
        logger.info(f"参数: Spread={self.spread*100:.3f}%, DeltaThresh={self.delta_thresh*100:.2f}%, OrderQty={self.order_qty}")
        logger.info(f"风控: MaxDrift={self.max_drift*100:.2f}%, MarginThresh={self.margin_thresh}")
        logger.info(f"触发: WS Trigger={self.ws_trigger*100:.3f}%, Fallback Timer={self.check_interval}s")

    def get_mid_price(self, ticker):
        try:
            ask = float(ticker.get("ask", 0))
            bid = float(ticker.get("bid", 0))
            if ask and bid:
                return (ask + bid) / 2.0
        except Exception:
            pass
        return None

    def check_risk(self):
        bal = get_balances()
        if not bal:
            logger.error("无法获取余额, 跳过风控检查。")
            return False
        avail, margin = bal
        if margin < self.margin_thresh:
            logger.warning(f"保证金风险过高: {margin:.2f}")
            return False
        return True

    def adjust_orders(self, current_price):
        if self.last_price:
            drift = abs(current_price - self.last_price) / self.last_price
            if drift > self.max_drift:
                logger.warning(f"价格偏移过大: {drift*100:.2f}% -> 取消挂单重新布局。")
                cancel_all_orders(self.symbol)
        self.last_price = current_price

        if not self.check_risk():
            logger.warning("风险检查未通过，暂停挂单。")
            return

        spread_price = current_price * self.spread
        buy_price = round(current_price - spread_price, 2)
        sell_price = round(current_price + spread_price, 2)

        cancel_all_orders(self.symbol)
        place_order(self.symbol, "BUY", buy_price, self.order_qty)
        place_order(self.symbol, "SELL", sell_price, self.order_qty)

        logger.info(f"挂单布局完成: 买 {buy_price}, 卖 {sell_price}")

    def run(self, poll_interval=1):
        self.running = True
        logger.info("正在获取市场精度...")
        # initial wait to let things warm up
        time.sleep(1)
        self.last_update_time = time.time()

        try:
            while self.running:
                ticker = get_ticker(self.symbol)
                if not ticker:
                    logger.debug("无法获取 ticker，等待下一次轮询。")
                    time.sleep(poll_interval)
                    continue

                price = self.get_mid_price(ticker)
                if price is None:
                    time.sleep(poll_interval)
                    continue

                if self.last_price is None:
                    self.last_price = price
                    logger.info(f"初始价格设定: {price}")
                    self.last_update_time = time.time()
                    time.sleep(poll_interval)
                    continue

                price_change = abs(price - self.last_price) / self.last_price  # fractional

                # WS trigger logic (we emulate WS by frequent polling; threshold is fractional)
                if price_change >= self.ws_trigger:
                    logger.info(f"价格变化触发调整: {self.last_price} -> {price}")
                    self.adjust_orders(price)
                    self.last_update_time = time.time()
                    # update last_price inside adjust_orders
                    time.sleep(poll_interval)
                    continue

                # fallback periodic check
                if time.time() - self.last_update_time > self.check_interval:
                    logger.info(f"{self.check_interval}s 定时检查触发调整")
                    self.adjust_orders(price)
                    self.last_update_time = time.time()
                    time.sleep(poll_interval)
                    continue

                # update last_price gradually (do not overwrite too often)
                # we keep last_price until a trigger or fallback adjusts it
                time.sleep(poll_interval)

        except KeyboardInterrupt:
            logger.info("收到停止信号, 正在关闭...")
            self.stop()

    def stop(self):
        logger.info("正在取消所有订单...")
        cancel_all_orders(self.symbol)
        self.running = False
        logger.info("程序已退出。")


# --- CLI and startup ---
def parse_args():
    p = argparse.ArgumentParser(description="Backpack 做市机器人（含 WS trigger 与 fallback interval）")
    p.add_argument("--symbol", type=str, default="BTC_USDC_PERP", help="交易对符号")
    p.add_argument("--spread", type=float, default=0.03, help="挂单价差百分比或小数 (e.g. 0.03 or 3)")
    p.add_argument("--delta", type=float, default=3.0, help="Delta 阈值百分比或小数")
    p.add_argument("--qty", type=float, default=0.0003, help="每笔下单数量")
    p.add_argument("--maxdrift", type=float, default=2.0, help="最大价格漂移百分比")
    p.add_argument("--margin", type=float, default=1.5, help="最低保证金比率")
    p.add_argument("--ws-trigger", type=float, default=0.015, help="WS 价格触发阈值 (百分比如 0.015 或小数 0.00015)")
    p.add_argument("--check-interval", type=int, default=60, help="兜底检测间隔（秒）")
    p.add_argument("--poll-interval", type=float, default=1.0, help="轮询 ticker 的间隔（秒）")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()

    logger.info(
        f"命令行参数: symbol={args.symbol}, spread={args.spread}, delta={args.delta}, qty={args.qty}, "
        f"maxdrift={args.maxdrift}, margin={args.margin}, ws_trigger={args.ws_trigger}, check_interval={args.check_interval}"
    )

    mm = MarketMaker(
        symbol=args.symbol,
        spread=args.spread,
        delta_thresh=args.delta,
        order_qty=args.qty,
        max_drift=args.maxdrift,
        margin_thresh=args.margin,
        ws_trigger=args.ws_trigger,
        check_interval=args.check_interval,
    )
    mm.run(poll_interval=args.poll_interval)
'''

with open(file_path, "w", encoding="utf-8") as f:
    f.write(script)

# Quick syntax check
import ast, traceback, sys as _sys
try:
    ast.parse(script)
    syntax_ok = True
    syntax_msg = "OK"
except Exception as e:
    syntax_ok = False
    syntax_msg = traceback.format_exc()

{"path": file_path, "syntax_ok": syntax_ok, "syntax_msg": syntax_msg}
