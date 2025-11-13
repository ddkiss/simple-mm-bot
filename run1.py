#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mm2_ws_delta_skew.py
官方 WebSocket + 真正的 Delta 中性动态偏斜做市
- 保持净 Delta 接近 0
- 根据 Delta 自动倾斜挂单量（skew）
- 可选自动 reduceOnly 对冲
"""

import os
import sys
import time
import json
import base64
import logging
import argparse
import threading
import websocket  # pip install websocket-client
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519
from dotenv import load_dotenv

# --- logging ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
if not logger.handlers:
    logger.addHandler(handler)

# --- load env ---
load_dotenv()
PUBLIC_KEY = os.getenv("PUBLIC_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")
if not PUBLIC_KEY or not SECRET_KEY:
    logger.critical("错误：未找到 PUBLIC_KEY 或 SECRET_KEY")
    sys.exit(1)

try:
    private_seed = base64.b64decode(SECRET_KEY)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_seed)
except Exception as e:
    logger.critical(f"私钥加载失败: {e}")
    sys.exit(1)

BASE_URL = "https://api.backpack.exchange"

# --- Backpack REST (不变) ---
# （包含：BackpackAuthenticator, get_headers, _params_to_sorted_query, rest_request）
# （为了篇幅，这里假设你已复制前面的完整实现，实际运行时请粘贴完整）

# === 请粘贴你之前的所有 REST 函数 ===
# get_balances(), cancel_all_orders(), place_order(), get_ticker(), get_positions()
# （直接从 mm2_ws_official_full.py 复制这5个函数过来）

# --- 示例：get_positions（必须有）---
def get_positions(symbol=None):
    params = {"symbol": symbol} if symbol else None
    data = rest_request("GET", "/api/v1/position", "positionQuery", params)
    return data or []

# --- WebSocket（不变）---
class TickerWebSocket:
    def __init__(self, symbol, callback):
        self.symbol = symbol
        self.callback = callback
        self.ws = None
        self.thread = None
        self.should_run = threading.Event()

    def start(self):
        self.should_run.set()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("WebSocket 启动")

    def stop(self):
        self.should_run.clear()
        if self.ws: self.ws.close()

    def _run(self):
        while self.should_run.is_set():
            try:
                self.ws = websocket.WebSocketApp(
                    "wss://ws.backpack.exchange/",
                    on_open=self._on_open,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                )
                self.ws.run_forever(ping_interval=20, ping_timeout=10)
                if self.should_run.is_set():
                    logger.warning("WS 断开，5秒后重连...")
                    time.sleep(5)
            except Exception as e:
                logger.error(f"WS 异常: {e}")
                time.sleep(5)

    def _on_open(self, ws):
        logger.info("WebSocket 连接成功")
        ws.send(json.dumps({"method": "SUBSCRIBE", "params": [f"ticker@{self.symbol}"]}))

    def _on_message(self, ws, message):
        try:
            data = json.loads(message)
            if data.get("channel") == "ticker":
                t = data["data"]
                bid = float(t.get("bestBidPrice", 0))
                ask = float(t.get("bestAskPrice", 0))
                if bid > 0 and ask > 0:
                    self.callback((bid + ask) / 2.0)
        except Exception as e:
            logger.debug(f"ticker 解析失败: {e}")

    def _on_error(self, ws, err): logger.error(f"WS Error: {err}")
    def _on_close(self, ws, *args): logger.warning("WS Closed")

# --- MarketMaker 主类（核心升级）---
class MarketMaker:
    def __init__(
        self,
        symbol,
        spread=0.03,
        delta_thresh=3.0,        # 新增：Delta 阈值（%）
        order_qty=0.0003,
        max_drift=2.0,
        margin_thresh=1.5,
        ws_trigger=0.015,
        check_interval=60,
        enable_hedge=False,      # 是否自动 reduceOnly 对冲
        skew_factor=2.0,         # 偏斜倍数：净 Delta 超阈值时，多挂几倍
    ):
        self.symbol = symbol
        self.spread = spread / 100 if spread > 1 else spread
        self.delta_thresh = delta_thresh / 100 if delta_thresh > 1 else delta_thresh
        self.base_qty = order_qty
        self.max_drift = max_drift / 100 if max_drift > 1 else max_drift
        self.margin_thresh = margin_thresh
        self.ws_trigger = ws_trigger / 100 if ws_trigger > 1 else ws_trigger
        self.check_interval = check_interval
        self.enable_hedge = enable_hedge
        self.skew_factor = skew_factor

        self.last_price = None
        self.last_update_time = time.time()
        self.running = False
        self.ws_client = TickerWebSocket(symbol, self._on_price_update)

        logger.info(f"Delta-Neutral 动态偏斜做市启动: {symbol}")
        logger.info(f"Delta 阈值: ±{self.delta_thresh*100:.2f}% | 偏斜倍数: {skew_factor}x | 自动对冲: {enable_hedge}")

    def get_net_delta(self):
        """返回净 Delta（正=多头暴露，负=空头暴露），单位：BTC"""
        positions = get_positions(self.symbol)
        net = 0.0
        for p in positions:
            size = float(p.get("size", 0))
            side = p.get("side", "")
            if side == "LONG":
                net += size
            elif side == "SHORT":
                net -= size
        return net

    def _on_price_update(self, mid_price):
        if not self.running or mid_price <= 0: return
        if self.last_price is None:
            self.last_price = mid_price
            logger.info(f"WebSocket 初始价格: {mid_price:.2f}")
            self.last_update_time = time.time()
            self.adjust_orders(mid_price)
            return

        change = abs(mid_price - self.last_price) / self.last_price
        if change >= self.ws_trigger:
            logger.info(f"WS 触发: {self.last_price:.2f} → {mid_price:.2f} ({change*100:.3f}%)")
            self.adjust_orders(mid_price)
            self.last_update_time = time.time()

    def periodic_check(self):
        while self.running:
            if time.time() - self.last_update_time > self.check_interval:
                logger.info(f"{self.check_interval}s 兜底触发")
                ticker = get_ticker(self.symbol)
                if ticker:
                    mid = (float(ticker.get("bid", 0)) + float(ticker.get("ask", 0))) / 2.0
                    if mid > 0:
                        self.adjust_orders(mid)
                        self.last_update_time = time.time()
            time.sleep(5)

    def check_risk(self):
        bal = get_balances()
        if not bal:
            logger.error("无法获取余额")
            return False
        _, margin = bal
        if margin < self.margin_thresh:
            logger.warning(f"保证金过低: {margin:.2f} < {self.margin_thresh}")
            return False
        return True

    def adjust_orders(self, current_price):
        if self.last_price:
            drift = abs(current_price - self.last_price) / self.last_price
            if drift > self.max_drift:
                logger.warning(f"漂移超限 {drift*100:.2f}% → 撤单重挂")
                cancel_all_orders(self.symbol)
        self.last_price = current_price

        if not self.check_risk():
            logger.warning("风控未通过，暂停挂单")
            return

        # === 核心：计算净 Delta 并决定挂单量 ===
        net_delta = self.get_net_delta()
        delta_ratio = net_delta / self.base_qty  # 相对基准数量的偏离倍数
        abs_ratio = abs(delta_ratio)

        buy_qty = self.base_qty
        sell_qty = self.base_qty

        if abs_ratio > self.delta_thresh:
            if net_delta > 0:  # 太多头暴露 → 多挂空单
                sell_qty *= self.skew_factor
                logger.info(f"Delta +{delta_ratio*100:.2f}% → 偏空，卖单 x{self.skew_factor}")
            else:  # 太空头暴露 → 多挂多单
                buy_qty *= self.skew_factor
                logger.info(f"Delta {delta_ratio*100:.2f}% → 偏多，买单 x{self.skew_factor}")
        else:
            logger.info(f"Delta 中性 ({delta_ratio*100:.2f}%)，等量挂单")

        # === 可选：自动对冲 ===
        if self.enable_hedge and abs_ratio > self.delta_thresh * 2:  # 超 2 倍阈值才对冲
            hedge_size = abs(net_delta)
            if net_delta > 0:
                place_order(self.symbol, "SELL", current_price, hedge_size, reduce_only=True)
                logger.info(f"自动对冲：卖出 {hedge_size} (reduceOnly)")
            elif net_delta < 0:
                place_order(self.symbol, "BUY", current_price, hedge_size, reduce_only=True)
                logger.info(f"自动对冲：买入 {hedge_size} (reduceOnly)")
            time.sleep(1.5)

        # === 挂单 ===
        spread_price = current_price * self.spread
        buy_price = round(current_price - spread_price, 2)
        sell_price = round(current_price + spread_price, 2)

        cancel_all_orders(self.symbol)
        if buy_qty > 0:
            place_order(self.symbol, "BUY", buy_price, buy_qty)
        if sell_qty > 0:
            place_order(self.symbol, "SELL", sell_price, sell_qty)

        logger.info(f"挂单完成: 买 {buy_qty} @ {buy_price} | 卖 {sell_qty} @ {sell_price} | 净Delta: {net_delta:.6f}")

    def run(self):
        self.running = True
        self.ws_client.start()
        threading.Thread(target=self.periodic_check, daemon=True).start()
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        self.ws_client.stop()
        cancel_all_orders(self.symbol)
        logger.info("程序安全退出")

# --- CLI 完整参数 ---
def parse_args():
    p = argparse.ArgumentParser(description="Delta-Neutral 动态偏斜做市机器人")
    p.add_argument("--symbol", type=str, default="BTC_USDC_PERP")
    p.add_argument("--spread", type=float, default=0.03)
    p.add_argument("--delta-thresh", type=float, default=3.0, help="Delta 阈值 % (e.g. 3.0)")
    p.add_argument("--qty", type=float, default=0.0003, help="基准挂单量")
    p.add_argument("--maxdrift", type=float, default=2.0)
    p.add_argument("--margin", type=float, default=1.5)
    p.add_argument("--ws-trigger", type=float, default=0.015)
    p.add_argument("--check-interval", type=int, default=60)
    p.add_argument("--skew-factor", type=float, default=2.0, help="偏斜倍数")
    p.add_argument("--enable-hedge", action="store_true", help="开启自动对冲")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    logger.info(f"启动参数: {vars(args)}")

    mm = MarketMaker(
        symbol=args.symbol,
        spread=args.spread,
        delta_thresh=args.delta_thresh,
        order_qty=args.qty,
        max_drift=args.maxdrift,
        margin_thresh=args.margin,
        ws_trigger=args.ws_trigger,
        check_interval=args.check_interval,
        enable_hedge=args.enable_hedge,
        skew_factor=args.skew_factor,
    )
    mm.run()
