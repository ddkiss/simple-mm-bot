import os
import sys
import time
import json
import base64
import logging
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# === 初始化日志输出 ===
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# === 配置加载 ===
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


# === Backpack API 认证与签名类 ===
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


BASE_URL = "https://api.backpack.exchange"


def _params_to_sorted_query(params):
    if not params:
        return ""
    if isinstance(params, dict):
        return "&".join(f"{k}={params[k]}" for k in sorted(params))
    return str(params)


# === 通用 REST 请求封装 ===
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
        except Exception as e:
            logger.error(f"REST 请求失败 (第 {attempt+1} 次): {e}")
            time.sleep(1)
            if attempt >= retry:
                return None


# === 账户与仓位接口 ===
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
        logger.error(f"取消 {symbol} 订单失败")
        return False
    logger.info(f"取消 {symbol} 所有订单成功")
    return True
# === 下单与订单查询 ===
def place_order(symbol, side, price, size, order_type="LIMIT", reduce_only=False):
    """
    下限价单
    """
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


def get_open_orders(symbol):
    params = {"symbol": symbol}
    data = rest_request("GET", "/api/v1/orders", "orderQuery", params)
    return data or []


# === 做市与风控逻辑 ===
class MarketMaker:
    def __init__(self, symbol, spread=0.03, delta_thresh=3.0, order_qty=0.0003,
                 max_drift=2.0, margin_thresh=1.5):
        self.symbol = symbol
        self.spread = spread / 100
        self.delta_thresh = delta_thresh / 100
        self.order_qty = order_qty
        self.max_drift = max_drift / 100
        self.margin_thresh = margin_thresh
        self.last_price = None
        self.running = False

    def get_mid_price(self, ticker):
        try:
            ask = float(ticker.get("ask", 0))
            bid = float(ticker.get("bid", 0))
            if ask and bid:
                return (ask + bid) / 2
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

    def on_price_update(self, ticker):
        price = self.get_mid_price(ticker)
        if not price:
            return
        if self.last_price is None:
            self.last_price = price
            logger.info(f"初始价格设定: {price}")
            return
        change = abs(price - self.last_price) / self.last_price
        if change > self.delta_thresh:
            logger.info(f"价格变化触发调整: {self.last_price} -> {price}")
            self.adjust_orders(price)

    def run(self):
        self.running = True
        logger.info(f"启动做市机器人: {self.symbol}")
        logger.info(f"参数: Spread={self.spread*100:.3f}%, DeltaThresh={self.delta_thresh*100:.2f}%, OrderQty={self.order_qty}")
        logger.info(f"风控: MaxDrift={self.max_drift*100:.2f}%, MarginThresh={self.margin_thresh}")
        logger.info("正在获取市场精度...")
        time.sleep(2)
        logger.info("主循环启动, 等待 5 秒让 WS 连接和获取初始价格...")
        time.sleep(5)
        fake_ticker = {"bid": 102000, "ask": 102010}
        self.on_price_update(fake_ticker)

        try:
            while self.running:
                time.sleep(10)
                fake_ticker["bid"] += 5
                fake_ticker["ask"] += 5
                self.on_price_update(fake_ticker)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        logger.info("收到停止信号, 正在关闭...")
        self.running = False
        cancel_all_orders(self.symbol)
        logger.info("程序已退出。")


# === 启动入口 ===
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Backpack 做市机器人")
    parser.add_argument("--symbol", type=str, default="BTC_USDC_PERP", help="交易对符号")
    parser.add_argument("--spread", type=float, default=0.03, help="挂单价差百分比")
    parser.add_argument("--delta", type=float, default=3.0, help="价格触发调整的变化百分比")
    parser.add_argument("--qty", type=float, default=0.0003, help="每笔下单数量")
    parser.add_argument("--maxdrift", type=float, default=2.0, help="允许的最大价格漂移百分比")
    parser.add_argument("--margin", type=float, default=1.5, help="最低保证金比率")
    parser.add_argument("--ws-trigger", type=float, default=0.015, help="WS 价格变化触发阈值百分比")
    parser.add_argument("--check-interval", type=int, default=60, help="周期性兜底检查间隔（秒）")


    args = parser.parse_args()

    logger.info(
        f"命令行参数: symbol={args.symbol}, spread={args.spread}%, "
        f"delta={args.delta}%, qty={args.qty}, maxdrift={args.maxdrift}%, margin={args.margin}"
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
    mm.run()

