#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ну тут крч можно поднастроить под себя че надо
Тут если что фильтрует "Антиблок" т.к я создавал для фильтрации YzeweNet, учтите это
"""

import asyncio
import base64
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

# =============================================================================
# КОНФИГУРАЦИЯ
# =============================================================================

CONFIG = {
    "subscription_url": "https://gd2pdg78vg.a.trbcdn.net/1946909976/tmXMH9zhkR7CEkAw1ShwRA",
    "check_interval_sec": 60,
    "xray_path": Path("./xray"),
    "output_file": Path("working_links.txt"),
    "log_file": Path("checker.log"),
    "socks_base_port": 20000,
    "test_url": "http://1.1.1.1/cdn-cgi/trace",
    "test_timeout_sec": 10,
    "max_concurrent_checks": 10,
    "min_delay_ms": 250,              # Отсечка: ссылки с пингом меньше не попадут в файл
    "sort_descending": True,          # True = медленные первые, False = быстрые первые
    "filter_keyword": "Антиблок",     # Ключевое слово для фильтрации ссылок
}


# =============================================================================
# МОДЕЛИ ДАННЫХ
# =============================================================================

@dataclass
class ProxyConfig:
    """Параметры VLESS-прокси."""
    uuid: str
    host: str
    port: int
    name: str
    params: Dict[str, str]
    original_url: str


@dataclass
class CheckResult:
    """Результат проверки прокси."""
    config: ProxyConfig
    success: bool
    delay_ms: Optional[float] = None
    protocol: str = ""
    error: Optional[str] = None


# =============================================================================
# ЛОГИРОВАНИЕ
# =============================================================================

class Logger:
    """Простой логгер с выводом в консоль и файл."""
    
    def __init__(self, log_file: Path):
        self.log_file = log_file
    
    def _write(self, level: str, message: str) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] [{level}] {message}"
        print(line)
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except IOError:
            pass
        return line
    
    def info(self, msg: str) -> str:
        return self._write("INFO", msg)
    
    def warn(self, msg: str) -> str:
        return self._write("WARN", msg)
    
    def error(self, msg: str) -> str:
        return self._write("ERROR", msg)
    
    def debug(self, msg: str) -> str:
        return self._write("DEBUG", msg)


log = Logger(CONFIG["log_file"])


# =============================================================================
# ПАРСИНГ И ЗАГРУЗКА
# =============================================================================

def parse_vless_url(url: str) -> Optional[ProxyConfig]:
    """
    Разбирает VLESS URL на компоненты.
    Возвращает None если формат некорректен.
    """
    try:
        if not url.startswith('vless://'):
            return None
        
        # Извлекаем фрагмент с именем
        rest = url[8:]
        name = ""
        if '#' in rest:
            rest, name = rest.split('#', 1)
            name = urllib.parse.unquote(name)
        
        # Разделяем UUID и адрес
        if '@' not in rest:
            return None
        uuid_part, address_part = rest.split('@', 1)
        
        # Парсим query-параметры
        params = {}
        if '?' in address_part:
            host_port, query_string = address_part.split('?', 1)
            params = dict(urllib.parse.parse_qsl(query_string))
        else:
            host_port = address_part
        
        # Хост и порт
        if ':' not in host_port:
            return None
        host, port_str = host_port.rsplit(':', 1)
        
        return ProxyConfig(
            uuid=uuid_part,
            host=host,
            port=int(port_str),
            name=name,
            params=params,
            original_url=url
        )
    except (ValueError, IndexError):
        return None


def fetch_subscription() -> List[str]:
    """
    Загружает список ссылок из подписки.
    Поддерживает plain-text и base64 кодирование.
    """
    try:
        with urllib.request.urlopen(CONFIG["subscription_url"], timeout=30) as resp:
            raw_content = resp.read().decode('utf-8')
        
        # Пробуем декодировать base64 (стандарт для subscription links)
        try:
            content = base64.b64decode(raw_content).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            content = raw_content
        
        links = [line.strip() for line in content.split('\n') if line.strip()]
        log.info(f"Загружено ссылок: {len(links)}")
        return links
    
    except Exception as e:
        log.error(f"Ошибка загрузки подписки: {e}")
        return []


def filter_proxies(links: List[str]) -> List[ProxyConfig]:
    """
    Фильтрует ссылки по ключевому слову и парсит их.
    """
    keyword = CONFIG["filter_keyword"]
    result = []
    
    for link in links:
        parsed = parse_vless_url(link)
        if parsed and keyword in parsed.name:
            result.append(parsed)
    
    log.info(f"Найдено '{keyword}': {len(result)} из {len(links)}")
    return result


# =============================================================================
# ГЕНЕРАЦИЯ КОНФИГУРАЦИИ XRAY
# =============================================================================

def build_xray_config(proxy: ProxyConfig, socks_port: int) -> Dict[str, Any]:
    """
    Создаёт JSON-конфигурацию для xray-core.
    """
    p = proxy.params
    
    # Базовая структура
    cfg = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": proxy.host,
                    "port": proxy.port,
                    "users": [{
                        "id": proxy.uuid,
                        "encryption": p.get('encryption', 'none'),
                        "flow": p.get('flow', '')
                    }]
                }]
            },
            "streamSettings": {
                "network": p.get('type', 'tcp'),
                "security": p.get('security', 'none')
            }
        }],
        "routing": {"rules": []}
    }
    
    outbound = cfg["outbounds"][0]
    stream = outbound["streamSettings"]
    
    # Reality
    if p.get('security') == 'reality':
        reality_cfg = {
            "serverName": p.get('sni', ''),
            "publicKey": p.get('pbk', ''),
            "shortId": p.get('sid', ''),
            "fingerprint": p.get('fp', 'chrome')
        }
        if p.get('spx'):
            reality_cfg["spiderX"] = urllib.parse.unquote(p['spx'])
        stream['realitySettings'] = reality_cfg
    
    # TCP
    if p.get('type') == 'tcp' and p.get('headerType') == 'none':
        stream['tcpSettings'] = {"header": {"type": "none"}}
    
    # xHTTP
    if p.get('type') == 'xhttp':
        stream['xhttpSettings'] = {
            "path": p.get('path', '/'),
            "mode": p.get('mode', 'auto'),
            "host": p.get('host', '')
        }
    
    # WebSocket
    if p.get('type') == 'ws':
        ws_cfg = {"path": p.get('path', '/')}
        if p.get('host'):
            ws_cfg["headers"] = {"Host": p['host']}
        stream['wsSettings'] = ws_cfg
    
    # gRPC
    if p.get('type') == 'grpc':
        stream['grpcSettings'] = {
            "serviceName": p.get('serviceName', ''),
            "multiMode": p.get('mode') == 'multi'
        }
    
    # Оптимизация сокета для TLS/Reality
    if p.get('security') in ('tls', 'reality'):
        stream['sockopt'] = {"tcpNoDelay": True}
    
    return cfg


# =============================================================================
# ПРОВЕРКА ДОСТУПНОСТИ
# =============================================================================

async def wait_for_socket(port: int, timeout: float = 5.0) -> bool:
    """Ждёт открытия SOCKS-порта."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', port),
                timeout=0.5
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.1)
    return False


async def measure_latency(socks_port: int) -> tuple[bool, float]:
    """
    Измеряет задержку через curl.
    Возвращает (успех, задержка_мс).
    """
    try:
        start = time.monotonic()
        
        proc = await asyncio.create_subprocess_exec(
            'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
            '--proxy', f'socks5h://127.0.0.1:{socks_port}',
            '--connect-timeout', str(int(CONFIG["test_timeout_sec"])),
            '--max-time', str(int(CONFIG["test_timeout_sec"])),
            CONFIG["test_url"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        
        stdout, _ = await asyncio.wait_for(
            proc.communicate(),
            timeout=CONFIG["test_timeout_sec"] + 2
        )
        
        elapsed_ms = (time.monotonic() - start) * 1000
        http_code = stdout.decode().strip()
        
        # Считаем успешными 2xx, 3xx, 4xx (главное — есть соединение)
        if proc.returncode == 0 and http_code and http_code[0] in '234':
            return True, round(elapsed_ms, 2)
        
        return False, 0.0
    
    except Exception:
        return False, 0.0


# =============================================================================
# ОСНОВНАЯ ЛОГИКА ПРОВЕРКИ
# =============================================================================

async def check_proxy(
    proxy: ProxyConfig,
    semaphore: asyncio.Semaphore
) -> Optional[CheckResult]:
    """
    Проверяет один прокси.
    """
    async with semaphore:
        short_name = proxy.name[:35] + "..." if len(proxy.name) > 35 else proxy.name
        
        # Уникальный порт на основе UUID (чтобы не было коллизий)
        port_offset = int(hashlib.md5(proxy.uuid.encode()).hexdigest()[:8], 16) % 1000
        socks_port = CONFIG["socks_base_port"] + port_offset
        
        config_file = Path(f'.xray_test_{socks_port}.json')
        xray_proc = None
        
        try:
            # Записываем конфиг
            xray_cfg = build_xray_config(proxy, socks_port)
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(xray_cfg, f, indent=2)
            
            # Запускаем xray
            xray_proc = await asyncio.create_subprocess_exec(
                str(CONFIG["xray_path"].resolve()),
                'run', '-config', str(config_file),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True
            )
            
            # Ждём поднятия порта
            if not await wait_for_socket(socks_port, timeout=5.0):
                return CheckResult(proxy, False, error="xray не запустил порт")
            
            # Замеряем пинг
            success, delay = await measure_latency(socks_port)
            
            if not success:
                return CheckResult(proxy, False, error="timeout или ошибка curl")
            
            # Формируем строку протокола
            p = proxy.params
            proto_parts = [
                p.get('security', 'none'),
                p.get('type', 'tcp')
            ]
            if p.get('flow'):
                proto_parts.append(p['flow'])
            
            return CheckResult(
                config=proxy,
                success=True,
                delay_ms=delay,
                protocol="+".join(proto_parts)
            )
        
        except Exception as e:
            log.debug(f"Ошибка проверки {short_name}: {e}")
            return CheckResult(proxy, False, error=str(e))
        
        finally:
            # Чистим процессы и файлы
            if xray_proc:
                try:
                    os.killpg(os.getpgid(xray_proc.pid), signal.SIGTERM)
                    await asyncio.wait_for(xray_proc.wait(), timeout=3)
                except Exception:
                    try:
                        xray_proc.kill()
                    except Exception:
                        pass
            
            if config_file.exists():
                try:
                    config_file.unlink()
                except Exception:
                    pass


async def run_check_cycle() -> List[CheckResult]:
    """
    Один полный цикл проверки всех прокси.
    """
    links = fetch_subscription()
    if not links:
        return []
    
    proxies = filter_proxies(links)
    if not proxies:
        return []
    
    semaphore = asyncio.Semaphore(CONFIG["max_concurrent_checks"])
    
    log.info(f"Запуск {len(proxies)} проверок (параллельно: {CONFIG['max_concurrent_checks']})")
    
    tasks = [check_proxy(p, semaphore) for p in proxies]
    results = await asyncio.gather(*tasks)
    
    return [r for r in results if r is not None and r.success]


# =============================================================================
# СОХРАНЕНИЕ РЕЗУЛЬТАТОВ
# =============================================================================

def save_results(results: List[CheckResult]) -> None:
    """
    Сохраняет рабочие прокси в файл.
    """
    # Сортировка
    if CONFIG["sort_descending"]:
        results.sort(key=lambda x: x.delay_ms or 0, reverse=True)
    else:
        results.sort(key=lambda x: x.delay_ms or 0)
    
    with open(CONFIG["output_file"], 'w', encoding='utf-8') as f:
        # Заголовок для импорта в клиент
        f.write("# 📋🔀 Обход белых списков YzeweNet.ru ♨️ (Working Filter / 1 min)\n\n")
        
        for idx, res in enumerate(results, 1):
            new_name = f"📶✅Антиглушилка #{idx} ({res.protocol})"
            encoded_name = urllib.parse.quote(new_name)
            
            # Заменяем старое имя в URL на новое
            base_url = res.config.original_url.split('#')[0]
            new_url = f"{base_url}#{encoded_name}"
            
            f.write(f"{new_url} | {res.delay_ms}ms\n")
    
    log.info(f"Сохранено {len(results)} ссылок в {CONFIG['output_file']}")


# =============================================================================
# СИСТЕМНЫЕ ПРОВЕРКИ
# =============================================================================

def verify_xray() -> bool:
    """Проверяет наличие и исполняемость xray."""
    xray_path = CONFIG["xray_path"]
    
    if not xray_path.exists():
        log.error("xray не найден в текущей директории")
        print("\n💡 Установка:")
        print("   wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip")
        print("   unzip Xray-linux-64.zip && chmod +x xray")
        return False
    
    if not os.access(xray_path, os.X_OK):
        log.error("xray не имеет флага исполнения")
        print("💡 Выполните: chmod +x ./xray")
        return False
    
    log.info("xray готов к работе")
    return True


# =============================================================================
# ТОЧКА ВХОДА
# =============================================================================

async def main_loop() -> None:
    """Бесконечный цикл проверки."""
    if not verify_xray():
        sys.exit(1)
    
    log.info("=" * 60)
    log.info("VLESS Proxy Health Monitor v1.2.0")
    log.info(f"Подписка: {CONFIG['subscription_url']}")
    log.info(f"Интервал: {CONFIG['check_interval_sec']} сек | Мин. пинг: {CONFIG['min_delay_ms']}мс")
    log.info("=" * 60)
    
    iteration = 0
    
    while True:
        iteration += 1
        log.info(f"\n{'='*60}")
        log.info(f"Итерация #{iteration} | {datetime.now().strftime('%H:%M:%S')}")
        log.info(f"{'='*60}")
        
        cycle_start = time.monotonic()
        
        working = await run_check_cycle()
        
        # Фильтр по пингу
        working = [r for r in working if r.delay_ms and r.delay_ms >= CONFIG["min_delay_ms"]]
        
        cycle_duration = time.monotonic() - cycle_start
        
        if working:
            save_results(working)
            
            delays = [r.delay_ms for r in working if r.delay_ms]
            log.info(f"\n✅ Найдено: {len(working)} (пинг {CONFIG['min_delay_ms']}мс+)")
            log.info(f"   Мин: {min(delays):.0f}мс | Макс: {max(delays):.0f}мс | Сред: {sum(delays)/len(delays):.0f}мс")
        else:
            log.warn("Нет ссылок, удовлетворяющих критериям")
        
        log.info(f"Время цикла: {cycle_duration:.1f} сек")
        
        # Пауза до следующего цикла
        if CONFIG["check_interval_sec"] > 0:
            sleep_time = max(0, CONFIG["check_interval_sec"] - cycle_duration)
            if sleep_time > 0:
                log.info(f"Следующая проверка через {sleep_time:.0f} сек...")
                await asyncio.sleep(sleep_time)


async def single_check() -> None:
    """Однократная проверка для теста."""
    if not verify_xray():
        sys.exit(1)
    
    log.info("Запуск однократной проверки...")
    
    working = await run_check_cycle()
    working = [r for r in working if r.delay_ms and r.delay_ms >= CONFIG["min_delay_ms"]]
    
    if working:
        save_results(working)
        log.info(f"\n✅ Найдено {len(working)} рабочих прокси")
        for i, r in enumerate(working[:5], 1):
            log.info(f"   {i}. {r.config.name[:40]} — {r.delay_ms}мс")
    else:
        log.warn("Рабочих прокси не найдено")


def main() -> None:
    """Инициализация и запуск."""
    if len(sys.argv) > 1 and sys.argv[1] == '--single':
        asyncio.run(single_check())
    else:
        try:
            asyncio.run(main_loop())
        except KeyboardInterrupt:
            log.info("\nОстановка пользователем (Ctrl+C)")
            sys.exit(0)


if __name__ == '__main__':
    main()
