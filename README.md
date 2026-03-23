# 🔍 VLESS Async Checker

Асинхронный инструмент для массовой проверки VLESS-прокси от YzeweNet созданный для [LSB Proxy](https://t.me/lsbproxy) с использованием xray-core. Автоматически фильтрует рабочие ссылки, измеряет пинг и сохраняет результат в удобный формат.

## ✨ Особенности

- 🚀 **Асинхронная проверка** — до 10 ссылок одновременно
- 📡 **Реальный тест** — проверка через xray-core с замером задержки
- 🎯 **Фильтрация** — отбор только ссылок с "Антиблок" в названии
- ⚡ **Сортировка** — по пингу (медленные → быстрые)
- 🔄 **Авто-обновление** — проверка каждые 60 секунд (настраиваемо)
- 📝 **Красивый вывод** — новые имена с номерами и протоколом
- 🐳 **Docker** — готовый контейнер для развёртывания

## 📋 Требования

| Компонент | Версия | Примечание |
|-----------|--------|------------|
| Python | 3.10+ | Требуется asyncio |
| xray-core | Любой | Исполняемый файл `./xray` |
| curl | Любой | Для тестирования соединения |
| ОС | Linux/macOS | Windows требует |

## 📦 Установка

### Быстрый старт

```bash
# 1. Создайте папку проекта
mkdir vless-checker && cd vless-checker

# 2. Скачайте скрипт
curl -O https://raw.githubusercontent.com/BrawePizza/vless-checker/master/main.py
chmod +x checker.py

# 3. Скачайте xray-core
wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
unzip Xray-linux-64.zip
chmod +x xray
rm Xray-linux-64.zip README.md LICENSE

# 4. Запустите
python3 checker.py --single    # Однократная проверка
python3 checker.py             # Постоянный мониторинг
