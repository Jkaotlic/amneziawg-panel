#!/usr/bin/env bash
# Установка awg3-panel. Идемпотентен: повторный запуск на настроенной
# системе не меняет состояние. Существующий config.yaml НЕ перетирается.
set -euo pipefail

# Разбор аргументов: --dry-run в любой позиции, путь к бинарю — первый
# позиционный. Простое ${1} здесь ошибочно: install.sh --dry-run приняло бы
# «--dry-run» за путь к бинарю и упало бы с невнятным сообщением.
BIN_SRC=""
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -*) echo "неизвестный ключ: $arg"; exit 2 ;;
    *) [ -z "$BIN_SRC" ] && BIN_SRC="$arg" ;;
  esac
done
BIN_SRC="${BIN_SRC:-./awg3panel}"

run() {
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

say() { printf '%s\n' "$*"; }

# ensure_dir — общий приём для КАЖДОГО каталога хранилища ниже: явный
# install -d -m 0700 на каждом уровне по отдельности, а не один вызов на
# конечный вложенный путь. install -d создаёт недостающих родителей и сам,
# но какие права достаются автоматически досозданным родителям — деталь
# реализации конкретной версии coreutils, а не документированная гарантия;
# здесь права каждого уровня выписаны явно, чтобы от неё не зависеть.
ensure_dir() {
  local d="$1"
  if [ -d "$d" ]; then
    say "каталог $d уже есть"
  else
    run install -d -m 0700 "$d"
    say "создан каталог $d"
  fi
}

[ "$(id -u)" = "0" ] || { say "нужен root"; exit 1; }
[ -f "$BIN_SRC" ] || { say "не найден бинарь: $BIN_SRC"; exit 1; }

# --- базовые каталоги ---
for d in /etc/awg3panel /var/lib/awg3panel; do
  ensure_dir "$d"
done

# --- бинарь ---
if [ -f /usr/local/bin/awg3panel ] && cmp -s "$BIN_SRC" /usr/local/bin/awg3panel; then
  say "бинарь не изменился"
  BIN_CHANGED=0
else
  run install -m 0755 "$BIN_SRC" /usr/local/bin/awg3panel
  say "бинарь установлен"
  BIN_CHANGED=1
fi

# --- конфиг: создаётся ТОЛЬКО если его нет ---
if [ -f /etc/awg3panel/config.yaml ]; then
  say "config.yaml уже есть — не трогаю"
else
  run install -m 0600 "$(dirname "$0")/config.example.yaml" /etc/awg3panel/config.yaml
  say "создан /etc/awg3panel/config.yaml — задайте bcrypt перед запуском:"
  say "  /usr/local/bin/awg3panel hash-password"
fi

# --- какой файл считать конфигом при всех дальнейших решениях ---
# Решение принимается по тому файлу, который к этому месту БУДЕТ на диске.
# В настоящем прогоне config.yaml уже существует: либо лежал, либо только что
# создан из примера шагом выше. В --dry-run его может не быть вовсе — и
# прежняя редакция скрипта проверяла именно его: страж на отсутствующем файле
# либо молчаливо не срабатывал там, где настоящий прогон применил бы его,
# либо падал там, где настоящий прогон прошёл бы гладко, — dry-run предсказывал
# не то решение, которое принял бы настоящий прогон. Поэтому при отсутствии
# целевого файла смотрим на тот же config.example.yaml, из которого он будет
# создан. CONFIG_CHECK ниже используется дважды: для каталогов хранилища
# интерфейсов и, в самом конце, для проверки, задан ли bcrypt, — оба решения
# обязаны согласоваться с одним и тем же будущим файлом, а не читать его
# заново с риском разъехаться.
if [ -f /etc/awg3panel/config.yaml ]; then
  CONFIG_CHECK=/etc/awg3panel/config.yaml
else
  CONFIG_CHECK="$(dirname "$0")/config.example.yaml"
  # Молча пропустить страж на отсутствующем примере значило бы вернуть ту же
  # ложь через другую дверь: решение принимается по файлу, которого нет.
  [ -f "$CONFIG_CHECK" ] || { say "не найден $CONFIG_CHECK"; exit 1; }
fi

# --- каталоги хранилища интерфейсов ---
# Конвенция путей — /var/lib/awg3panel/<id>/{peers.json,backups,keys}
# (см. deploy/config.example.yaml). peers.json и defaults.json создаёт сама
# панель при первом обращении (os.MkdirAll с 0700 внутри store.writeAtomicJSON
# и issuer.KeyStore.Put) — но backups и keys нужны раньше первого такого
# обращения: Applier пишет бэкап при первой же мутации, KeyStore — при первом
# выпуске пира. Раз уж каталог интерфейса всё равно приходится трогать
# заранее, он создаётся тем же проходом, тем же приёмом ensure_dir, что и
# базовые каталоги выше.
#
# Список id читается из CONFIG_CHECK построчным разбором "- id: <slug>"
# внутри interfaces:. Старый одноинтерфейсный формат (без interfaces: на
# верхнем уровне) такого списка не даёт — тогда действует раскладка, которая
# была до мультиинтерфейса: /var/lib/awg3panel/{backups,keys}. keys/ в этой
# ветке — устранение пробела прежней версии скрипта: хранилища приватных
# ключей тогда не существовало, и каталог для него не создавался никогда,
# хотя миграция (см. README, «Миграция ключей со старой установки») требует
# его с первого же обращения к пиру. clients/ по-прежнему не создаётся ни в
# одной из веток — это только источник ЧТЕНИЯ при миграции ключей, новый код
# в него не пишет никогда, а на уже установленных системах он либо
# существует с настоящими файлами, либо не нужен вовсе.
if grep -q '^interfaces:' "$CONFIG_CHECK"; then
  ids=$( { grep -E '^[[:space:]]*-[[:space:]]*id:[[:space:]]*' "$CONFIG_CHECK" || true; } \
    | sed -E 's/^[[:space:]]*-[[:space:]]*id:[[:space:]]*"?([a-z0-9-]+)"?.*/\1/' )
  if [ -z "$ids" ]; then
    say "внимание: interfaces: есть в $CONFIG_CHECK, но ни одного id не распознано — каталоги интерфейсов не созданы"
  fi
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ensure_dir "/var/lib/awg3panel/$id"
    ensure_dir "/var/lib/awg3panel/$id/backups"
    ensure_dir "/var/lib/awg3panel/$id/keys"
  done <<< "$ids"
else
  ensure_dir /var/lib/awg3panel/backups
  ensure_dir /var/lib/awg3panel/keys
fi

# --- юнит ---
UNIT_SRC="$(dirname "$0")/awg3panel.service"
if [ -f /etc/systemd/system/awg3panel.service ] && cmp -s "$UNIT_SRC" /etc/systemd/system/awg3panel.service; then
  say "юнит не изменился"
  UNIT_CHANGED=0
else
  run install -m 0644 "$UNIT_SRC" /etc/systemd/system/awg3panel.service
  run systemctl daemon-reload
  say "юнит установлен"
  UNIT_CHANGED=1
fi

# --- запуск ---
if grep -q 'ЗАМЕНИТЬ' "$CONFIG_CHECK"; then
  say "в config.yaml не задан bcrypt — сервис не запускаю"
  exit 0
fi

if systemctl is-enabled --quiet awg3panel 2>/dev/null && systemctl is-active --quiet awg3panel 2>/dev/null; then
  if [ "$BIN_CHANGED" = "1" ] || [ "$UNIT_CHANGED" = "1" ]; then
    run systemctl restart awg3panel
    say "сервис перезапущен"
  else
    say "сервис уже работает, ничего не менялось"
  fi
else
  run systemctl enable --now awg3panel
  say "сервис включён и запущен"
fi
