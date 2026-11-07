#!/usr/bin/env bash
# agent-net-doctor — находит участок, на котором рвётся связь Claude Code или Codex с API.
# Скрипт только читает и меряет: настройки системы, WSL, VPN и агентов он не меняет.
#
# Код выхода: 0 — сеть здорова, 1 — найдена поломка,
#             2 — среда не поддерживается или неверный ключ.
#
# Для тестов: ND_ROOT — корень, от которого читаются системные файлы
# (/proc, /etc, .wslconfig). По умолчанию пусто, то есть настоящий корень.
#
# Код до проверки ОС должен работать и в bash 3.2 (macOS): там нужен вежливый отказ,
# а не синтаксическая ошибка.

set -u

ND_VERSION="0.1.0-dev"
ND_ROOT="${ND_ROOT:-}"

SHOW_IP=0
FAILS=0

# ---------- вывод ----------

say()  { printf '%s\n' "$*"; }
err()  { printf 'net-doctor: %s\n' "$*" >&2; }

# Шаги: ✓ прошло, ✗ поломка, – пропущено или не к чему применить.
step_ok()   { printf '  ✓ %s\n' "$*"; }
step_fail() { printf '  ✗ %s\n' "$*"; FAILS=$((FAILS + 1)); }
step_skip() { printf '  – %s\n' "$*"; }
section()   { printf '\n%s\n' "$*"; }

# ---------- скрытие адресов ----------
# Петлевые адреса (127.x.x.x, ::1, localhost) не скрываются: они не раскрывают
# машину, а для диагностики важны (в режиме NAT 127.0.0.1 — это сам WSL).

# IPv4 → x.x.x.x
mask_ipv4() {
  local s=$1 out="" m
  local re='([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
  while [[ $s =~ $re ]]; do
    m=${BASH_REMATCH[1]}
    out+=${s%%"$m"*}
    case $m in
      127.*) out+=$m ;;
      *)     out+='x.x.x.x' ;;
    esac
    s=${s#*"$m"}
  done
  printf '%s' "$out$s"
}

# IPv6 → x:x::x. Кандидат — группы hex через двоеточия; чтобы не задеть время
# вида 12:30:45, в нём должно быть «::» или буква a–f.
mask_ipv6() {
  local s=$1 out="" m
  local re='([0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7})'
  while [[ $s =~ $re ]]; do
    m=${BASH_REMATCH[1]}
    out+=${s%%"$m"*}
    if [[ $m == ::1 ]]; then
      out+=$m
    elif [[ $m == *::* || $m == *[A-Fa-f]* ]]; then
      out+='x:x::x'
    else
      out+=$m
    fi
    s=${s#*"$m"}
  done
  printf '%s' "$out$s"
}

# Логин и пароль в URL. Пароль скрыт всегда, логин — без --show-ip.
# Захват жадный, до последней «@» перед пробелом: в пароле бывают «/» и «@».
mask_userinfo() {
  local s=$1 out="" pre ui
  local re='://([^[:space:]]+)@'
  while [[ $s =~ $re ]]; do
    ui=${BASH_REMATCH[1]}
    pre=${s%%"${BASH_REMATCH[0]}"*}
    if [[ $SHOW_IP == 1 && $ui == *:* ]]; then
      out+="$pre://${ui%%:*}:***@"
    elif [[ $SHOW_IP == 1 ]]; then
      out+="$pre://$ui@"
    else
      out+="$pre://***@"
    fi
    s=${s#*"${BASH_REMATCH[0]}"}
  done
  printf '%s' "$out$s"
}

# Произвольный текст: логины, пароли, IP-адреса.
mask_text() {
  local s
  s=$(mask_userinfo "$1")
  if [[ $SHOW_IP == 1 ]]; then
    printf '%s' "$s"
    return
  fi
  s=$(mask_ipv4 "$s")
  mask_ipv6 "$s"
}

# Адрес прокси: схема://[логин:пароль@]хост[:порт][/путь].
# Без --show-ip скрывается и имя хоста; схема и порт остаются — по ним видно,
# что за прокси и куда стучаться.
mask_proxy_url() {
  local url=$1 scheme="" rest hostport tail="" ui="" host port=""
  if [[ $url == *://* ]]; then
    scheme=${url%%://*}://
    rest=${url#*://}
  else
    rest=$url
  fi
  # Логин и пароль — всё до последней «@»: в пароле бывают «/» и «@».
  # «@» в пути тоже уйдёт в скрытое — лучше скрыть лишнее, чем показать пароль.
  if [[ $rest == *@* ]]; then
    ui=${rest%@*}
    rest=${rest##*@}
  fi
  hostport=${rest%%/*}
  [[ $rest == */* ]] && tail=/${rest#*/}
  if [[ $hostport == \[*\]* ]]; then            # [IPv6]:порт
    host=${hostport%%]*}]
    port=${hostport#"$host"}
  elif [[ $hostport == *:* && $hostport != *:*:* ]]; then
    host=${hostport%:*}
    port=:${hostport##*:}
  else
    host=$hostport
  fi

  if [[ -n $ui ]]; then
    if [[ $SHOW_IP == 1 && $ui == *:* ]]; then
      ui="${ui%%:*}:***@"
    elif [[ $SHOW_IP == 1 ]]; then
      ui="$ui@"
    else
      ui='***@'
    fi
  fi

  if [[ $SHOW_IP != 1 ]]; then
    if [[ $host == localhost || $host == ::1 || $host == '[::1]' ||
          $host =~ ^127(\.[0-9]{1,3}){3}$ ]]; then
      :                                        # петля видна, имя «127.x.example» — нет
    elif [[ $host == \[* || $host == *:* ]]; then
      host='[x:x::x]'
    elif [[ $host =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      host='x.x.x.x'
    elif [[ -n $host ]]; then
      host='***'
    fi
  fi
  printf '%s' "$scheme$ui$host$port$tail"
}

# ---------- ключи ----------

usage() {
  cat <<'EOF'
Использование: bash net-doctor.sh [ключи]

Находит участок, на котором рвётся связь Claude Code или Codex с API:
мост WSL↔Windows, прокси, DNS/IPv6, перехват TLS, туннель.
Скрипт только читает и меряет, ничего в системе не меняет.

Ключи:
  --show-ip    показать полные адреса (по умолчанию IP, адреса прокси
               и логины скрыты; пароль скрыт всегда)
  --version    версия скрипта
  -h, --help   эта справка

Код выхода:
  0  сеть здорова
  1  найдена поломка
  2  среда не поддерживается или неверный ключ
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      --show-ip)  SHOW_IP=1 ;;
      --version)  say "agent-net-doctor $ND_VERSION"; exit 0 ;;
      -h|--help)  usage; exit 0 ;;
      *)          err "неизвестный ключ: $1"; err "справка: bash net-doctor.sh --help"; exit 2 ;;
    esac
    shift
  done
}

# ---------- среда ----------

check_os() {
  local os
  os=$(uname -s 2>/dev/null || echo unknown)
  case $os in
    Linux) ;;
    Darwin)
      say "macOS пока не поддерживается: v0.1.0 проверяет WSL2 и Ubuntu."
      say "Поддержка macOS планируется в v0.2. Если готовы проверить на своём Mac —"
      say "откройте issue: https://github.com/ferroua/agent-net-doctor/issues"
      exit 2 ;;
    *)
      say "Среда «$os» не поддерживается: v0.1.0 проверяет WSL2 и Ubuntu."
      exit 2 ;;
  esac
}

# ---------- проверки ----------

check_proxy_vars() {
  section "Прокси-переменные"
  local name val found=0
  for name in https_proxy HTTPS_PROXY http_proxy HTTP_PROXY all_proxy ALL_PROXY; do
    val=${!name:-}
    [[ -z $val ]] && continue
    found=1
    step_ok "$name=$(mask_proxy_url "$val")"
  done
  [[ $found == 0 ]] && step_skip "прокси не задан"
  return 0
}

# ---------- вердикт ----------

verdict() {
  section "Итог"
  if [[ $FAILS -gt 0 ]]; then
    say "  Найдено поломок: $FAILS"
    return 1
  fi
  say "  Поломок не найдено"
  return 0
}

main() {
  parse_args "$@"
  check_os
  say "agent-net-doctor $ND_VERSION"
  [[ $SHOW_IP == 1 ]] && say "Внимание: --show-ip, адреса в выводе не скрыты."
  check_proxy_vars
  verdict
}

# Без запуска при `source` — так тесты проверяют функции по отдельности.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
