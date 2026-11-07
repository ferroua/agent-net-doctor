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
WARNS=0

# Что узнали о среде — для следующих проверок и вердикта.
# Часть переменных читают проверки задач 4–6, которых ещё нет.
# shellcheck disable=SC2034
{
  ENV_KIND=""          # wsl2 | wsl1 | container | linux
  WSL_MODE=""          # nat | mirrored | virtioproxy | none — только в WSL
  WSL_MODE_SRC=""      # wslinfo | .wslconfig | по умолчанию
  WSLCONF_MODE=""      # networkingMode из .wslconfig, если задан
  WSLCONF_AUTOPROXY="" # autoProxy из .wslconfig, если задан
  WSLCONF_DNSTUN=""    # dnsTunneling из .wslconfig, если задан
  PROXY_FROM_WINDOWS=0 # 1 — в no_proxy маркер <local>: прокси импортирован из Windows
  AGENTS=()            # найденные агенты: claude-code, codex
  CLAUDE_VER=""
  CODEX_VER=""
}

# ---------- вывод ----------

say()  { printf '%s\n' "$*"; }
err()  { printf 'net-doctor: %s\n' "$*" >&2; }

# Шаги: ✓ прошло, ✗ поломка, – пропущено или не к чему применить.
step_ok()   { printf '  ✓ %s\n' "$*"; }
step_fail() { printf '  ✗ %s\n' "$*"; FAILS=$((FAILS + 1)); }
step_skip() { printf '  – %s\n' "$*"; }
step_warn() { printf '  ! %s\n' "$*"; WARNS=$((WARNS + 1)); }
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
    Linux)
      if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
        say "Нужен bash 4 или новее, а запущен $BASH_VERSION."
        exit 2
      fi ;;
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

# Дальше — только Linux, bash 4+.

trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }

# Значение ключа из файла вида KEY=value (/etc/os-release). Файл не выполняется.
kv_get() {
  local file=$1 key=$2 line v
  [[ -r $file ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line == "$key="* ]] || continue
    v=${line#*=}; v=${v%\"}; v=${v#\"}; v=${v%\'}; v=${v#\'}
    printf '%s' "$v"
    return 0
  done < "$file"
  return 1
}

# Путь для вывода: домашняя папка → ~, чужие имена пользователей скрыты.
show_path() {
  local p=$1
  if [[ -n ${HOME:-} && $p == "$HOME"/* ]]; then
    p=\~/${p#"$HOME"/}
  elif [[ $p == /mnt/* ]]; then
    p="/mnt/…"
  elif [[ $p == /home/*/* ]]; then
    p="/home/…/${p#/home/*/}"
  fi
  printf '%s' "$p"
}

# ---------- среда ----------
# WSL определяется по WSL_DISTRO_NAME, WSLInterop и wslinfo, а не по ядру:
# docker внутри WSL работает на том же ядре microsoft-standard-WSL2.

wslinfo_mode() {
  local m
  command -v wslinfo >/dev/null 2>&1 || return 1
  m=$(wslinfo --networking-mode 2>/dev/null) || return 1
  m=$(trim "${m//$'\r'/}")
  [[ -n $m ]] || return 1
  printf '%s' "${m,,}"
}

in_container() {
  [[ -e $ND_ROOT/.dockerenv || -e $ND_ROOT/run/.containerenv ]] && return 0
  [[ -r $ND_ROOT/proc/1/cgroup ]] &&
    grep -qE '/(docker|kubepods|containerd|libpod)' "$ND_ROOT/proc/1/cgroup" 2>/dev/null
}

wsl_markers() {
  [[ -n ${WSL_DISTRO_NAME:-} ]] && return 0
  [[ -e $ND_ROOT/proc/sys/fs/binfmt_misc/WSLInterop ||
     -e $ND_ROOT/proc/sys/fs/binfmt_misc/WSLInterop-late ]] && return 0
  wslinfo_mode >/dev/null
}

check_env() {
  section "Среда"
  local osr="" pretty id like distro
  [[ -r $ND_ROOT/proc/sys/kernel/osrelease ]] && osr=$(<"$ND_ROOT/proc/sys/kernel/osrelease")
  pretty=$(kv_get "$ND_ROOT/etc/os-release" PRETTY_NAME) || pretty="Linux"
  id=$(kv_get "$ND_ROOT/etc/os-release" ID) || id=""
  like=$(kv_get "$ND_ROOT/etc/os-release" ID_LIKE) || like=""

  # Контейнер — первым: в нём бывают видны маркеры WSL хозяина.
  if in_container; then
    ENV_KIND=container
    if [[ $osr == *[Mm]icrosoft* ]]; then
      step_skip "контейнер на ядре WSL2 ($pretty) — это не WSL: режим сети WSL и мост до Windows не проверяются"
      say "    Чтобы проверить WSL, запустите скрипт в самом дистрибутиве WSL, а не в контейнере."
    else
      step_skip "контейнер ($pretty): проверки только общие"
    fi
    return 0
  fi

  if wsl_markers; then
    distro=${WSL_DISTRO_NAME:-}
    # WSL1 — без своего ядра, версия ядра вида 4.4.0-19041-Microsoft.
    if [[ $osr == *-Microsoft ]]; then
      ENV_KIND=wsl1
      step_warn "WSL1${distro:+, дистрибутив $distro} ($pretty): v0.1.0 проверяет WSL2, проверки только общие"
      return 0
    fi
    ENV_KIND=wsl2
    step_ok "WSL2${distro:+, дистрибутив $distro} ($pretty)"
    return 0
  fi

  ENV_KIND=linux
  if [[ $id == ubuntu || " $like " == *" ubuntu "* ]]; then
    step_ok "$pretty без WSL: общие проверки"
  else
    step_ok "$pretty без WSL: общие проверки (v0.1.0 проверялась на Ubuntu)"
  fi
  return 0
}

# ---------- настройки WSL ----------

# .wslconfig лежит в профиле пользователя Windows. Ищем на дисках /mnt/<буква>.
# Несколько профилей — берём тот, что совпадает с именем пользователя Linux.
find_wslconfig() {
  local f found=() me=${USER:-${LOGNAME:-}} d
  for f in "$ND_ROOT"/mnt/*/Users/*/.wslconfig; do
    [[ -f $f ]] && found+=("$f")
  done
  if [[ ${#found[@]} -eq 1 ]]; then
    printf '%s' "${found[0]}"; return 0
  fi
  [[ ${#found[@]} -eq 0 ]] && return 1
  for f in "${found[@]}"; do
    d=${f%/.wslconfig}; d=${d##*/}
    if [[ -n $me && ${d,,} == "${me,,}" ]]; then printf '%s' "$f"; return 0; fi
  done
  return 2
}

# Ключи секции [wsl2]. Имена без учёта регистра, файл с Windows — с CRLF.
read_wslconfig() {
  local file=$1 line sec="" k v
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line//$'\r'/}
    line=${line%%[#;]*}
    line=$(trim "$line")
    [[ -z $line ]] && continue
    if [[ $line =~ ^\[(.*)\]$ ]]; then
      sec=$(trim "${BASH_REMATCH[1]}"); sec=${sec,,}
      continue
    fi
    [[ $sec == wsl2 && $line == *=* ]] || continue
    k=$(trim "${line%%=*}"); k=${k,,}
    v=$(trim "${line#*=}"); v=${v%\"}; v=${v#\"}
    case $k in
      networkingmode) WSLCONF_MODE=${v,,} ;;
      autoproxy)      WSLCONF_AUTOPROXY=${v,,} ;;
      dnstunneling)   WSLCONF_DNSTUN=${v,,} ;;
    esac
  done < "$file"
}

check_wsl() {
  section "Настройки WSL"
  local conf rc=0 m parts=()
  conf=$(find_wslconfig) || rc=$?
  case $rc in
    0)
      read_wslconfig "$conf"
      [[ -n $WSLCONF_MODE ]]      && parts+=("networkingMode=$WSLCONF_MODE")
      [[ -n $WSLCONF_AUTOPROXY ]] && parts+=("autoProxy=$WSLCONF_AUTOPROXY")
      [[ -n $WSLCONF_DNSTUN ]]    && parts+=("dnsTunneling=$WSLCONF_DNSTUN")
      if [[ ${#parts[@]} -gt 0 ]]; then
        local joined
        printf -v joined '%s, ' "${parts[@]}"
        step_ok ".wslconfig: ${joined%, }"
      else
        step_ok ".wslconfig есть, сеть в нём не настроена: всё по умолчанию"
      fi ;;
    2) step_skip ".wslconfig: найдено несколько профилей Windows, не знаю, какой ваш" ;;
    *) step_skip ".wslconfig не найден: всё по умолчанию (networkingMode=nat, autoProxy=true)" ;;
  esac

  if m=$(wslinfo_mode); then
    WSL_MODE=$m; WSL_MODE_SRC=wslinfo
  elif [[ -n $WSLCONF_MODE ]]; then
    WSL_MODE=$WSLCONF_MODE; WSL_MODE_SRC=.wslconfig
  else
    WSL_MODE=nat; WSL_MODE_SRC="по умолчанию"
  fi
  step_ok "режим сети: $WSL_MODE ($WSL_MODE_SRC)"

  if [[ $WSL_MODE_SRC == wslinfo && -n $WSLCONF_MODE && $WSLCONF_MODE != "$WSL_MODE" ]]; then
    step_warn "в .wslconfig networkingMode=$WSLCONF_MODE, а WSL работает в $WSL_MODE: настройка вступит в силу после «wsl --shutdown» в Windows"
  fi
  return 0
}

# ---------- агенты ----------

# Путь к агенту — в AGENT_PATH: сначала PATH, потом обычные места установки.
# Вариант из Windows (/mnt/…) — в WIN_AGENT, агентом WSL он не считается.
AGENT_PATH=""
WIN_AGENT=""
find_agent() {
  local cmd=$1 p c
  AGENT_PATH="" WIN_AGENT=""
  while IFS= read -r p; do
    [[ -z $p ]] && continue
    if [[ $p == /mnt/* ]]; then WIN_AGENT=$p; continue; fi
    AGENT_PATH=$p; return 0
  done < <(type -aP "$cmd" 2>/dev/null)
  for c in "$HOME/.local/bin/$cmd" "$HOME/.claude/local/$cmd" "$HOME/.npm-global/bin/$cmd"; do
    [[ -x $c ]] && { AGENT_PATH=$c; return 0; }
  done
  return 1
}

agent_version() {
  local out
  if command -v timeout >/dev/null 2>&1; then
    out=$(timeout 10 "$1" --version 2>/dev/null)
  else
    out=$("$1" --version 2>/dev/null)
  fi
  [[ $out =~ ([0-9]+(\.[0-9]+)+) ]] || return 1
  printf '%s' "${BASH_REMATCH[1]}"
}

check_one_agent() { # id  команда  имя  переменная-для-версии
  local id=$1 cmd=$2 name=$3 p v="" where
  if ! find_agent "$cmd"; then
    if [[ -n $WIN_AGENT ]]; then
      step_warn "$name: найден только вариант из Windows (/mnt/…), в WSL нужен свой — поставьте $name внутри WSL"
    else
      step_skip "$name не найден"
    fi
    return 0
  fi
  p=$AGENT_PATH
  where=$(show_path "$p")
  AGENTS+=("$id")
  if v=$(agent_version "$p"); then
    step_ok "$name $v ($where)"
  else
    step_warn "$name найден ($where), но версию узнать не удалось"
  fi
  printf -v "$4" '%s' "$v"
}

check_agents() {
  section "Агенты"
  check_one_agent claude-code claude "Claude Code" CLAUDE_VER
  check_one_agent codex codex "Codex" CODEX_VER
  if [[ ${#AGENTS[@]} -eq 0 ]]; then
    step_skip "ни Claude Code, ни Codex не найдены: проверю хосты обоих"
  fi
  return 0
}

# ---------- проверки ----------

check_proxy_vars() {
  section "Прокси-переменные"
  local name val any=0
  for name in https_proxy HTTPS_PROXY http_proxy HTTP_PROXY all_proxy ALL_PROXY; do
    val=${!name:-}
    [[ -z $val ]] && continue
    any=1
    step_ok "$name=$(mask_proxy_url "$val")"
  done
  [[ $any == 0 ]] && step_skip "прокси не задан"

  # WSL с autoProxy переносит в no_proxy список исключений Windows,
  # а в нём маркер <local> («не через прокси для локальных адресов»).
  # Само значение не печатается: там бывают имена внутренних хостов.
  if [[ ${no_proxy:-}${NO_PROXY:-} == *"<local>"* ]]; then
    # shellcheck disable=SC2034  # читает вердикт (задача 6)
    PROXY_FROM_WINDOWS=1
    step_ok "прокси импортирован из Windows: в no_proxy есть «<local>» (autoProxy WSL)"
    if [[ $ENV_KIND == wsl2 && $WSLCONF_AUTOPROXY == false ]]; then
      step_warn "в .wslconfig autoProxy=false, а переменные из Windows на месте: WSL не перезапущен или они заданы вручную"
    fi
  fi
  return 0
}

# ---------- вердикт ----------

verdict() {
  section "Итог"
  if [[ $FAILS -gt 0 ]]; then
    say "  Найдено поломок: $FAILS"
    [[ $WARNS -gt 0 ]] && say "  Предупреждений: $WARNS"
    return 1
  fi
  say "  Поломок не найдено"
  [[ $WARNS -gt 0 ]] && say "  Предупреждений: $WARNS"
  return 0
}

main() {
  parse_args "$@"
  check_os
  say "agent-net-doctor $ND_VERSION"
  [[ $SHOW_IP == 1 ]] && say "Внимание: --show-ip, адреса в выводе не скрыты."
  check_env
  [[ $ENV_KIND == wsl2 ]] && check_wsl
  check_agents
  check_proxy_vars
  verdict
}

# Без запуска при `source` — так тесты проверяют функции по отдельности.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
