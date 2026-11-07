#!/usr/bin/env bash
# Прогон сценариев из tests/cases/ и проверок отдельных функций.
# Без сети и без WSL: внешние команды подменяются заглушками через PATH,
# системные файлы скрипт читает от ND_ROOT.
#
# Сценарий — папка tests/cases/<имя>/:
#   code     ожидаемый код выхода (обязательно)
#   args     ключи скрипта, по одному на строку
#   env      переменные окружения KEY=VALUE, по одной на строку
#   bin/     заглушки команд, идут в PATH первыми
#   root/    корень системных файлов (ND_ROOT)
#   expect   строки, которые должны быть в выводе (stdout+stderr)
#   reject   строки, которых в выводе быть не должно
#
# Запуск: bash tests/run.sh [имя-сценария ...]

set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT="$TESTS_DIR/../net-doctor.sh"
PASS=0
FAIL=0

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ok()   { PASS=$((PASS + 1)); printf '  ✓ %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  ✗ %s\n' "$1"; shift; local l; for l in "$@"; do printf '      %s\n' "$l"; done; }

# Строки файла без пустых и без комментариев.
lines() { [[ -f $1 ]] || return 0; grep -v -e '^[[:space:]]*$' -e '^#' "$1" || true; }

run_case() {
  local dir=$1 name tmp out code want l problems=()
  name=$(basename "$dir")
  tmp="$WORK/$name"
  mkdir -p "$tmp/bin" "$tmp/home"

  # Заглушки: общие (запрет сети) и свои. Копия + chmod: на /mnt/c и после
  # клона без бита исполнения файлы иначе не запустятся.
  cp "$TESTS_DIR"/stubs/* "$tmp/bin/" 2>/dev/null
  [[ -d $dir/bin ]] && cp "$dir"/bin/* "$tmp/bin/" 2>/dev/null
  chmod +x "$tmp"/bin/* 2>/dev/null

  local envs=() args=()
  while IFS= read -r l; do envs+=("$l"); done < <(lines "$dir/env")
  while IFS= read -r l; do args+=("$l"); done < <(lines "$dir/args")

  local root=""
  [[ -d $dir/root ]] && root="$dir/root"

  out=$(env -i HOME="$tmp/home" PATH="$tmp/bin:/usr/bin:/bin" LANG=C.UTF-8 \
        ND_ROOT="$root" ${envs[@]+"${envs[@]}"} \
        bash "$SCRIPT" ${args[@]+"${args[@]}"} 2>&1)
  code=$?

  want=$(lines "$dir/code")
  [[ $code == "$want" ]] || problems+=("код выхода $code, ожидался $want")
  while IFS= read -r l; do
    grep -qF -- "$l" <<<"$out" || problems+=("нет строки: $l")
  done < <(lines "$dir/expect")
  while IFS= read -r l; do
    grep -qF -- "$l" <<<"$out" && problems+=("лишняя строка: $l")
  done < <(lines "$dir/reject")

  if [[ ${#problems[@]} -eq 0 ]]; then
    ok "$name"
  else
    bad "$name" "${problems[@]}" "--- вывод ---" "$out"
  fi
}

# Проверки функций скрытия: source без запуска main. Имена функций скрипта
# (say, step_*, mask_*, main) с именами раннера не пересекаются.
unit() {
  # shellcheck disable=SC1090,SC1091  # путь вычисляется при запуске
  source "$SCRIPT"
  local got
  check() { # имя  show_ip  функция  вход  ожидание
    # shellcheck disable=SC2034  # читают функции подключённого скрипта
    SHOW_IP=$2
    got=$("$3" "$4")
    if [[ $got == "$5" ]]; then ok "$1"; else bad "$1" "вход:     $4" "получено: $got" "ожидание: $5"; fi
  }
  check "ipv4 скрыт"               0 mask_text "к 203.0.113.7:443 и 10.0.0.1" "к x.x.x.x:443 и x.x.x.x"
  check "127.0.0.1 не скрыт"       0 mask_text "прокси 127.0.0.1:7890" "прокси 127.0.0.1:7890"
  check "ipv6 скрыт"               0 mask_text "адрес 2001:db8::1 есть" "адрес x:x::x есть"
  check "ipv6 полный скрыт"        0 mask_text "fe80:0:0:0:a00:27ff:fe4e:66a1" "x:x::x"
  check "::1 не скрыт"             0 mask_text "петля ::1" "петля ::1"
  check "время не задето"          0 mask_text "в 12:30:45" "в 12:30:45"
  check "версия не задета"         0 mask_text "Claude Code 2.1.319" "Claude Code 2.1.319"
  check "логин в тексте скрыт"     0 mask_text "socks5://u:p@1.2.3.4:1080" "socks5://***@x.x.x.x:1080"
  check "show-ip: пароль скрыт"    1 mask_text "http://u:p@1.2.3.4:80" "http://u:***@1.2.3.4:80"
  check "прокси: имя хоста скрыто" 0 mask_proxy_url "http://proxy.corp.example:3128/" "http://***:3128/"
  check "прокси: localhost виден"  0 mask_proxy_url "http://localhost:7890" "http://localhost:7890"
  check "прокси: без схемы"        0 mask_proxy_url "10.1.2.3:8080" "x.x.x.x:8080"
  check "прокси: [ipv6]:порт"      0 mask_proxy_url "http://[2001:db8::5]:3128" "http://[x:x::x]:3128"
  check "прокси: [::1] виден"      0 mask_proxy_url "http://[::1]:3128" "http://[::1]:3128"
  check "прокси: «/» в пароле"      0 mask_proxy_url "http://u:pa/ss@proxy.corp.example:80" "http://***@***:80"
  check "прокси: «@» в пароле"      0 mask_proxy_url "http://u:p@ss@10.1.2.3:80" "http://***@x.x.x.x:80"
  check "прокси: 127.имя скрыто"    0 mask_proxy_url "http://127.corp.example:3128" "http://***:3128"
  check "прокси: localhost.имя скрыто" 0 mask_proxy_url "http://localhost.corp.example:3128" "http://***:3128"
  check "текст: «/» в пароле"       0 mask_text "http://u:pa/ss@1.2.3.4:80" "http://***@x.x.x.x:80"
  check "прокси: show-ip"          1 mask_proxy_url "http://a:b@proxy.corp.example:3128" "http://a:***@proxy.corp.example:3128"
}

echo "Функции скрытия адресов"
unit

echo "Сценарии"
if [[ $# -gt 0 ]]; then
  for n in "$@"; do run_case "$TESTS_DIR/cases/$n"; done
else
  for d in "$TESTS_DIR"/cases/*/; do run_case "${d%/}"; done
fi

echo
echo "Итого: прошло $PASS, упало $FAIL"
[[ $FAIL -eq 0 ]]
