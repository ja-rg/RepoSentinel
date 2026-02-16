#!/usr/bin/env bash
set -euo pipefail

# Interactive scanner orchestrator (ALL SCANNERS VIA DOCKER)
# Scanners: semgrep, trivy, syft, grype, nuclei (run as containers)
#
# Modes:
# 1) Docker artifacts: IMAGE / local Dockerfile / public repo (Docker context)
# 2) Static code: public repo (SAST/SCA)
# 3) Minikube YAML (kubectl): gate scan YAML -> if clean deploy -> Nuclei DAST -> teardown on findings -> else keep & publish
#
# Host prereqs:
# - docker
# - git
# - kubectl + minikube (for option 3)
#
# Reports: ./scan-reports/

############################
# Config (container images)
############################
IMG_SEMGREP="${IMG_SEMGREP:-semgrep/semgrep:latest}"
IMG_TRIVY="${IMG_TRIVY:-aquasec/trivy:latest}"
IMG_SYFT="${IMG_SYFT:-anchore/syft:latest}"
IMG_GRYPE="${IMG_GRYPE:-anchore/grype:latest}"
IMG_NUCLEI="${IMG_NUCLEI:-projectdiscovery/nuclei:latest}"

REPORT_ROOT="${REPORT_ROOT:-./scan-reports}"
mkdir -p "$REPORT_ROOT"

# Caches (speed + stability)
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/scanner-docker}"
mkdir -p "$CACHE_DIR/trivy" "$CACHE_DIR/semgrep" "$CACHE_DIR/nuclei"

############################
# UI helpers
############################
RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'; BLU=$'\033[0;34m'; RST=$'\033[0m'
say()  { echo "${BLU}[*]${RST} $*"; }
ok()   { echo "${GRN}[+]${RST} $*"; }
warn() { echo "${YEL}[!]${RST} $*"; }
err()  { echo "${RED}[-]${RST} $*" >&2; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Falta '$1' en PATH."; exit 1; }; }

timestamp() { date +"%Y%m%d-%H%M%S"; }

cleanup_dir=""
on_exit() { [[ -n "${cleanup_dir:-}" && -d "$cleanup_dir" ]] && rm -rf "$cleanup_dir"; }
trap on_exit EXIT
mktempdir() { mktemp -d 2>/dev/null || mktemp -d -t scan-tmp; }

# Detect host access from container (for Nuclei to hit services exposed on host/minikube)
host_from_container() {
  # On Linux: --network host works best.
  # On Mac/Windows: host.docker.internal exists (often).
  if [[ "$(uname -s | tr '[:upper:]' '[:lower:]')" == "linux" ]]; then
    echo "linux_hostnet"
  else
    echo "host.docker.internal"
  fi
}

############################
# Docker runners for tools
############################
docker_pull_if_needed() {
  local img="$1"
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    say "Pull: $img"
    docker pull "$img" >/dev/null
  fi
}

run_semgrep() {
  local wd="$1"; shift
  docker_pull_if_needed "$IMG_SEMGREP"
  docker run --rm \
    -v "$wd:/src" -w /src \
    -v "$CACHE_DIR/semgrep:/root/.cache/semgrep" \
    "$IMG_SEMGREP" semgrep "$@"
}

run_trivy() {
  local wd="$1"; shift
  docker_pull_if_needed "$IMG_TRIVY"
  docker run --rm \
    -v "$wd:/work" -w /work \
    -v "$CACHE_DIR/trivy:/root/.cache/trivy" \
    "$IMG_TRIVY" "$@"
}

run_syft() {
  # Mount docker.sock so syft can reliably inspect local images too
  local wd="$1"; shift
  docker_pull_if_needed "$IMG_SYFT"
  docker run --rm \
    -v "$wd:/mnt/code" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$IMG_SYFT" "$@"
}

run_grype() {
  local wd="$1"; shift
  docker_pull_if_needed "$IMG_GRYPE"
  docker run --rm \
    -v "$wd:/work" -w /work \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$IMG_GRYPE" "$@"
}

run_nuclei() {
  docker_pull_if_needed "$IMG_NUCLEI"
  docker run --rm \
    -v "$CACHE_DIR/nuclei:/root/.cache/nuclei" \
    "$IMG_NUCLEI" "$@"
}

############################
# Core scan flows
############################
scan_docker_image() {
  local image="$1"
  local stamp outdir
  stamp="$(timestamp)"
  outdir="$REPORT_ROOT/image-$stamp"
  mkdir -p "$outdir"

  say "Escaneo de IMAGEN: $image"

  # Trivy image (FIX: no --no-progress; use --quiet)
  run_trivy "$PWD" image --severity HIGH,CRITICAL --ignore-unfixed --quiet "$image" \
    >"$outdir/trivy-image.txt" 2>&1 || true
  ok "Report: $outdir/trivy-image.txt"

  # Syft SBOM (SPDX JSON) (FIX: no headers in JSON)
  run_syft "$PWD" "$image" -o spdx-json \
    >"$outdir/sbom.image.spdx.json" 2>"$outdir/syft-image-stderr.txt" || true
  ok "SBOM: $outdir/sbom.image.spdx.json"

  # Grype (prefer SBOM)
  if [[ -s "$outdir/sbom.image.spdx.json" ]]; then
    # Mount outdir as /work and reference file relatively
    run_grype "$outdir" "sbom:sbom.image.spdx.json" --fail-on high \
      >"$outdir/grype-sbom.txt" 2>&1 || true
    ok "Report: $outdir/grype-sbom.txt"
  else
    # Fallback: scan image directly
    run_grype "$PWD" "$image" --fail-on high \
      >"$outdir/grype-image.txt" 2>&1 || true
    ok "Report: $outdir/grype-image.txt"
  fi

  ok "Reportes en: $outdir"
}

scan_dockerfile_path() {
  local dockerfile="$1"
  [[ -f "$dockerfile" ]] || { err "No existe: $dockerfile"; return 1; }

  local ctx_dir stamp outdir
  ctx_dir="$(cd "$(dirname "$dockerfile")" && pwd)"
  stamp="$(timestamp)"
  outdir="$REPORT_ROOT/dockerfile-$stamp"
  mkdir -p "$outdir"

  say "Escaneo de DOCKERFILE: $dockerfile"
  say "Contexto: $ctx_dir"

  # Trivy config (FIX: --quiet, no --no-progress)
  run_trivy "$ctx_dir" config --severity HIGH,CRITICAL --quiet . \
    >"$outdir/trivy-config.txt" 2>&1 || true
  ok "Report: $outdir/trivy-config.txt"

  # Semgrep Dockerfile rules
  run_semgrep "$ctx_dir" --config p/dockerfile --quiet "$dockerfile" \
    >"$outdir/semgrep-dockerfile.txt" 2>&1 || true
  ok "Report: $outdir/semgrep-dockerfile.txt"

  ok "Reportes en: $outdir"
}

clone_public_repo() {
  local url="$1" dest="$2"
  need_cmd git
  say "Clonando: $url"
  git clone --depth 1 "$url" "$dest" >/dev/null
  ok "Clonado en: $dest"
}

scan_repo_static() {
  local repo_url="$1"
  local stamp outdir workdir
  stamp="$(timestamp)"
  outdir="$REPORT_ROOT/repo-$stamp"
  mkdir -p "$outdir"

  cleanup_dir="$(mktempdir)"
  workdir="$cleanup_dir/repo"
  clone_public_repo "$repo_url" "$workdir"

  say "SAST (Semgrep auto)"
  run_semgrep "$workdir" --config=auto --timeout 600 --quiet . \
    >"$outdir/semgrep-auto.txt" 2>&1 || true
  ok "Report: $outdir/semgrep-auto.txt"

  say "SCA/Secrets/Misconfig (Trivy fs)"
  run_trivy "$workdir" fs --severity HIGH,CRITICAL --ignore-unfixed --quiet . \
    >"$outdir/trivy-fs.txt" 2>&1 || true
  ok "Report: $outdir/trivy-fs.txt"

  say "SBOM (Syft dir)"
  run_syft "$workdir" dir:/mnt/code -o spdx-json \
    >"$outdir/sbom.dir.spdx.json" 2>"$outdir/syft-dir-stderr.txt" || true
  ok "SBOM: $outdir/sbom.dir.spdx.json"

  if [[ -s "$outdir/sbom.dir.spdx.json" ]]; then
    say "Vulns desde SBOM (Grype)"
    run_grype "$outdir" "sbom:sbom.dir.spdx.json" --fail-on high \
      >"$outdir/grype-sbom.txt" 2>&1 || true
    ok "Report: $outdir/grype-sbom.txt"
  fi

  ok "Reportes en: $outdir"
}

scan_repo_for_docker_context() {
  local repo_url="$1"
  cleanup_dir="$(mktempdir)"
  local workdir="$cleanup_dir/repo"
  clone_public_repo "$repo_url" "$workdir"

  local dockerfile
  dockerfile="$(find "$workdir" -maxdepth 4 -type f -iname 'dockerfile' | head -n 1 || true)"

  if [[ -n "${dockerfile:-}" ]]; then
    say "Dockerfile detectado: $dockerfile"
    scan_dockerfile_path "$dockerfile"
  else
    warn "No encontré Dockerfile (hasta 4 niveles)."
  fi

  scan_repo_static "$repo_url"
}

############################
# Option 3: Minikube YAML gate -> deploy -> nuclei -> teardown/publish
############################
gate_yaml_trivy_semgrep() {
  local yaml_path="$1" outdir="$2"
  local gate_fail=0
  local ydir; ydir="$(cd "$(dirname "$yaml_path")" && pwd)"

  say "Gate: Trivy config (HIGH/CRITICAL)"
  if run_trivy "$ydir" config --severity HIGH,CRITICAL --exit-code 1 --quiet . \
      >"$outdir/trivy-config-gate.txt" 2>&1; then
    ok "Trivy gate: limpio."
  else
    err "Trivy gate: encontró HIGH/CRITICAL (o error)."
    gate_fail=1
  fi

  say "Gate: Semgrep Kubernetes (p/kubernetes) severidad ERROR"
  if run_semgrep "$ydir" --config p/kubernetes --severity ERROR --error --quiet "$yaml_path" \
      >"$outdir/semgrep-k8s-gate.txt" 2>&1; then
    ok "Semgrep gate: limpio."
  else
    err "Semgrep gate: encontró findings severos (o error)."
    gate_fail=1
  fi

  return "$gate_fail"
}

minikube_yaml_flow() {
  local yaml_path="$1"
  [[ -f "$yaml_path" ]] || { err "No existe: $yaml_path"; return 1; }

  need_cmd kubectl
  need_cmd minikube
  need_cmd docker

  local stamp outdir
  stamp="$(timestamp)"
  outdir="$REPORT_ROOT/minikube-$stamp"
  mkdir -p "$outdir"

  say "Verificando Minikube..."
  if ! minikube status >/dev/null 2>&1; then
    warn "Minikube no está arriba. Intento iniciarlo..."
    minikube start >/dev/null
    ok "Minikube iniciado."
  else
    ok "Minikube OK."
  fi

  if ! gate_yaml_trivy_semgrep "$yaml_path" "$outdir"; then
    err "Gate FALLÓ -> no despliego. Reportes: $outdir"
    return 2
  fi

  say "kubectl apply -f $yaml_path"
  kubectl apply -f "$yaml_path" | tee "$outdir/kubectl-apply.txt"
  ok "Aplicado."

  kubectl wait --for=condition=Ready pods --all --all-namespaces --timeout=180s >/dev/null 2>&1 || \
    warn "No todos los pods llegaron a Ready en 180s."

  local svc_name target_url
  svc_name="$(kubectl get svc -n default -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  target_url=""

  if [[ -n "${svc_name:-}" ]]; then
    say "Service detectado: $svc_name"
    target_url="$(minikube service "$svc_name" -n default --url 2>/dev/null | head -n 1 || true)"
  fi

  if [[ -z "${target_url:-}" ]]; then
    err "No pude obtener URL con 'minikube service --url'."
    err "Para Nuclei necesitas un Service/Ingress o un port-forward."
    kubectl delete -f "$yaml_path" --ignore-not-found | tee "$outdir/kubectl-delete.txt" || true
    return 3
  fi

  ok "Target URL para Nuclei: $target_url"

  say "Nuclei (HIGH/CRITICAL) contra: $target_url"
  local nuclei_out="$outdir/nuclei.txt"

  if [[ "$(host_from_container)" == "linux_hostnet" ]]; then
    docker_pull_if_needed "$IMG_NUCLEI"
    docker run --rm --network host \
      -v "$CACHE_DIR/nuclei:/root/.cache/nuclei" \
      "$IMG_NUCLEI" -u "$target_url" -severity high,critical -silent | tee "$nuclei_out" || true
  else
    run_nuclei -u "$target_url" -severity high,critical -silent | tee "$nuclei_out" || true
  fi

  if [[ -s "$nuclei_out" ]]; then
    err "Nuclei reportó hallazgos -> teardown"
    kubectl delete -f "$yaml_path" --ignore-not-found | tee "$outdir/kubectl-delete.txt" || true
    err "VULNERABLE. Reportes: $outdir"
    return 4
  fi

  ok "Nuclei sin HIGH/CRITICAL. Mantengo despliegue."
  ok "App publicada en: $target_url"
  ok "Reportes: $outdir"
}

############################
# Menu
############################
menu() {
  echo
  echo "=================================================="
  echo " Scanner interactivo (herramientas via DOCKER)"
  echo "=================================================="
  echo "1) Docker: imagen / Dockerfile / repo público"
  echo "2) Código estático: repo público"
  echo "3) Minikube YAML: gate -> deploy -> nuclei -> teardown/publish"
  echo "q) Salir"
  echo "--------------------------------------------------"
}

docker_menu() {
  echo
  echo "Docker scanning"
  echo " a) Escanear IMAGEN (ej: nginx:latest, ghcr.io/org/app:tag)"
  echo " b) Escanear DOCKERFILE local"
  echo " c) Repo público (clona + busca Dockerfile + escanea)"
  echo " x) Volver"
}

check_prereqs() {
  need_cmd docker
  need_cmd git
}

main() {
  check_prereqs

  while true; do
    menu
    read -r -p "Selecciona opción: " opt || true
    case "${opt,,}" in
      1)
        while true; do
          docker_menu
          read -r -p "Selecciona (a/b/c/x): " dopt || true
          case "${dopt,,}" in
            a)
              read -r -p "Imagen (name:tag): " img
              [[ -n "${img:-}" ]] || { warn "Vacío."; continue; }
              scan_docker_image "$img"
              ;;
            b)
              read -r -p "Ruta a Dockerfile: " df
              [[ -f "${df:-}" ]] || { err "No existe: $df"; continue; }
              scan_dockerfile_path "$df"
              ;;
            c)
              read -r -p "URL repo público (https://...git): " rurl
              [[ -n "${rurl:-}" ]] || { warn "Vacío."; continue; }
              scan_repo_for_docker_context "$rurl"
              ;;
            x) break ;;
            *) warn "Opción inválida." ;;
          esac
        done
        ;;
      2)
        read -r -p "URL repo público (https://...git): " rurl
        [[ -n "${rurl:-}" ]] || { warn "Vacío."; continue; }
        scan_repo_static "$rurl"
        ;;
      3)
        need_cmd kubectl
        need_cmd minikube
        read -r -p "Ruta al YAML (kubectl) para Minikube: " yml
        [[ -f "${yml:-}" ]] || { err "No existe: $yml"; continue; }
        minikube_yaml_flow "$yml" || true
        ;;
      q|quit|exit)
        ok "Bye."
        break
        ;;
      *)
        warn "Opción inválida."
        ;;
    esac
  done
}

main "$@"
