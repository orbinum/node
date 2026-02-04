# Benchmarks: pallet-zk-verifier

Directorio de benchmarks para medir performance criptográfica y on-chain.

## 📁 Estructura

```
benches/
├── config.rs           # Configuración compartida (Criterion + FRAME)
├── groth16_verify.rs   # Criterion benchmarks (off-chain)
├── run.sh              # Script de ejecución
└── README.md           # Esta documentación
```

## 🚀 Quick Start

```bash
# Fast benchmarks (desarrollo)
./benches/run.sh fast

# Standard benchmarks (regular)
./benches/run.sh standard

# Production benchmarks (accuracy)
./benches/run.sh production

# FRAME benchmarks (generar weights.rs)
./benches/run.sh frame
```

## 📊 Tipos de Benchmarks

### 1. Criterion Benchmarks (Off-chain)

**Archivo:** `groth16_verify.rs`  
**Propósito:** Medir performance criptográfica pura sin overhead FRAME

**Benchmarks disponibles:**
- `single_verification` - Tiempo de verificación de un proof
- `batch_verification` - Throughput con 1, 5, 10, 20, 50 proofs
- `vk_operations` - Parsing de verification keys (transfer, unshield)
- `proof_operations` - Parsing de proofs
- `public_inputs_scaling` - Impacto del número de inputs (1, 2, 4, 8, 16)
- `e2e_workflow` - Pipeline completo (parse + verify)

**Configuraciones:**
- `fast`: 10 samples, 2s measurement (desarrollo rápido)
- `standard`: 100 samples, 10s measurement (regular)
- `production`: 200 samples, 30s measurement (accuracy máxima)

**Ejecutar:**
```bash
# Con configuración por defecto
cargo bench --package pallet-zk-verifier

# Con configuración custom
CRITERION_CONFIG=production cargo bench --package pallet-zk-verifier

# Benchmark específico
cargo bench --package pallet-zk-verifier -- single_verification

# Ver reporte HTML
open target/criterion/report/index.html
```

### 2. FRAME Benchmarks (On-chain)

**Archivo:** `../src/benchmarking.rs`  
**Propósito:** Calcular pesos (weights) para fees on-chain

**Benchmarks disponibles:**
- `register_verification_key` - Almacenar VK en storage
- `remove_verification_key` - Eliminar VK de storage
- `verify_proof` - Verificar proof (⚠️ usa datos mock)

**Ejecutar:**
```bash
# Build con runtime-benchmarks
cargo build --release --features runtime-benchmarks

# Generar weights.rs
./benches/run.sh frame

# O manual:
./target/release/orbinum-node benchmark pallet \
    --chain dev \
    --pallet pallet_zk_verifier \
    --extrinsic '*' \
    --steps 50 \
    --repeat 20 \
    --output frame/zk-verifier/src/weights.rs
```

## 🔧 Configuración

### Módulo `config.rs`

Configuración compartida para ambos tipos de benchmarks:

```rust
// Criterion presets
CriterionConfig::fast()        // 10 samples, 2s
CriterionConfig::standard()    // 100 samples, 10s
CriterionConfig::production()  // 200 samples, 30s

// Tamaños de test
BenchmarkSizes::BATCH_SIZES             // [1, 5, 10, 20, 50]
BenchmarkSizes::PUBLIC_INPUT_COUNTS     // [1, 2, 4, 8, 16]

// Datos de prueba
test_data::mock_vk_bytes(768)
test_data::mock_proof_bytes()
test_data::mock_public_inputs(count)
```

### Variables de Entorno

```bash
# Configuración Criterion
export CRITERION_CONFIG=production

# Output detallado
export RUST_LOG=info

# Colorear output
export CARGO_TERM_COLOR=always
```

## 📈 Métricas Esperadas

### Criterion (Off-chain)

```
single_verification/groth16_verify           ~8-10ms
batch_verification/5                         ~40-50ms (8-10ms/proof)
vk_operations/parse_transfer_vk              ~100-200μs
proof_operations/parse_proof                 ~50-100μs
public_inputs_scaling/16                     ~10-20μs
e2e_workflow/full_verification_pipeline      ~10-12ms
```

### FRAME (On-chain)

```
register_verification_key    ~7ms + 3 DB writes
remove_verification_key      ~10ms + 4 DB writes
verify_proof                 ~13ms + 3 DB writes (⚠️ sin crypto real)
```

⚠️ **Nota:** Los pesos actuales de `verify_proof` NO incluyen el tiempo de verificación criptográfica real (~8-10ms) porque usan datos mock.

## 🔄 Workflow Típico

### Desarrollo (iteración rápida)

```bash
# 1. Hacer cambios en código
vim src/infrastructure/services/groth16_verifier.rs

# 2. Quick benchmark
./benches/run.sh fast

# 3. Ver resultados
./benches/run.sh report
```

### Pre-Release (validación)

```bash
# 1. Guardar baseline
./benches/run.sh save

# 2. Hacer cambios
git checkout feature-optimization

# 3. Comparar
./benches/run.sh compare

# 4. Si hay mejora, generar weights
./benches/run.sh frame
```

### Producción (deployment)

```bash
# 1. Ejecutar en hardware de referencia (no laptop)
ssh production-benchmark-server

# 2. Production benchmarks
CRITERION_CONFIG=production ./benches/run.sh production

# 3. Generar weights finales
./benches/run.sh frame

# 4. Commit weights.rs actualizado
git add src/weights.rs
git commit -m "chore: update benchmark weights for v0.x.x"
```

## 📊 Interpretación de Resultados

### Criterion HTML Report

```
target/criterion/report/index.html
├── single_verification/
│   ├── report/index.html          # Gráficos y estadísticas
│   ├── base/estimates.json        # Datos crudos
│   └── ...
└── ...
```

**Métricas clave:**
- **Mean**: Promedio del tiempo de ejecución
- **Std Dev**: Desviación estándar (menor = más consistente)
- **Median**: Valor medio (más robusto que mean)
- **MAD**: Median Absolute Deviation

**¿Qué buscar?**
- Mean < 10ms para single verification ✅
- Std Dev < 5% del mean ✅
- Outliers < 2% de los samples ✅

### FRAME weights.rs

```rust
fn verify_proof() -> Weight {
    Weight::from_parts(13_000_000, 11684)
    //                  ^^^^^^^^^^  ^^^^^^
    //                  ref_time    proof_size
    //                  (picosegundos) (bytes)
}
```

**Componentes:**
- `ref_time`: Tiempo de ejecución (13ms = 13,000,000 picosegundos)
- `proof_size`: Tamaño de datos leídos de DB (11,684 bytes)

## ⚠️ Limitaciones Actuales

1. **FRAME `verify_proof` usa datos mock**
   - Solo mide overhead FRAME (~13ms)
   - NO mide verificación Groth16 real (~8-10ms)
   - Peso total esperado: ~21-23ms

2. **Criterion usa VKs reales pero proofs mock**
   - VKs: Hardcoded de `fp-zk-verifier` (transfer, unshield)
   - Proofs: Mock data (no verifican criptográficamente)
   - TODO: Usar proofs reales cuando circuits estén listos

## 🛠️ Troubleshooting

### Benchmarks muy lentos

```bash
# Verificar que estás en release mode
cargo bench --package pallet-zk-verifier -- --profile-time 5

# Reducir sample size temporalmente
CRITERION_CONFIG=fast ./benches/run.sh fast
```

### Resultados inconsistentes

```bash
# Asegurar que no hay procesos pesados corriendo
top

# Ejecutar con nice (menor prioridad a otros procesos)
nice -n -20 cargo bench --package pallet-zk-verifier
```

### FRAME benchmarks fallan

```bash
# Verificar feature está habilitada
cargo build --release --features runtime-benchmarks

# Verificar node existe
ls -lh target/release/orbinum-node
```

## 📚 Referencias

- [Criterion.rs Book](https://bheisler.github.io/criterion.rs/book/)
- [FRAME Benchmarking](https://docs.substrate.io/test/benchmark/)
- [../BENCHMARKING.md](../BENCHMARKING.md) - Estrategia completa
- [../README.md](../README.md) - Documentación del pallet
